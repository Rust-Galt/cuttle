mod header;
const ADD_READ_BLOCK_SIZE: usize = 1_000_000;
const NONCE_SIZE: usize = 12;

use blake2::digest::Mac;
// use argon2::Argon2;
// use blake2::digest::consts::U32;
use color_eyre::{
    eyre::{eyre, Ok},
    Result,
};
type Blake2bMac256 = blake2::Blake2bMac<blake2::digest::consts::U32>;

use rand::{thread_rng, RngCore};
use secrecy::{ExposeSecret, SecretString, SecretVec, Zeroize};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    num::{NonZeroU32, NonZeroU8},
    os::unix::fs::MetadataExt,
    path::PathBuf,
};
use tracing::{debug, info};

use crate::app::header::{RawHeader, ValidHeader};

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Argon2Parameters {
    m_cost: NonZeroU32,
    t_cost: NonZeroU32,
    p_cost: NonZeroU8,
}
impl Argon2Parameters {
    pub fn new(m: u32, t: u32, p: u8) -> Result<Self> {
        // m_cost bounds check
        let m_cost = if (argon2::Params::MIN_M_COST..=argon2::Params::MAX_M_COST).contains(&m) {
            NonZeroU32::new(m).unwrap()
        } else {
            return Err(eyre!(format!(
                "m needs to be between {} and {} inclusive",
                argon2::Params::MIN_M_COST,
                argon2::Params::MAX_M_COST
            )));
        };
        // t_cost bounds check
        let t_cost = if (argon2::Params::MIN_T_COST..=argon2::Params::MAX_T_COST).contains(&t) {
            NonZeroU32::new(t).unwrap()
        } else {
            return Err(eyre!(format!(
                "t needs to be between {} and {} inclusive",
                argon2::Params::MIN_T_COST,
                argon2::Params::MAX_T_COST
            )));
        };
        // p_cost bounds check
        let p_cost = if p >= argon2::Params::MIN_P_COST as u8 {
            NonZeroU8::new(p).unwrap()
        } else {
            return Err(eyre!(format!(
                "p needs to be between {} and {} inclusive",
                argon2::Params::MIN_P_COST,
                u8::MAX
            )));
        };

        Ok(Self {
            m_cost,
            t_cost,
            p_cost,
        })
    }
}
impl Default for Argon2Parameters {
    fn default() -> Self {
        Self {
            m_cost: NonZeroU32::new(argon2::Params::DEFAULT_M_COST).unwrap(),
            t_cost: NonZeroU32::new(argon2::Params::DEFAULT_T_COST).unwrap(),
            p_cost: NonZeroU8::new(argon2::Params::DEFAULT_P_COST.try_into().unwrap()).unwrap(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InputFilePath(pub PathBuf);

#[derive(Debug)]
pub struct OutputFilePath(pub PathBuf);

#[derive(Debug)]
pub struct EncryptionParameters {
    pub input: InputFilePath,
    pub additional_data: Option<InputFilePath>,
    pub output: OutputFilePath,
    pub argon2_parameters: Argon2Parameters,
}
#[derive(Debug)]
pub struct Passphrase(pub SecretString);

#[derive(Debug)]
pub struct Salt([u8; 32]);

pub struct EncKey(SecretVec<u8>);
pub struct MacKey(SecretVec<u8>);
pub struct DerivedKeysAndMeta {
    enc_key: EncKey,
    mac_key: MacKey,
    salt: Salt,
    argon2_parameters: Argon2Parameters,
}

#[derive(Debug)]
pub enum Operation {
    Information(InputFilePath),
    ExtractAdditionalData(InputFilePath, OutputFilePath),
    Verify(Passphrase, InputFilePath),
    Encrypt(Passphrase, EncryptionParameters),
    Decrypt(Passphrase, InputFilePath, OutputFilePath),
}

#[derive(Debug)]
pub struct App {}
impl App {
    pub fn new() -> Self {
        Self {}
    }
    pub fn run(self, operation: Operation) -> Result<()> {
        match operation {
            Operation::Information(ifp) => Self::information(&self, ifp),
            Operation::ExtractAdditionalData(ifp, ofp) => {
                Self::extract_additional_data(&self, ifp, ofp)
            }
            Operation::Verify(pp, ifp) => Self::verify(&self, &pp, ifp),
            Operation::Encrypt(pp, ep) => Self::encrypt(&self, &pp, ep),
            Operation::Decrypt(pp, ifp, ofp) => Self::decrypt(&self, &pp, ifp, ofp),
        }
    }
    fn information(&self, ifp: InputFilePath) -> Result<()> {
        // Read header
        let in_file_handle = std::fs::File::open(ifp.0)?;
        let mut reader = BufReader::new(in_file_handle);
        let mut buffer = [0; 100];
        reader.read_exact(&mut buffer)?;
        let rh = RawHeader::from_raw(&buffer[..])?;
        // Print information
        println!("RAW_HEADER: {:?}", rh);
        // TODO
        todo!("Additional info needs to be printed")
    }

    fn verify(&self, pp: &Passphrase, ifp: InputFilePath) -> Result<()> {
        // Read header
        let in_file_handle = std::fs::File::open(ifp.0)?;
        let mut reader = BufReader::new(in_file_handle);
        let mut buffer = [0; 100];
        reader.read_exact(&mut buffer)?;
        let rh = RawHeader::from_raw(&buffer[..])?;
        // Generate keys
        let ap = Argon2Parameters::new(rh.m_cost, rh.t_cost, rh.p_cost)?;
        let DerivedKeysAndMeta { mac_key, .. } = Self::generate_keys(pp, ap, Some(Salt(rh.salt)))?;

        // Validate header
        let RawHeader {
            add_size,
            data_size,
            block_size,
            ..
        } = rh.validate(&mac_key)?;

        // Initialize hasher for validations
        let mut mac =
            Blake2bMac256::new_with_salt_and_personal(mac_key.0.expose_secret(), &[], &[])
                .expect("Mac key length is 32 bytes");

        if add_size != 0 {
            // Validate Add

            // Read filename_len
            let mut buffer = [0u8; 1];
            reader.read_exact(&mut buffer)?;
            mac.update(&buffer);
            let add_filename_len = u8::from_le_bytes(buffer);
            // Read filename
            let mut buffer = vec![0u8; add_filename_len as usize];
            reader.read_exact(&mut buffer)?;
            mac.update(&buffer);
            let _add_file_name = String::from_utf8(buffer)?;

            // Validate add block
            // add support for large add
            debug!("// Validate add block");

            let computed_add_tag = {
                let block_count = add_size as usize / ADD_READ_BLOCK_SIZE;
                let rest_bytes_count = add_size as usize % ADD_READ_BLOCK_SIZE;

                let mut buffer: Vec<u8> = vec![0u8; ADD_READ_BLOCK_SIZE];
                for _ in 0..block_count {
                    reader.read_exact(&mut buffer)?;
                    mac.update(&buffer);
                }
                if rest_bytes_count != 0 {
                    let mut buffer = vec![0u8; rest_bytes_count];
                    reader.read_exact(&mut buffer)?;
                    mac.update(&buffer);
                }
                mac.finalize_reset()
            };

            // Read add tag from file
            debug!("// Read add tag from file");
            let mut buffer = [0u8; 32];
            let _count = reader.read(&mut buffer)?;
            let file_add_tag: blake2::digest::CtOutput<Blake2bMac256> =
                blake2::digest::CtOutput::new(buffer.into());
            // Compare computed_add_tag with file_add_tag in constant time
            if file_add_tag != computed_add_tag {
                return Err(eyre!("Add tag invalid"));
            } else {
                info!("ADD Tag valid!");
            }
        } else {
            info!("No add, skipping...")
        }
        // Validate each datablock
        let full_datablock_count = data_size / block_size as u64;
        let rest_bytes_count = data_size % block_size as u64;

        let total_datablock_count =
            full_datablock_count + if rest_bytes_count == 0 { 0 } else { 1 };

        let mut tag_buffer = [0u8; 32];
        let mut data_buffer = vec![0u8; block_size as usize + NONCE_SIZE];

        for i in 1..=full_datablock_count {
            // Read datablock and hash data
            reader.read_exact(&mut data_buffer)?;
            mac.update(&data_buffer);
            let computed_tag = mac.finalize_reset();

            // Extract datablock tag
            reader.read_exact(&mut tag_buffer)?;
            let file_block_tag: blake2::digest::CtOutput<Blake2bMac256> =
                blake2::digest::CtOutput::new(tag_buffer.into());

            // Compare tags
            if file_block_tag != computed_tag {
                return Err(eyre!("Data block {} invalid tag", i));
            } else {
                info!("Data block {}/{} valid!", i, total_datablock_count);
            }
        }
        if rest_bytes_count != 0 {
            let mut data_buffer = vec![0u8; rest_bytes_count as usize + NONCE_SIZE];
            reader.read_exact(&mut data_buffer)?;
            mac.update(&data_buffer);
            let computed_tag = mac.finalize_reset();

            // Extract final datablock tag
            reader.read_exact(&mut tag_buffer)?;
            let file_block_tag: blake2::digest::CtOutput<Blake2bMac256> =
                blake2::digest::CtOutput::new(tag_buffer.into());
            // Compare tags
            if file_block_tag != computed_tag {
                return Err(eyre!("Data block {} invalid tag", total_datablock_count));
            } else {
                info!("Data block {0}/{0} valid!", total_datablock_count);
            }
        }

        // Print result
        Ok(())
    }

    fn extract_additional_data(&self, ifp: InputFilePath, ofp: OutputFilePath) -> Result<()> {
        // Read header
        let in_file_handle = std::fs::File::open(ifp.0)?;
        let mut reader = BufReader::new(in_file_handle);
        let mut buffer = [0; 100];
        reader.read_exact(&mut buffer)?;
        let rh = RawHeader::from_raw(&buffer[..])?;
        // If additional data exists extract to output path with original name
        if rh.add_size != 0 {
            let mut buffer = [0u8; 1];
            reader.read_exact(&mut buffer)?;
            let add_filename_len = u8::from_le_bytes(buffer);
            // Read filename
            let mut buffer = vec![0u8; add_filename_len as usize];
            reader.read_exact(&mut buffer)?;
            let mut add_file_name = String::from_utf8(buffer)?;
            add_file_name.push_str(".new");

            // Extract ADD
            // Create writer

            let mut out_path = ofp.0.clone();
            out_path.push(PathBuf::from(add_file_name));

            let out_file_handle = std::fs::File::create(&out_path)?;
            let mut writer = BufWriter::new(out_file_handle);

            let block_count = rh.add_size as usize / ADD_READ_BLOCK_SIZE;
            let rest_bytes_count = rh.add_size as usize % ADD_READ_BLOCK_SIZE;

            let mut buffer: Vec<u8> = vec![0u8; ADD_READ_BLOCK_SIZE];
            for _ in 0..block_count {
                reader.read_exact(&mut buffer)?;
                let _count = writer.write(&buffer)?;
            }
            if rest_bytes_count != 0 {
                let mut buffer = vec![0u8; rest_bytes_count];
                reader.read_exact(&mut buffer)?;
                let _count = writer.write(&buffer)?;
            }
            writer.flush()?;
        } else {
            info!("No add data available!")
        }
        Ok(())
    }

    fn encrypt(&self, pp: &Passphrase, ep: EncryptionParameters) -> Result<()> {
        let EncryptionParameters {
            input: ifp,
            additional_data,
            output,
            argon2_parameters,
        } = ep;

        // Get length of input file
        let file_size = std::fs::metadata(&ifp.0)?.size();
        let in_file_handle = std::fs::File::open(&ifp.0)?;
        let mut in_reader = BufReader::new(in_file_handle);
        // Generate keys, None generates new salt
        let DerivedKeysAndMeta {
            enc_key,
            mac_key,
            salt,
            argon2_parameters,
        } = Self::generate_keys(pp, argon2_parameters, None)?;

        // Generate header for output file and get add size if present
        let add_size = additional_data
            .clone()
            .and_then(|afp| std::fs::metadata(afp.0).ok())
            .map(|meta| meta.size());

        let valid_header = ValidHeader::new(argon2_parameters, add_size, file_size, salt, &mac_key);

        // Create new output file and write header
        let out_file_handle = std::fs::File::create(output.0)?;

        // Write header
        let mut writer = BufWriter::new(out_file_handle);
        writer.write_all(&valid_header.to_bytes())?;

        // Write add and add-tag
        // u8, filename length || filename || data || add tag
        if let Some(add_file_path) = additional_data {
            let filename = add_file_path
                .0
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(eyre!("Invalid filename in path"))?
                .as_bytes();

            let filename_len = u8::try_from(filename.len())?;

            let mut mac =
                Blake2bMac256::new_with_salt_and_personal(mac_key.0.expose_secret(), &[], &[])
                    .expect("Mac key length is 32 bytes");

            // Write and hash filename length
            let len_bytes = &filename_len.to_le_bytes();
            mac.update(len_bytes);
            let _count = writer.write(len_bytes)?;

            // Write and hash filename
            mac.update(filename);
            let _count = writer.write(filename)?;
            writer.flush()?;
            let add_file_handle = std::fs::File::open(&add_file_path.0)?;
            let mut add_reader = BufReader::new(add_file_handle);
            let mut buffer: Vec<u8> = vec![0; ADD_READ_BLOCK_SIZE];
            loop {
                let count = add_reader.read(&mut buffer)?;
                if count != 0 {
                    // Write and hash block of add
                    mac.update(&buffer[..count]);
                    let _count = writer.write(&buffer[..count])?;
                } else {
                    // Finalize hash and append tag
                    let _count = writer.write(&mac.finalize().into_bytes())?;
                    writer.flush()?;
                    break;
                }
            }
        }

        // Encrypt file in chunks and write to output file
        Self::encrypt_chunks(&valid_header, enc_key, mac_key, &mut in_reader, &mut writer)?;
        // // Verify output file
        Ok(())
        // self.verify(pp, InputFilePath(output.0))
    }
    fn decrypt(&self, pp: &Passphrase, ifp: InputFilePath, _ofp: OutputFilePath) -> Result<()> {
        // TODO: Proper way and then refactor overlapping steps in other functions
        // Read header
        // Verify header
        // Generate keys
        // Create new output file
        // Read input file in chunks, verify and decrypt, write into output file

        // Alternative
        // Verify file
        self.verify(pp, ifp.clone())?;

        // Handle additional_data by seeking forward in reader

        todo!("Decryption not implemented yet!")
    }

    /// Generate keys from Some(salt) or None generates new salt
    fn generate_keys(
        pp: &Passphrase,
        argon2_parameters: Argon2Parameters,
        salt: Option<Salt>,
    ) -> Result<DerivedKeysAndMeta> {
        let kdf_params = argon2::Params::new(
            argon2_parameters.m_cost.into(),
            argon2_parameters.t_cost.into(),
            Into::<u8>::into(argon2_parameters.p_cost).into(),
            Some(64),
        )
        .expect("Parameter valid as they are checked upon creation in Argon2Parameters struct");
        let kdf = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            kdf_params,
        );

        let salt = if let Some(s) = salt {
            s
        } else {
            let mut buf = [0u8; 32];
            let mut rnd = thread_rng();
            rnd.try_fill_bytes(&mut buf)?;
            Salt(buf)
        };

        let mut buf = [0u8; 64];
        kdf.hash_password_into(pp.0.expose_secret().as_bytes(), &salt.0, &mut buf)?;

        let enc_key = EncKey(SecretVec::new(buf[0..32].to_vec()));
        let mac_key = MacKey(SecretVec::new(buf[32..64].to_vec()));
        buf.zeroize();

        Ok(DerivedKeysAndMeta {
            enc_key,
            mac_key,
            salt,
            argon2_parameters,
        })
    }
    fn encrypt_chunks(
        valid_header: &ValidHeader,
        enc_key: EncKey,
        mac_key: MacKey,
        reader: &mut BufReader<File>,
        writer: &mut BufWriter<File>,
    ) -> Result<()> {
        let total_blocks = valid_header.data_size / valid_header.block_size as u64 + {
            if valid_header.data_size % valid_header.block_size as u64 == 0 {
                0
            } else {
                1
            }
        };

        let mut mac =
            Blake2bMac256::new_with_salt_and_personal(mac_key.0.expose_secret(), &[], &[])
                .expect("Mac key length is 32 bytes");

        // let mut blake3mac =
        //     blake3::Hasher::new_keyed(mac_key.0.expose_secret().as_slice().try_into()?);
        let mut buffer: Vec<u8> = vec![0; valid_header.block_size as usize];
        let mut index = 0u64;
        let mut nonce = Vec::with_capacity(NONCE_SIZE);
        loop {
            index += 1;

            let count = reader.read(&mut buffer)?;

            if count != 0 {
                nonce.clear();
                nonce.extend([0x00, 0x00, 0x00, 0x00]);
                nonce.extend(index.to_le_bytes());

                // Add nonce to mac calculation

                mac.update(&nonce);
                // blake3mac.update(&nonce);
                let nonce = chacha20::Nonce::from_slice(&nonce);
                let key = chacha20::Key::from_slice(enc_key.0.expose_secret());

                let mut chacha20 =
                    <chacha20::ChaCha20 as chacha20::cipher::KeyIvInit>::new(key, nonce);

                chacha20::cipher::StreamCipher::try_apply_keystream(
                    &mut chacha20,
                    &mut buffer[..count],
                )?;

                // Add nonce to mac calculation and finalize
                mac.update(&buffer[..count]);
                // blake3mac.update(&buffer[..count]);

                // let tag = mac.finalize_reset().into_bytes();

                let _count = writer.write(nonce)?;
                let _count = writer.write(&buffer[..count])?;
                // writer.write(&blake3mac.finalize().as_bytes()[..])?;
                let _count = writer.write(&mac.finalize_reset().into_bytes())?;
                writer.flush()?;
                // blake3mac.reset();
                info!("Written block {}/{}", index, total_blocks);
            } else {
                break;
            }
        }

        Ok(())
    }
}

// pub fn apply_keystream_to_data(enc_key: &SecretVec<u8>, mut data: &mut [u8], index: u64) {
//     // nonce is 12 bytes using index as unique nonce
//     let mut nonce = vec![0, 0, 0, 0];
//     nonce.extend(index.to_le_bytes());
//     let nonce = chacha20::Nonce::from_slice(&nonce);
//     let key = chacha20::Key::from_slice(enc_key.expose_secret());
//     let mut chacha20 = <chacha20::ChaCha20 as chacha20::cipher::KeyIvInit>::new(key, nonce);
//     chacha20::cipher::StreamCipher::apply_keystream(&mut chacha20, &mut data);
// }
#[test]
fn argon2_parameters_valid() {
    let ap = Argon2Parameters::new(8, 1, 1).unwrap();
    assert_eq!(
        ap,
        Argon2Parameters {
            m_cost: NonZeroU32::new(8).unwrap(),
            t_cost: NonZeroU32::new(1).unwrap(),
            p_cost: NonZeroU8::new(1).unwrap()
        }
    )
}

// #[test]
// fn app_encrypt() {
//     let command = Operation::Encrypt(
//         Passphrase(SecretString::new("qwe123".to_string())),
//         EncryptionParameters {
//             input: InputFilePath(PathBuf::new()),
//             additional_data: None,
//             output: OutputFilePath(PathBuf::new()),
//             argon2_parameters: Argon2Parameters::new(10, 10, 10).unwrap(),
//         },
//     );
//     let app = App::new(0).run(command);
// }
