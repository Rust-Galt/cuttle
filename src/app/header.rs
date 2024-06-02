const MAGIC: [u8; 6] = *b"cuttle";
use std::{fmt::Debug, marker::PhantomData};

use blake2::digest::{consts::U32, Mac};
use color_eyre::{eyre::eyre, Result};
use secrecy::ExposeSecret;

use super::{Argon2Parameters, MacKey, Salt};

type Blake2bMac256 = blake2::Blake2bMac<U32>;

pub struct Tag(pub blake2::digest::CtOutput<Blake2bMac256>);
impl Tag {
    pub fn new(mac_key: &MacKey, data: &[u8]) -> Self {
        let mac = Blake2bMac256::new_with_salt_and_personal(mac_key.0.expose_secret(), &[], &[])
            .expect("Mac key length is 32 bytes")
            .chain_update(data)
            .finalize();
        Self(mac)
    }
}

impl Debug for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tag: {:#02X?}", self.0.clone().into_bytes())
    }
}

pub trait Validation {}

#[derive(Debug)]
pub struct Unvalidated;
impl Validation for Unvalidated {}

#[derive(Debug)]
pub struct Validated;
impl Validation for Validated {}

// 100 bytes
#[derive(Debug)]
pub struct RawHeader<M: Validation> {
    pub magic: [u8; 6],
    pub version: u8,
    pub add_size: u64,
    pub data_size: u64,
    pub block_size: u32,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u8,
    pub salt: [u8; 32],
    pub header_tag: Tag,
    _marker: PhantomData<M>,
}

impl RawHeader<Unvalidated> {
    pub fn from_raw(input: &[u8]) -> Result<Self> {
        let magic: [u8; 6] = input[0..6].try_into()?;
        let version: u8 = u8::from_le_bytes(input[6..7].try_into()?);
        let add_size: u64 = u64::from_le_bytes(input[7..15].try_into()?);
        let data_size: u64 = u64::from_le_bytes(input[15..23].try_into()?);
        let block_size: u32 = u32::from_le_bytes(input[23..27].try_into()?);
        let m_cost: u32 = u32::from_le_bytes(input[27..31].try_into()?);
        let t_cost: u32 = u32::from_le_bytes(input[31..35].try_into()?);
        let p_cost: u8 = u8::from_le_bytes(input[35..36].try_into()?);
        let salt: [u8; 32] = input[36..68].try_into()?;
        let header_tag: [u8; 32] = input[68..100].try_into()?;
        let header_tag: Tag = Tag(blake2::digest::CtOutput::new(header_tag.into()));
        Ok(Self {
            magic,
            version,
            add_size,
            data_size,
            block_size,
            m_cost,
            t_cost,
            p_cost,
            salt,
            header_tag,
            _marker: PhantomData,
        })
    }
    pub fn validate(self, mac_key: &MacKey) -> Result<RawHeader<Validated>> {
        let RawHeader {
            magic,
            version,
            add_size,
            data_size,
            block_size,
            m_cost,
            t_cost,
            p_cost,
            salt,
            header_tag,
            _marker,
        } = self;
        let mut data = Vec::with_capacity(100);
        data.extend(magic);
        data.extend(version.to_le_bytes());
        data.extend(add_size.to_le_bytes());
        data.extend(data_size.to_le_bytes());
        data.extend(block_size.to_le_bytes());
        data.extend(m_cost.to_le_bytes());
        data.extend(t_cost.to_le_bytes());
        data.extend(p_cost.to_le_bytes());
        data.extend(salt);

        if header_tag.0 == Tag::new(mac_key, &data).0 {
            Ok(RawHeader {
                magic,
                version,
                add_size,
                data_size,
                block_size,
                m_cost,
                t_cost,
                p_cost,
                salt,
                header_tag,
                _marker: PhantomData,
            })
        } else {
            Err(eyre!("Header invalid!"))
        }
    }
}

#[derive(Debug)]

pub struct ValidHeader {
    pub magic: [u8; 6],
    pub version: u8,
    pub add_size: u64,
    pub data_size: u64,
    pub block_size: u32,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u8,
    pub salt: [u8; 32],
    pub header_tag: Tag,
}
impl ValidHeader {
    pub fn new(
        argon2_parameters: Argon2Parameters,
        add_size: Option<u64>,
        data_size: u64,
        salt: Salt,
        mac_key: &MacKey,
    ) -> Self {
        let version: u8 = 1;
        let Argon2Parameters {
            m_cost,
            t_cost,
            p_cost,
        } = argon2_parameters;
        let m_cost: u32 = m_cost.into();
        let t_cost: u32 = t_cost.into();
        let p_cost: u8 = p_cost.into();
        let block_size: u32 = {
            match data_size {
                n if n >= 10_000_000 => 10_000_000,
                n if n >= 1_000_000 => 15_625 * 64,
                n if n >= 4096 => 4096,
                // n if n >= 1024 => 1024,
                _ => 640,
            }
        };
        let salt = salt.0;
        let add_size = add_size.unwrap_or_default();

        let mut data = Vec::with_capacity(100);
        data.extend(MAGIC);
        data.extend(version.to_le_bytes());
        data.extend(add_size.to_le_bytes());
        data.extend(data_size.to_le_bytes());
        data.extend(block_size.to_le_bytes());
        data.extend(m_cost.to_le_bytes());
        data.extend(t_cost.to_le_bytes());
        data.extend(p_cost.to_le_bytes());

        data.extend(salt);

        let header_tag = Tag::new(mac_key, &data);

        Self {
            magic: MAGIC,
            version,
            add_size,
            data_size,
            block_size,
            m_cost,
            t_cost,
            p_cost,
            salt,
            header_tag,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(100);
        data.extend(self.magic);
        data.extend(self.version.to_le_bytes());
        data.extend(self.add_size.to_le_bytes());
        data.extend(self.data_size.to_le_bytes());
        data.extend(self.block_size.to_le_bytes());
        data.extend(self.m_cost.to_le_bytes());
        data.extend(self.t_cost.to_le_bytes());
        data.extend(self.p_cost.to_le_bytes());
        data.extend(self.salt);
        data.extend(self.header_tag.0.clone().into_bytes());
        data
    }
}

// type Blake2bMac256 = blake2::Blake2bMac<U32>;
