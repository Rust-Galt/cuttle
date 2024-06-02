# Cuttle(fish) - Unfinished experimental file encryption tool

## Decryption not implemented yet

## Commands

- Encrypt
- Decrypt
- Extract additional data (filename, data)
- Info
- Verify

## Info

Show if additional data is present and its filename and size
Show encrypted data file size and block count and size
Argon2 parameters

## Encrypt

- Extract file paths for plain file and output file. Check if output file does not exist yet
- Prompt for or generate random passphrase
- Generate key from passphrase
- Write header to temporary file
- Encrypt in chunk into this file
- Verify file and copy to output destination
