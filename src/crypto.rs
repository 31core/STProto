use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use crypto::aes::*;
use crypto::blockmodes::*;
use crypto::buffer::*;

pub const RSA_BITS: usize = 3072;
pub const IV_SIZE: usize = 16;

pub const CHACHA20_KEY_SIZE: usize = 32;
pub const CHACHA20_NONCE_SIZE: usize = 12;

pub const ENCRYPRION_AES128CBC: u8 = 1;
pub const ENCRYPRION_AES256CBC: u8 = 2;
pub const ENCRYPRION_CHACHA20: u8 = 3;

#[derive(Clone, Copy, Debug)]
pub enum EncryptionType {
    AES128CBC,
    AES256CBC,
    ChaCha20,
}

impl EncryptionType {
    pub fn new(encryption_type: u8) -> Self {
        match encryption_type {
            ENCRYPRION_AES128CBC => Self::AES128CBC,
            ENCRYPRION_AES256CBC => Self::AES256CBC,
            ENCRYPRION_CHACHA20 => Self::ChaCha20,
            _ => panic!("Unkown encryption '{}'", encryption_type),
        }
    }
    pub fn dump_as_byte(&self) -> u8 {
        match self {
            Self::AES128CBC => ENCRYPRION_AES128CBC,
            Self::AES256CBC => ENCRYPRION_AES256CBC,
            Self::ChaCha20 => ENCRYPRION_CHACHA20,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Key {
    AES128CBC([u8; 16]),
    AES256CBC([u8; 32]),
    ChaCha20([u8; CHACHA20_KEY_SIZE]),
}

pub fn aes128_cbc_encrypt(data: &[u8], key: &[u8], iv: &[u8; IV_SIZE]) -> Vec<u8> {
    let mut encryptor = cbc_encryptor(KeySize::KeySize128, key, iv, PkcsPadding);

    let mut encrypted_data = Vec::new();
    let mut read_buffer = RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor
            .encrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();

        encrypted_data.extend(write_buffer.take_read_buffer().take_remaining());

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => continue,
        }
    }

    encrypted_data
}

pub fn aes128_cbc_decrypt(data: &[u8], key: &[u8], iv: &[u8; IV_SIZE]) -> Vec<u8> {
    let mut decryptor = cbc_decryptor(KeySize::KeySize128, key, iv, PkcsPadding);

    let mut decrypted_data = Vec::new();
    let mut read_buffer = RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor
            .decrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();
        decrypted_data.extend(write_buffer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => continue,
        }
    }

    decrypted_data
}

pub fn aes256_cbc_encrypt(data: &[u8], key: &[u8], iv: &[u8; IV_SIZE]) -> Vec<u8> {
    let mut encryptor = cbc_encryptor(KeySize::KeySize256, key, iv, PkcsPadding);

    let mut encrypted_data = Vec::new();
    let mut read_buffer = RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor
            .encrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();

        encrypted_data.extend(write_buffer.take_read_buffer().take_remaining());

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => continue,
        }
    }

    encrypted_data
}

pub fn aes256_cbc_decrypt(data: &[u8], key: &[u8], iv: &[u8; IV_SIZE]) -> Vec<u8> {
    let mut decryptor = cbc_decryptor(KeySize::KeySize256, key, iv, PkcsPadding);

    let mut decrypted_data = Vec::new();
    let mut read_buffer = RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor
            .decrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();
        decrypted_data.extend(write_buffer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => continue,
        }
    }

    decrypted_data
}

pub fn chacah20_encrypt(key: [u8; 32], nonce: [u8; CHACHA20_NONCE_SIZE], data: &[u8]) -> Vec<u8> {
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    let mut encrypted_data = data.to_owned();
    cipher.apply_keystream(&mut encrypted_data);

    encrypted_data
}

pub fn chacah20_decrypt(key: [u8; 32], nonce: [u8; CHACHA20_NONCE_SIZE], data: &[u8]) -> Vec<u8> {
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    let mut decrypted_data = data.to_owned();
    cipher.apply_keystream(&mut decrypted_data);

    decrypted_data
}
