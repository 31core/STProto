use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use chacha20poly1305::ChaCha20Poly1305;

pub const RSA_BITS: usize = 3072;

pub const AES_NONCE_SIZE: usize = 12;

pub const CHACHA20_KEY_SIZE: usize = 32;
pub const CHACHA20_NONCE_SIZE: usize = 12;

pub const ENCRYPRION_AES128GCM: u8 = 1;
pub const ENCRYPRION_AES256GCM: u8 = 2;
pub const ENCRYPRION_CHACHA20: u8 = 3;
pub const ENCRYPRION_AES128CCM: u8 = 4;
pub const ENCRYPRION_AES256CCM: u8 = 5;

#[derive(Clone, Copy, Debug)]
pub enum EncryptionType {
    AES128GCM,
    AES256GCM,
    ChaCha20Poly1305,
    AES128CCM,
    AES256CCM,
}

impl EncryptionType {
    pub fn new(encryption_type: u8) -> Self {
        match encryption_type {
            ENCRYPRION_AES128GCM => Self::AES128GCM,
            ENCRYPRION_AES256GCM => Self::AES256GCM,
            ENCRYPRION_CHACHA20 => Self::ChaCha20Poly1305,
            ENCRYPRION_AES128CCM => Self::AES128CCM,
            ENCRYPRION_AES256CCM => Self::AES256CCM,
            _ => panic!("Unkown encryption '{}'", encryption_type),
        }
    }
    pub fn dump_as_byte(&self) -> u8 {
        match self {
            Self::AES128GCM => ENCRYPRION_AES128GCM,
            Self::AES256GCM => ENCRYPRION_AES256GCM,
            Self::ChaCha20Poly1305 => ENCRYPRION_CHACHA20,
            Self::AES128CCM => ENCRYPRION_AES128CCM,
            Self::AES256CCM => ENCRYPRION_AES256CCM,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Key {
    AES128GCM([u8; 16]),
    AES256GCM([u8; 32]),
    ChaCha20([u8; CHACHA20_KEY_SIZE]),
    AES128CCM([u8; 16]),
    AES256CCM([u8; 32]),
}

pub fn aes128_gcm_encrypt(data: &[u8], key: &[u8], iv: &[u8; AES_NONCE_SIZE]) -> Vec<u8> {
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).unwrap();
    cipher
        .encrypt(aes_gcm::Nonce::from_slice(iv), data)
        .unwrap()
}

pub fn aes128_gcm_decrypt(data: &[u8], key: &[u8], iv: &[u8; AES_NONCE_SIZE]) -> Vec<u8> {
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).unwrap();
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(iv), data)
        .unwrap()
}

pub fn aes256_gcm_encrypt(data: &[u8], key: &[u8], iv: &[u8; AES_NONCE_SIZE]) -> Vec<u8> {
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(key).unwrap();
    cipher
        .encrypt(aes_gcm::Nonce::from_slice(iv), data)
        .unwrap()
}

pub fn aes256_gcm_decrypt(data: &[u8], key: &[u8], iv: &[u8; AES_NONCE_SIZE]) -> Vec<u8> {
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(key).unwrap();
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(iv), data)
        .unwrap()
}

pub fn aes128_ccm_encrypt(data: &[u8], key: &[u8], iv: &[u8; AES_NONCE_SIZE]) -> Vec<u8> {
    let cipher =
        ccm::Ccm::<aes::Aes128, ccm::consts::U10, ccm::consts::U12>::new_from_slice(key).unwrap();
    cipher
        .encrypt(aes_gcm::Nonce::from_slice(iv), data)
        .unwrap()
}

pub fn aes128_ccm_decrypt(data: &[u8], key: &[u8], iv: &[u8; AES_NONCE_SIZE]) -> Vec<u8> {
    let cipher =
        ccm::Ccm::<aes::Aes128, ccm::consts::U10, ccm::consts::U12>::new_from_slice(key).unwrap();
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(iv), data)
        .unwrap()
}

pub fn aes256_ccm_encrypt(data: &[u8], key: &[u8], iv: &[u8; AES_NONCE_SIZE]) -> Vec<u8> {
    let cipher =
        ccm::Ccm::<aes::Aes256, ccm::consts::U10, ccm::consts::U12>::new_from_slice(key).unwrap();
    cipher
        .encrypt(aes_gcm::Nonce::from_slice(iv), data)
        .unwrap()
}

pub fn aes256_ccm_decrypt(data: &[u8], key: &[u8], nonce: &[u8; AES_NONCE_SIZE]) -> Vec<u8> {
    let cipher =
        ccm::Ccm::<aes::Aes256, ccm::consts::U10, ccm::consts::U12>::new_from_slice(key).unwrap();
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce), data)
        .unwrap()
}

pub fn chacah20poly1305_encrypt(
    key: [u8; 32],
    nonce: [u8; CHACHA20_NONCE_SIZE],
    data: &[u8],
) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(&key.into());
    cipher.encrypt(&nonce.into(), data).unwrap()
}

pub fn chacah20poly1305_decrypt(
    key: [u8; 32],
    nonce: [u8; CHACHA20_NONCE_SIZE],
    data: &[u8],
) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(&key.into());
    cipher.decrypt(&nonce.into(), data).unwrap()
}
