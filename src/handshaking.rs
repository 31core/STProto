use crate::crypto::*;
use crate::version::*;

use rand::RngCore;
use rsa::{Pkcs1v15Encrypt, PublicKey, RsaPrivateKey, RsaPublicKey};
use std::io::Read;
use std::{io::Write, net::TcpStream};

pub struct ClientHello {
    pub proto_version: u8,
    pub client_version_major: u8,
    pub client_version_minor: u8,
    pub session_id: u64,
}

impl Default for ClientHello {
    fn default() -> Self {
        ClientHello {
            proto_version: PROTO_VERSION,
            client_version_major: CLIENT_VERSION_MAJOR,
            client_version_minor: CLIENT_VERSION_MINOR,
            session_id: rand::random(),
        }
    }
}

impl ClientHello {
    pub fn send(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let mut data = vec![
            self.proto_version,
            self.client_version_major,
            self.client_version_minor,
        ];

        data.extend(self.session_id.to_be_bytes());
        stream.write_all(&data)?;
        Ok(())
    }
    pub fn receive(&mut self, stream: &mut TcpStream) -> std::io::Result<()> {
        let mut data = [0; 11];
        stream.read_exact(&mut data)?;
        self.proto_version = data[0];
        self.client_version_major = data[1];
        self.client_version_minor = data[2];
        self.session_id = u64::from_be_bytes(data[3..].try_into().unwrap());
        Ok(())
    }
    pub fn verify(&self) -> bool {
        self.proto_version == PROTO_VERSION
    }
}

pub struct KeyExchange {
    pub encryption: EncryptionType,
    pub key: Key,
}

impl Default for KeyExchange {
    fn default() -> Self {
        Self::new(EncryptionType::AES256CBC)
    }
}

impl KeyExchange {
    pub fn new(encryption: EncryptionType) -> Self {
        Self {
            encryption,
            key: Key::AES256CBC([0; 32]),
        }
    }
    /** send key to server */
    pub fn send(&mut self, stream: &mut TcpStream, pub_key: &RsaPublicKey) -> std::io::Result<()> {
        stream.write_all(&[self.encryption.dump_as_byte()])?;

        match self.encryption {
            EncryptionType::AES128CBC => {
                self.gen_aes128cbc_key();

                if let Key::AES128CBC(key) = self.key {
                    let mut rng = rand::thread_rng();
                    let encrypted_key = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &key).unwrap();

                    /* send key size */
                    stream.write_all(&(encrypted_key.len() as u16).to_be_bytes())?;
                    /* send key */
                    stream.write_all(&encrypted_key)?;
                }
            }
            EncryptionType::AES256CBC => {
                self.gen_aes256cbc_key();

                if let Key::AES256CBC(key) = self.key {
                    let mut rng = rand::thread_rng();
                    let encrypted_key = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &key).unwrap();

                    /* send key size */
                    stream.write_all(&(encrypted_key.len() as u16).to_be_bytes())?;
                    /* send key */
                    stream.write_all(&encrypted_key)?;
                }
            }
            EncryptionType::ChaCha20 => {
                self.gen_chacha20_key();

                if let Key::ChaCha20(key) = self.key {
                    let mut rng = rand::thread_rng();
                    let encrypted_key = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &key).unwrap();

                    /* send key size */
                    stream.write_all(&(encrypted_key.len() as u16).to_be_bytes())?;
                    /* send key */
                    stream.write_all(&encrypted_key)?;
                }
            }
        }
        Ok(())
    }
    /** receive key from client */
    pub fn receive(
        &mut self,
        stream: &mut TcpStream,
        priv_key: &RsaPrivateKey,
    ) -> std::io::Result<()> {
        /* receive encryption argorithm */
        self.encryption = {
            let mut encryption = [0];
            stream.read_exact(&mut encryption)?;
            EncryptionType::new(encryption[0])
        };
        /* receive key */
        self.key = {
            /* receive key size */
            let key_size = {
                let mut size = [0; 2];
                stream.read_exact(&mut size)?;
                u16::from_be_bytes(size)
            };
            let mut key_buf = vec![0; key_size as usize];
            stream.read_exact(&mut key_buf)?;
            match self.encryption {
                EncryptionType::AES128CBC => {
                    let key = priv_key
                        .decrypt(rsa::Pkcs1v15Encrypt, &key_buf)
                        .unwrap()
                        .try_into()
                        .unwrap();
                    Key::AES128CBC(key)
                }
                EncryptionType::AES256CBC => {
                    let key = priv_key
                        .decrypt(rsa::Pkcs1v15Encrypt, &key_buf)
                        .unwrap()
                        .try_into()
                        .unwrap();
                    Key::AES256CBC(key)
                }
                EncryptionType::ChaCha20 => {
                    let key = priv_key
                        .decrypt(rsa::Pkcs1v15Encrypt, &key_buf)
                        .unwrap()
                        .try_into()
                        .unwrap();
                    Key::ChaCha20(key)
                }
            }
        };
        Ok(())
    }
    fn gen_aes128cbc_key(&mut self) {
        self.key = {
            let mut rng = rand::thread_rng();
            let mut key = [0; 16];
            rng.fill_bytes(&mut key);
            Key::AES128CBC(key)
        };
    }
    fn gen_aes256cbc_key(&mut self) {
        self.key = {
            let mut rng = rand::thread_rng();
            let mut key = [0; 32];
            rng.fill_bytes(&mut key);
            Key::AES256CBC(key)
        };
    }
    fn gen_chacha20_key(&mut self) {
        self.key = {
            let mut rng = rand::thread_rng();
            let mut key = [0; CHACHA20_KEY_SIZE];
            rng.fill_bytes(&mut key);
            let mut iv = [0; CHACHA20_NONCE_SIZE];
            rng.fill_bytes(&mut iv);
            Key::ChaCha20(key)
        };
    }
}
