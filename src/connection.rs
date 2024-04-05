use crate::crypto::*;
use crate::datapack::*;
use crate::encoding::*;
use crate::handshaking::*;
use crate::method::*;

use rand::RngCore;
use std::io::{BufReader, Read, Write};
use std::io::{Error, ErrorKind, Result as IOResult};
use std::net::*;

impl Write for STClient {
    fn write(&mut self, buf: &[u8]) -> IOResult<usize> {
        self.datapack.method = METHOD_SEND;
        self.datapack.payload.extend(buf);
        self.send()?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> IOResult<()> {
        Ok(())
    }
}

impl Read for STClient {
    fn read(&mut self, buf: &mut [u8]) -> IOResult<usize> {
        if self.datapack.payload.is_empty() {
            let err = self.receive();

            if err.is_err() {
                return Ok(0);
            }
        }

        let read_size = std::cmp::min(self.datapack.payload.len(), buf.len());
        buf[..read_size].copy_from_slice(&self.datapack.payload[..read_size]);

        for _ in 0..read_size {
            self.datapack.payload.remove(0);
        }
        Ok(read_size)
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct STClient {
    host: String,
    port: u16,
    key: Key,
    session_id: u64,
    time_stamp: u64, //the time stamp of connection setting up
    pub datapack: DataPack,
    stream: TcpStream,
    pub encryption_type: EncryptionType,
}

#[allow(dead_code)]
pub struct STServer {
    host: String,
    port: u16,
    listener: TcpListener,
    clients: Vec<STClient>,
}

impl STClient {
    pub fn connect(host: &str, port: u16, encryption_type: EncryptionType) -> IOResult<Self> {
        let mut stream = TcpStream::connect(format!("{}:{}", host, port))?;

        /* send client version to server */
        let client_hello = ClientHello::default();
        client_hello.send(&mut stream)?;

        let server_hello = ServerHello::receive(&mut stream)?;

        let mut key_exchanger = KeyExchange::new(encryption_type, client_hello.session_id);
        key_exchanger.send(&mut stream, &server_hello.pub_key)?;

        let conn = STClient {
            host: host.to_string(),
            port,
            key: key_exchanger.key,
            session_id: client_hello.session_id,
            time_stamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            datapack: DataPack::default(),
            stream,
            encryption_type: key_exchanger.encryption,
        };

        Ok(conn)
    }
    /** Send data */
    pub fn send(&mut self) -> IOResult<()> {
        self.datapack.update_timestamp();
        self.datapack.session_id = self.session_id;

        match self.datapack.encoding {
            ZSTD => {
                self.datapack.payload = zstd::encode_all(&self.datapack.payload[..], 3)?.to_vec();
            }
            GZIP => {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(&self.datapack.payload)?;
                self.datapack.payload.extend(&encoder.finish()?);
            }
            LZMA2 => {
                let mut compressed_data = Vec::new();
                lzma_rs::lzma2_compress(
                    &mut BufReader::new(&self.datapack.payload[..]),
                    &mut compressed_data,
                )?;
                self.datapack.payload.extend(&compressed_data);
            }
            _ => {}
        }

        match self.encryption_type {
            EncryptionType::AES128GCM => {
                self.datapack.crypto = vec![0; AES_NONCE_SIZE];
                rand::thread_rng().fill_bytes(&mut self.datapack.crypto);
                let iv: [u8; AES_NONCE_SIZE] = self.datapack.crypto.clone().try_into().unwrap();
                if let Key::AES128GCM(key) = self.key {
                    self.datapack.payload = aes128_gcm_encrypt(&self.datapack.payload, &key, &iv);
                }
            }
            EncryptionType::AES256GCM => {
                self.datapack.crypto = vec![0; AES_NONCE_SIZE];
                rand::thread_rng().fill_bytes(&mut self.datapack.crypto);
                let nonce: [u8; AES_NONCE_SIZE] = self.datapack.crypto.clone().try_into().unwrap();
                if let Key::AES256GCM(key) = self.key {
                    self.datapack.payload =
                        aes256_gcm_encrypt(&self.datapack.payload, &key, &nonce);
                }
            }
            EncryptionType::ChaCha20Poly1305 => {
                self.datapack.crypto = vec![0; CHACHA20_NONCE_SIZE];
                rand::thread_rng().fill_bytes(&mut self.datapack.crypto);
                let nonce: [u8; CHACHA20_NONCE_SIZE] =
                    self.datapack.crypto.clone().try_into().unwrap();
                if let Key::ChaCha20(key) = self.key {
                    self.datapack.payload =
                        chacah20poly1305_encrypt(key, nonce, &self.datapack.payload);
                }
            }
            EncryptionType::AES128CCM => {
                self.datapack.crypto = vec![0; AES_NONCE_SIZE];
                rand::thread_rng().fill_bytes(&mut self.datapack.crypto);
                let nonce: [u8; AES_NONCE_SIZE] = self.datapack.crypto.clone().try_into().unwrap();
                if let Key::AES128CCM(key) = self.key {
                    self.datapack.payload =
                        aes128_ccm_encrypt(&self.datapack.payload, &key, &nonce);
                }
            }
            EncryptionType::AES256CCM => {
                self.datapack.crypto = vec![0; AES_NONCE_SIZE];
                rand::thread_rng().fill_bytes(&mut self.datapack.crypto);
                let nonce: [u8; AES_NONCE_SIZE] = self.datapack.crypto.clone().try_into().unwrap();
                if let Key::AES256CCM(key) = self.key {
                    self.datapack.payload =
                        aes256_ccm_encrypt(&self.datapack.payload, &key, &nonce);
                }
            }
        }

        let data = self.datapack.build();
        self.stream.write_all(&data)?;

        let original_datapack = self.datapack.clone();

        /* METHOD_OK doesn't require verification, so we needn't handle METHOD_OK or METHOD_REQUEST_RESEND reply. */
        if self.datapack.method != METHOD_OK {
            self.receive()?;
            if self.datapack.method == METHOD_REQUEST_RESEND {
                self.datapack = original_datapack;
                self.send()?;
            }
        }

        Ok(())
    }
    pub fn receive(&mut self) -> IOResult<()> {
        /* Receive header */
        let mut header = [0; HEADER_SIZE];
        self.stream.read_exact(&mut header)?;
        self.datapack.parse(&header);

        let mut crypto_size = [0; 2];
        self.stream.read_exact(&mut crypto_size)?;
        self.datapack.crypto = vec![0; u16::from_be_bytes(crypto_size) as usize];
        self.stream.read_exact(&mut self.datapack.crypto)?;

        let mut payload_size = [0; 2];
        self.stream.read_exact(&mut payload_size)?;
        self.datapack.payload = vec![0; u16::from_be_bytes(payload_size) as usize];
        self.stream.read_exact(&mut self.datapack.payload)?;

        /* check sha256sum */
        if !self.datapack.verify(&self.datapack.payload) {
            /* If failed, then request resend */
            self.datapack.method = METHOD_REQUEST_RESEND;
            self.datapack.encoding = PLAIN;
            self.datapack.payload.clear();
            self.send()?;
            self.receive()?;
        } else if self.datapack.method != METHOD_OK {
            let original_datapack = self.datapack.clone();
            self.datapack.encoding = PLAIN;
            self.datapack.method = METHOD_OK;
            self.datapack.payload.clear();
            self.send()?;
            self.datapack = original_datapack;
        }

        match self.encryption_type {
            EncryptionType::AES128GCM => {
                let nonce: [u8; AES_NONCE_SIZE] = self.datapack.clone().crypto.try_into().unwrap();
                if let Key::AES128GCM(key) = self.key {
                    self.datapack.payload =
                        aes128_gcm_decrypt(&self.datapack.payload, &key, &nonce);
                }
            }
            EncryptionType::AES256GCM => {
                if let Key::AES256GCM(key) = self.key {
                    let nonce: [u8; AES_NONCE_SIZE] =
                        self.datapack.clone().crypto.try_into().unwrap();
                    self.datapack.payload =
                        aes256_gcm_decrypt(&self.datapack.payload, &key, &nonce);
                }
            }
            EncryptionType::ChaCha20Poly1305 => {
                let nonce: [u8; CHACHA20_NONCE_SIZE] =
                    self.datapack.clone().crypto.try_into().unwrap();
                if let Key::ChaCha20(key) = self.key {
                    self.datapack.payload =
                        chacah20poly1305_decrypt(key, nonce, &self.datapack.payload);
                }
            }
            EncryptionType::AES128CCM => {
                let nonce: [u8; AES_NONCE_SIZE] = self.datapack.clone().crypto.try_into().unwrap();
                if let Key::AES128CCM(key) = self.key {
                    self.datapack.payload =
                        aes128_ccm_decrypt(&self.datapack.payload, &key, &nonce);
                }
            }
            EncryptionType::AES256CCM => {
                let nonce: [u8; AES_NONCE_SIZE] = self.datapack.clone().crypto.try_into().unwrap();
                if let Key::AES256CCM(key) = self.key {
                    self.datapack.payload =
                        aes256_ccm_decrypt(&self.datapack.payload, &key, &nonce);
                }
            }
        }

        match self.datapack.encoding {
            ZSTD => {
                let payload = self.datapack.payload.clone();
                self.datapack.payload = zstd::decode_all(&payload[..])?;
            }
            GZIP => {
                let mut decoder = flate2::read::GzDecoder::new(&self.datapack.payload[..]);
                let mut decompressed_data = Vec::new();
                decoder.read_to_end(&mut decompressed_data)?;
                self.datapack.payload = decompressed_data;
            }
            LZMA2 => {
                let mut decompressed_data = Vec::new();
                lzma_rs::lzma2_decompress(
                    &mut BufReader::new(&self.datapack.payload[..]),
                    &mut decompressed_data,
                )
                .unwrap();
                self.datapack.payload = decompressed_data;
            }
            _ => {}
        }

        Ok(())
    }
    /** close a connection */
    pub fn close(self) -> IOResult<()> {
        self.stream.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }
}

impl STServer {
    pub fn bind(host: &str, port: u16) -> IOResult<Self> {
        let conn = STServer {
            host: host.to_string(),
            port,
            listener: TcpListener::bind(format!("{}:{}", host, port))?,
            clients: Vec::new(),
        };

        Ok(conn)
    }
    pub fn listen(&mut self) -> IOResult<()> {
        let host;
        let port;
        let mut stream;
        {
            let ret = self.listener.accept()?;
            stream = ret.0;
            match ret.1 {
                std::net::SocketAddr::V4(addr) => {
                    host = addr.ip().to_string();
                    port = addr.port();
                }
                std::net::SocketAddr::V6(addr) => {
                    host = addr.ip().to_string();
                    port = addr.port();
                }
            }
        }
        /* check client version */
        let mut client_hello = ClientHello::default();
        client_hello.receive(&mut stream)?;
        if !client_hello.verify() {
            return Err(Error::from(ErrorKind::Other));
        }

        let mut seever_hello = ServerHello::new_server(client_hello.session_id);
        seever_hello.send(&mut stream)?;

        let mut key_exchanger = KeyExchange::default();

        key_exchanger.receive(&mut stream, &seever_hello.priv_key.unwrap())?;

        let client = STClient {
            host,
            port,
            session_id: client_hello.session_id,
            key: key_exchanger.key,
            time_stamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            datapack: DataPack::default(),
            stream,
            encryption_type: key_exchanger.encryption,
        };

        self.clients.push(client);

        Ok(())
    }
    pub fn accept(&mut self) -> &mut STClient {
        let len = self.clients.len();
        &mut self.clients[len - 1]
    }
}
