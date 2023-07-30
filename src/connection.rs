use crate::datapack::*;
use crate::handshaking::ClientHello;
use crate::method::*;
use crate::totp;
use crypto::aes::*;
use crypto::blockmodes::*;
use crypto::buffer::*;
use rand::{Rng, RngCore};
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::*;
use std::io::Result as IOResult;
use std::io::*;
use std::{io::Write, net::*};

const RSA_BITS: usize = 3072;
const IV_SIZE: usize = 16;

impl Write for STClient {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.datapack.set_method(METHOD_SEND_DATA);
        self.datapack.set_data(buf);
        self.send()?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Read for STClient {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.datapack.get_data_size() == 0 {
            let err = self.receive();

            if err.is_err() {
                return Ok(0);
            }
        }

        let size = self.datapack.get_data_size();

        let mut i = 0;
        while i < buf.len() && !self.datapack.data.is_empty() {
            buf[i] = *self.datapack.data.first().unwrap();
            self.datapack.data.remove(0);
            i += 1;
        }
        Ok(size)
    }
}

impl Drop for STClient {
    fn drop(&mut self) {
        /* erase keys from memory */
        for i in &mut self.key {
            *i = 0;
        }
        for i in &mut self.iv {
            *i = 0;
        }
    }
}

#[allow(dead_code)]
pub struct STClient {
    host: String,
    port: u16,
    iv: [u8; IV_SIZE],
    key: Vec<u8>,
    time_stamp: u64, //the time stamp of connection setting up
    pub datapack: DataPack,
    stream: TcpStream,
}

#[allow(dead_code)]
pub struct STServer {
    host: String,
    port: u16,
    listener: TcpListener,
    clients: Vec<STClient>,
}

impl STClient {
    pub fn connect(host: &str, port: u16) -> IOResult<Self> {
        let mut stream;

        match TcpStream::connect(format!("{}:{}", host, port)) {
            Ok(s) => stream = s,
            Err(_) => return Err(Error::from(ErrorKind::Other)),
        }

        /* send client version to server */
        let client_hello = ClientHello::new();
        client_hello.send(&mut stream)?;

        /* receive RSA public key from server */
        /* receive RSA pubkey size */
        let size = {
            let mut size = [0; 2];
            stream.read_exact(&mut size[..])?;
            u16::from_be_bytes(size)
        };
        /* receive RSA pubkey */
        let mut buf = vec![0; size as usize];
        stream.read_exact(&mut buf[..])?;
        let pub_key = RsaPublicKey::from_public_key_der(&buf).unwrap();
        /* generate a key */
        let key = {
            let mut rng = rand::thread_rng();
            let key_len = rng.gen_range(128..=(RSA_BITS / 8 - 11));
            let mut key = vec![0; key_len];
            rng.fill_bytes(&mut key);
            key
        };
        let encrypted_key = {
            let mut rng = rand::thread_rng();
            pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &key).unwrap()
        };

        /* send key size */
        stream.write_all(&(encrypted_key.len() as u16).to_be_bytes())?;
        /* send key */
        stream.write_all(&encrypted_key)?;

        /* generate and send iv to server */
        /* generate iv */
        let iv = {
            let mut rng = rand::thread_rng();
            let mut iv = [0; IV_SIZE];
            rng.fill_bytes(&mut iv);
            iv
        };
        let encrypted_iv = {
            let mut rng = rand::thread_rng();
            pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &iv).unwrap()
        };
        stream.write_all(&(encrypted_iv.len() as u16).to_be_bytes())?;
        stream.write_all(&encrypted_iv)?;

        let conn = STClient {
            host: host.to_string(),
            port,
            iv,
            key,
            time_stamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            datapack: DataPack::new(),
            stream,
        };

        Ok(conn)
    }
    pub fn send(&mut self) -> IOResult<()> {
        self.datapack.update_timestamp();
        let key = totp::gen_key(&self.key, self.datapack.get_timestamp());
        self.datapack.set_data(&aes256_cbc_encrypt(
            self.datapack.get_data(),
            &key,
            &self.iv,
        ));
        let data = self.datapack.build();
        self.stream.write_all(&data)?;

        let original_datapack = self.datapack.clone();

        /* METHOD_OK doesn't require verification, so we needn't handle METHOD_OK or METHOD_REQUEST_RESEND reply. */
        if self.datapack.get_method() != METHOD_OK {
            self.receive()?;
            if self.datapack.get_method() == METHOD_REQUEST_RESEND {
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

        let size = self.datapack.len();
        let mut data = vec![0; size];
        self.stream.read_exact(&mut data)?;

        /* check sha256sum */
        if !self.datapack.verify(&data) {
            /* If failed, then request resend */
            self.datapack.set_method(METHOD_REQUEST_RESEND);
            self.datapack.clear();
            self.send()?;
            self.receive()?;
        } else if self.datapack.get_method() != METHOD_OK {
            let original_datapack = self.datapack.clone();
            self.datapack.set_method(METHOD_OK);
            self.datapack.clear();
            self.send()?;
            self.datapack = original_datapack;
        }

        let key = totp::gen_key(&self.key, self.datapack.get_timestamp());
        self.datapack
            .set_data(&aes256_cbc_decrypt(&data, &key, &self.iv));
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
    pub fn listen(&mut self) -> Result<()> {
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
        {
            let mut client_hello = ClientHello::new();
            client_hello.receive(&mut stream)?;
            if !client_hello.verify() {
                return Err(Error::from(ErrorKind::Other));
            }
        }

        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, RSA_BITS).unwrap();
        let pub_key = priv_key.to_public_key();
        let binding = pub_key.to_public_key_der().unwrap();
        let pub_key_der = binding.as_bytes();
        /* send RSA public key */
        stream.write_all(&(pub_key_der.len() as u16).to_be_bytes())?; //send RSA pubkey size
        stream.write_all(pub_key_der)?; //send RSA pubkey

        /* receive key from client */
        /* receive key size */
        let size = {
            let mut size = [0; 2];
            stream.read_exact(&mut size)?;
            u16::from_be_bytes(size)
        };
        /* receive key */
        let key = {
            let mut buf = vec![0; size as usize];
            stream.read_exact(&mut buf)?;
            priv_key.decrypt(rsa::Pkcs1v15Encrypt, &buf).unwrap()
        };

        /* receive key from client */
        /* receive key size */
        let size = {
            let mut size = [0; 2];
            stream.read_exact(&mut size)?;
            u16::from_be_bytes(size)
        };
        /* receive key */
        let iv = {
            let mut buf = vec![0; size as usize];
            stream.read_exact(&mut buf)?;
            let data = priv_key.decrypt(rsa::Pkcs1v15Encrypt, &buf).unwrap();
            let mut iv = [0; IV_SIZE];
            iv.copy_from_slice(&data[..IV_SIZE]);
            iv
        };

        let client = STClient {
            host,
            port,
            key,
            iv,
            time_stamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            datapack: DataPack::new(),
            stream,
        };

        self.clients.push(client);

        Ok(())
    }
    pub fn accept(&mut self) -> &mut STClient {
        let len = self.clients.len();
        &mut self.clients[len - 1]
    }
}

fn aes256_cbc_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut encryptor = cbc_encryptor(KeySize::KeySize256, key, iv, PkcsPadding);

    let mut encrypted_data = Vec::<u8>::new();
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

fn aes256_cbc_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut decryptor = cbc_decryptor(KeySize::KeySize256, key, iv, PkcsPadding);

    let mut decrypted_data = Vec::<u8>::new();
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
