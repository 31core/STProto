use super::datapack::*;
use super::handshaking::ClientHello;
use super::totp;
use crypto::aes::*;
use crypto::blockmodes::*;
use crypto::buffer::*;
use rand::{Rng, RngCore};
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::*;
use std::io::*;
use std::{io::Write, net::*};

const RSA_BITS: usize = 2048;
const IV_SIZE: usize = 16;

pub struct Connection {
    pub host: String,
    pub port: u16,
    pub iv: [u8; IV_SIZE],
    pub key: Vec<u8>,
    pub time_stamp: u64, //the time stamp of connection setting up
    pub datapack: DataPack,
    pub stream: TcpStream,
    pub listener: Option<TcpListener>, //only for server
}

impl Connection {
    pub fn connect(host: &str, port: u16) -> Result<Self> {
        let mut stream;

        match TcpStream::connect(format!("{}:{}", host, port)) {
            Ok(s) => stream = s,
            Err(_) => return Err(Error::from(ErrorKind::Other)),
        }

        /* send client version to server */
        let client_hello = ClientHello::new();
        client_hello.send(&mut stream).unwrap();

        /* receive RSA public key from server */
        /* receive RSA pubkey size */
        let size = {
            let mut size = [0; 2];
            stream.read(&mut size[..])?;
            u16::from_be_bytes(size)
        };
        /* receive RSA pubkey */
        let mut buf = vec![0; size as usize];
        stream.read(&mut buf[..])?;
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
        stream.write(&(encrypted_key.len() as u16).to_be_bytes())?;
        /* send key */
        stream.write(&encrypted_key)?;

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
        stream.write(&(encrypted_iv.len() as u16).to_be_bytes())?;
        stream.write(&encrypted_iv)?;

        let conn = Connection {
            host: host.to_string(),
            port,
            iv,
            key,
            time_stamp: 0,
            datapack: DataPack::new(),
            stream,
            listener: None,
        };

        Ok(conn)
    }
    pub fn listen(host: &str, port: u16) -> Result<Self> {
        let listener = TcpListener::bind(format!("{}:{}", host, port))?;

        let mut stream = listener.accept().unwrap().0;

        /* check client version */
        {
            let mut client_hello = ClientHello::new();
            client_hello.receive(&mut stream).unwrap();
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
        stream.write(&(pub_key_der.len() as u16).to_be_bytes())?; //send RSA pubkey size
        stream.write(pub_key_der)?; //send RSA pubkey

        /* receive key from client */
        /* receive key size */
        let size = {
            let mut size = [0; 2];
            stream.read(&mut size)?;
            u16::from_be_bytes(size)
        };
        /* receive key */
        let key = {
            let mut buf = vec![0; size as usize];
            stream.read(&mut buf)?;
            priv_key.decrypt(rsa::Pkcs1v15Encrypt, &buf).unwrap()
        };

        /* receive key from client */
        /* receive key size */
        let size = {
            let mut size = [0; 2];
            stream.read(&mut size)?;
            u16::from_be_bytes(size)
        };
        /* receive key */
        let iv = {
            let mut buf = vec![0; size as usize];
            stream.read(&mut buf)?;
            let data = priv_key.decrypt(rsa::Pkcs1v15Encrypt, &buf).unwrap();
            let mut iv = [0; IV_SIZE];
            for i in 0..IV_SIZE {
                iv[i] = data[i];
            }
            iv
        };

        let conn = Connection {
            host: host.to_string(),
            port,
            key,
            iv,
            time_stamp: 0,
            datapack: DataPack::new(),
            stream,
            listener: Some(listener),
        };

        Ok(conn)
    }
    pub fn send(&mut self) -> Result<()> {
        self.datapack.get_timestamp();
        let key = totp::gen_key(&self.key, self.datapack.time_stamp);
        self.datapack.data = aes256_cbc_encrypt(&self.datapack.data, &key, &self.iv);
        let data = self.datapack.build();
        self.stream.write(&data)?;

        Ok(())
    }
    pub fn receive(&mut self) -> Result<()> {
        /* Receive header */
        let mut header = [0; HEADER_SIZE];
        self.stream.read(&mut header)?;
        self.datapack.parse(&header);

        let mut size = self.datapack.size as usize;
        let mut data = Vec::new();
        loop {
            let mut tmp = vec![0; self.datapack.size as usize];
            let recv_size = self.stream.read(&mut tmp)?;
            data.extend(tmp[0..recv_size].iter());
            size -= recv_size;
            if size == 0 {
                break;
            }
        }

        let key = totp::gen_key(&self.key, self.datapack.time_stamp);
        self.datapack.data = aes256_cbc_decrypt(&data, &key, &self.iv);
        Ok(())
    }
    /// write data to be sent
    pub fn write(&mut self, data: &[u8]) {
        self.datapack.data = data.to_vec();
    }
    /// read received data
    pub fn read(&self) -> &Vec<u8> {
        &self.datapack.data
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

        encrypted_data.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
        );

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
        decrypted_data.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => continue,
        }
    }

    decrypted_data
}
