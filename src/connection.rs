use super::datapack::*;
use super::handshaking::ClientHello;
use rand::Rng;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::*;
use std::io::*;
use std::{io::Write, net::*};
pub struct Connection {
    pub host: String,
    pub port: u16,
    pub key: Vec<u8>,
    pub time_stamp: u64,
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
            let mut size = [0; 8];
            stream.read(&mut size[..])?;
            usize::from_be_bytes(size)
        };
        /* receive RSA pubkey */
        let mut buf = {
            let mut buf = Vec::new();
            for _ in 0..size {
                buf.push(0);
            }
            buf
        };
        stream.read(&mut buf[..])?;
        let pub_key = RsaPublicKey::from_public_key_der(&buf).unwrap();
        /* generate a key */
        let key = {
            let mut rng = rand::thread_rng();
            let mut key = Vec::new();
            let key_len: u16 = rng.gen_range(128..256);
            for _ in 0..key_len {
                key.push(rng.gen::<u8>());
            }
            key
        };
        let encrypted_key = {
            let mut rng = rand::thread_rng();
            pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &key).unwrap()
        };

        /* send key size */
        stream.write(&encrypted_key.len().to_be_bytes())?;
        /* send key */
        stream.write(&encrypted_key)?;

        let conn = Connection {
            host: host.to_string(),
            port,
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
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pub_key = priv_key.to_public_key();
        let binding = pub_key.to_public_key_der().unwrap();
        let pub_key_der = binding.as_bytes();
        /* send RSA public key */
        stream.write(&pub_key_der.len().to_be_bytes())?; //send RSA pubkey size
        stream.write(pub_key_der)?; //send RSA pubkey

        /* receive key size */
        let size = {
            let mut size = [0; 8];
            stream.read(&mut size)?;
            usize::from_be_bytes(size)
        };
        /* receive key */
        let key = {
            let mut buf = Vec::new();
            for _ in 0..size {
                buf.push(0);
            }
            stream.read(&mut buf)?;
            priv_key.decrypt(rsa::Pkcs1v15Encrypt, &buf).unwrap()
        };

        let conn = Connection {
            host: host.to_string(),
            port,
            key,
            time_stamp: 0,
            datapack: DataPack::new(),
            stream,
            listener: Some(listener),
        };
        Ok(conn)
    }
    pub fn send(&mut self) -> Result<()> {
        let data = self.datapack.build();
        self.stream.write(&data[..])?;
        Ok(())
    }
    pub fn receive(&mut self) -> Result<()> {
        /* Receive header */
        let mut header = [0; HEADER_SIZE];
        self.stream.read(&mut header)?;
        self.datapack.parse(&header);

        let mut data = {
            let mut data = Vec::new();
            for _ in 0..self.datapack.size as usize {
                data.push(0);
            }
            data
        };
        self.stream.read(&mut data)?;
        self.datapack.data = data.to_vec();
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
