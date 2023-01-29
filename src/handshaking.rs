use super::version::*;
use std::io::Read;
use std::{io::Write, net::TcpStream};
pub struct ClientHello {
    pub proto_version: u8,
    pub client_version_major: u8,
    pub client_version_minor: u8,
}

impl ClientHello {
    pub fn new() -> Self {
        ClientHello {
            proto_version: PROTO_VERSION,
            client_version_major: CLIENT_VERSION_MAJOR,
            client_version_minor: CLIENT_VERSION_MINOR,
        }
    }
    pub fn send(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let mut data = Vec::new();
        data.push(self.proto_version);
        data.push(self.client_version_major);
        data.push(self.client_version_minor);
        stream.write(&data)?;
        Ok(())
    }
    pub fn receive(&mut self, stream: &mut TcpStream) -> std::io::Result<()> {
        let mut data = [0; 3];
        stream.read(&mut data)?;
        self.proto_version = data[0];
        self.client_version_major = data[1];
        self.client_version_minor = data[2];
        Ok(())
    }
    pub fn verify(&self) -> bool {
        if self.proto_version != PROTO_VERSION {
            return false;
        }
        true
    }
}
