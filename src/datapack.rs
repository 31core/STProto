use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::time::*;

pub const HEADER_SIZE: usize = 46;

#[derive(Debug, Clone)]
pub struct DataPack {
    pub method: u8,
    pub time_stamp: u64,
    pub encoding: u8,
    pub sha256: [u8; 32],
    pub size: u32,
    pub data: Vec<u8>,
}

impl DataPack {
    pub fn new() -> DataPack {
        DataPack {
            method: 0,
            time_stamp: 0,
            encoding: 0,
            sha256: [0; 32],
            size: 0,
            data: vec![],
        }
    }
    pub fn build(&mut self) -> Vec<u8> {
        self.get_timestamp();
        self.digest();
        self.size = self.data.len() as u32;

        let mut pack: Vec<u8> = vec![];
        pack.push(self.method);
        for byte in self.time_stamp.to_be_bytes() {
            pack.push(byte);
        }
        pack.push(self.encoding);
        for byte in self.sha256 {
            pack.push(byte);
        }
        for byte in self.size.to_be_bytes() {
            pack.push(byte);
        }
        for byte in self.data.iter() {
            pack.push(*byte);
        }
        return pack;
    }
    pub fn parse(&mut self, data: &[u8]) {
        self.method = data[0];
        self.time_stamp = u64::from_be_bytes(data[1..9].try_into().unwrap());
        self.encoding = data[9];
        self.sha256 = data[10..42].try_into().unwrap();
        self.size = u32::from_be_bytes(data[42..46].try_into().unwrap());
        for byte in data[46..].iter() {
            self.data.push(*byte);
        }
    }
    pub fn get_timestamp(&mut self) {
        if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {
            self.time_stamp = n.as_secs()
        }
    }
    pub fn digest(&mut self) {
        let mut hasher = Sha256::new();
        hasher.input(&self.data);

        hasher.result(&mut self.sha256[..])
    }
}
