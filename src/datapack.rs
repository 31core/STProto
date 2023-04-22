use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::time::*;

pub const HEADER_SIZE: usize = 46;

#[derive(Debug, Clone, Default)]
pub struct DataPack {
    method: u8,
    time_stamp: u64,
    encoding: u8,
    sha256: [u8; 32],
    size: u32,
    data: Vec<u8>,
}

#[allow(dead_code)]
impl DataPack {
    pub fn new() -> DataPack {
        DataPack::default()
    }
    pub fn build(&mut self) -> Vec<u8> {
        self.digest();
        self.size = self.data.len() as u32;

        let mut pack: Vec<u8> = vec![];
        pack.push(self.method);
        pack.extend(self.time_stamp.to_be_bytes());
        pack.push(self.encoding);
        pack.extend(self.sha256);
        pack.extend(self.size.to_be_bytes());
        pack.extend(&self.data);

        pack
    }
    pub fn parse(&mut self, data: &[u8]) {
        self.method = data[0];
        self.time_stamp = u64::from_be_bytes(data[1..9].try_into().unwrap());
        self.encoding = data[9];
        self.sha256 = data[10..42].try_into().unwrap();
        self.size = u32::from_be_bytes(data[42..46].try_into().unwrap());
        for byte in &data[46..] {
            self.data.push(*byte);
        }
    }
    /// checksum for SHA256
    pub fn verify(&self, data: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.input(data);
        let mut sha256sum = [0; 32];
        hasher.result(&mut sha256sum);

        if sha256sum != self.sha256 {
            return false;
        }
        true
    }
    pub fn update_timestamp(&mut self) {
        if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {
            self.time_stamp = n.as_secs()
        }
    }
    pub fn get_timestamp(&self) -> u64 {
        self.time_stamp
    }
    pub fn set_encoding(&mut self, encoding: u8) {
        self.encoding = encoding;
    }
    pub fn set_data(&mut self, data: &[u8]) {
        self.data = data.to_vec();
    }
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }
    pub fn len(&self) -> usize {
        self.size as usize
    }
    fn digest(&mut self) {
        let mut hasher = Sha256::new();
        hasher.input(&self.data);

        hasher.result(&mut self.sha256);
    }
}
