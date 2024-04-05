use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::time::*;

pub const HEADER_SIZE: usize = 50;

#[derive(Debug, Clone, Default)]
/**
 * # Data structure
 *
 * |Start|End|Description|
 * |-----|---|-----------|
 * |0    |1  |Method     |
 * |1    |9  |Session ID |
 * |9    |17  |Timestamp  |
 * |17    |18 |Encoding   |
 * |18   |50 |SHA256 summary|
*/
pub struct DataPack {
    pub method: u8,
    pub session_id: u64,
    time_stamp: u64,
    pub encoding: u8,
    sha256: [u8; 32],
    pub crypto: Vec<u8>,
    pub payload: Vec<u8>,
}

impl DataPack {
    pub fn build(&mut self) -> Vec<u8> {
        self.digest();

        let mut pack: Vec<u8> = vec![];
        pack.push(self.method);
        pack.extend(self.session_id.to_be_bytes());
        pack.extend(self.time_stamp.to_be_bytes());
        pack.push(self.encoding);
        pack.extend(self.sha256);
        pack.extend((self.crypto.len() as u16).to_be_bytes());
        pack.extend(&self.crypto);
        pack.extend((self.payload.len() as u16).to_be_bytes());
        pack.extend(&self.payload);

        pack
    }
    /** parse datapack from bytes */
    pub fn parse(&mut self, data: &[u8]) {
        self.method = data[0];
        self.session_id = u64::from_be_bytes(data[1..9].try_into().unwrap());
        self.time_stamp = u64::from_be_bytes(data[9..17].try_into().unwrap());
        self.encoding = data[17];
        self.sha256 = data[18..50].try_into().unwrap();

        /*for byte in &data[54..] {
            self.data.push(*byte);
        }*/
    }
    /** checksum for SHA256 */
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
    fn digest(&mut self) {
        let mut hasher = Sha256::new();
        hasher.input(&self.payload);

        hasher.result(&mut self.sha256);
    }
}
