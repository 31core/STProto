use crypto::digest::Digest;
use crypto::sha3::Sha3;

pub fn gen_key(raw_key: &[u8], time_stamp: u64) -> [u8; 32] {
    let mut key = [0; 32];
    let mut mix_key = Vec::new();
    mix_key.extend(raw_key);
    mix_key.extend(time_stamp.to_be_bytes());

    let mut hasher = Sha3::sha3_256();
    let mut sha256sum = [0; 32];
    hasher.input(&mix_key);
    hasher.result(&mut sha256sum);
    key.copy_from_slice(&sha256sum);
    key
}
