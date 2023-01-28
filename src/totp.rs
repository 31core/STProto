use crypto::digest::Digest;
use crypto::sha2::Sha256;

pub fn gen_key(raw_key: &[u8], time_stamp: u64) -> [u8; 32] {
    let mut key = [0; 32];
    let mut mix_key = Vec::new();
    mix_key.extend(raw_key.iter());
    mix_key.extend(time_stamp.to_be_bytes().iter());

    let mut hasher = Sha256::new();
    let mut sha256sum = [0; 32];
    hasher.input(&mix_key);
    hasher.result(&mut sha256sum);
    for i in 0..32 {
        key[i] = sha256sum[i];
    }
    key
}
