//! A small SHA-256 implementation, for executable hashes in samples.
//!
//! A sample names the programs of a session by hash, so a researcher can
//! tell two different `python3` binaries apart without a path. The workspace
//! carries no cryptography crate, and the need is one well-specified
//! function, so it lives here with its test vectors. The implementation
//! streams, because a program file can be large.

/// The round constants of SHA-256, FIPS 180-4 section 4.2.2.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// A streaming SHA-256 state.
#[derive(Debug)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Makes the initial state, FIPS 180-4 section 5.3.3.
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    /// Absorbs bytes. Any number of calls, any length.
    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let want = 64 - self.buffered;
            let take = want.min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
        let mut blocks = data.chunks_exact(64);
        for block in &mut blocks {
            let mut owned = [0u8; 64];
            owned.copy_from_slice(block);
            self.compress(&owned);
        }
        // The tail only fills the buffer when the buffer is empty; a partial
        // buffer from an earlier call must stay untouched.
        if self.buffered == 0 {
            let rest = blocks.remainder();
            self.buffer[..rest.len()].copy_from_slice(rest);
            self.buffered = rest.len();
        }
    }

    /// Finishes and returns the digest.
    pub fn finish(mut self) -> [u8; 32] {
        let length = self.length;
        self.update_pad(&[0x80]);
        while self.buffered != 56 {
            self.update_pad(&[0]);
        }
        let bits = length.wrapping_mul(8);
        self.update_pad(&bits.to_be_bytes());
        let mut out = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            out[4 * index..4 * index + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Absorbs padding bytes without counting them as message length.
    fn update_pad(&mut self, data: &[u8]) {
        for byte in data {
            self.buffer[self.buffered] = *byte;
            self.buffered += 1;
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
    }

    /// Compresses one 64-byte block, FIPS 180-4 section 6.2.2.
    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (index, word) in w.iter_mut().take(16).enumerate() {
            let begin = 4 * index;
            *word = u32::from_be_bytes([
                block[begin],
                block[begin + 1],
                block[begin + 2],
                block[begin + 3],
            ]);
        }
        for index in 16..64 {
            let prior = w[index - 15];
            let s0 = prior.rotate_right(7) ^ prior.rotate_right(18) ^ (prior >> 3);
            let two = w[index - 2];
            let s1 = two.rotate_right(17) ^ two.rotate_right(19) ^ (two >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (word, sum) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word = word.wrapping_add(sum);
        }
    }
}

/// Hashes one slice of bytes.
pub fn digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finish()
}

/// Returns the bytes as lower-case hexadecimal.
pub fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test vectors of FIPS 180-4 and of the `sha256sum` tool.
    #[test]
    fn the_known_vectors_match() {
        assert_eq!(
            hex(&digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// Streaming in odd pieces must give the digest of the whole message.
    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|value| value as u8).collect();
        let mut hasher = Sha256::new();
        for chunk in data.chunks(7) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finish(), digest(&data));
    }

    /// A message that needs padding past one block boundary.
    #[test]
    fn a_long_message_hashes() {
        let data = vec![b'a'; 1_000];
        assert_eq!(
            hex(&digest(&data)),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }
}
