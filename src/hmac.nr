use crate::constants::{I_PAD, O_PAD, SHA256_BLOCKSIZE};
use dep::std::hash::sha256_var;

struct HmacSha256<K, N> {
    key: [u8; K],
    inner_key_pad: [u8; SHA256_BLOCKSIZE],
    outer_key_pad: [u8; SHA256_BLOCKSIZE],
    message: [u8; N],
}

impl<K, N> HmacSha256<K, N> {
    pub fn init(message: [u8; N], key: [u8; K]) -> Self {
        let mut inner_key_pad: [u8; SHA256_BLOCKSIZE] = [0; SHA256_BLOCKSIZE];
        let mut outer_key_pad: [u8; SHA256_BLOCKSIZE] = [0; SHA256_BLOCKSIZE];

        let mut block_size_key: [u8; SHA256_BLOCKSIZE] = [0; SHA256_BLOCKSIZE];

        let key_len = key.len();

        if key_len > SHA256_BLOCKSIZE {
            let key_hash = sha256_var(key, key.len());

            for i in 0..32 {
                block_size_key[i] = key_hash[i];
            }
            for i in 0..32 {
                block_size_key[i] = 0;
            }
        } else if key_len < SHA256_BLOCKSIZE {

            for i in 0..key_len {
                block_size_key[i] = key[i];
            }
            //padding
            for i in key_len..SHA256_BLOCKSIZE {
                block_size_key[i] = 0;
            }
        } else {
            for i in 0..SHA256_BLOCKSIZE {
                block_size_key[i] = key[i];
            }
        }

        for i in 0..SHA256_BLOCKSIZE {
            inner_key_pad[i] = block_size_key[i] ^ I_PAD;
            outer_key_pad[i] = block_size_key[i] ^ O_PAD;
        }

        Self {
            key,
            inner_key_pad,
            outer_key_pad,
            message,
        }
    }

    pub fn compute(self) -> [u8; 32] {
        let mut inner_pad: [u8; 128] = [0; 128];
        for i in 0..64 {
            inner_pad[i] = self.inner_key_pad[i];
        }

        for i in 64..128 {
            inner_pad[i] = self.message[i-64];
        }

        let hash_i_pad = sha256_var(inner_pad, 128);

        let mut outer_pad: [u8; 96] = [0; 96];

        for i in 0..64 {
            outer_pad[i] = self.outer_key_pad[i];
        }

        for i in 64..96 {
            outer_pad[i] = hash_i_pad[i-64];
        }

        let hmac = sha256_var(outer_pad, 96);

        hmac
    }
}