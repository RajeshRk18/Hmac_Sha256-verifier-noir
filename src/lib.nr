mod hmac;
mod constants;

use crate::hmac::HmacSha256;
use crate::constants::SHA256_BLOCKSIZE;

#[test]
fn test() {
    let response: [u8; 80] = [217, 172, 44, 55, 194, 149, 201, 98, 58, 113, 138, 215, 154, 126, 21, 247, 95, 158, 253, 101, 65, 141, 74, 124, 250, 128, 93, 5, 48, 171, 32, 235, 252, 187, 45, 144, 183, 194, 34, 153, 251, 130, 63, 51, 28, 224, 66, 191, 144, 43, 240, 79, 230, 64, 123, 130, 255, 15, 55, 127, 102, 118, 107, 188, 240, 130, 24, 84, 151, 211, 136, 213, 156, 51, 240, 94, 113, 44, 117, 195];
    let key: [u8; 7] = [22, 139, 145, 6, 197, 166, 137];
    let expected: [u8; 32] = [232, 252, 220, 195, 159, 115, 4, 76, 151, 50, 208, 166, 13, 168, 209, 59, 18, 51, 226, 79, 67, 46, 89, 56, 186, 151, 180, 128, 218, 230, 27, 155];

    let hmac = HmacSha256::init(response, key);
    let inner_pad_size = response.len() + SHA256_BLOCKSIZE;
    let computed_tag = hmac.compute(inner_pad_size);
   // println(computed_tag);
    assert(computed_tag == expected);
}