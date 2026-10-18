use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
  #[error("Invalid key or IV length")]
  InvalidKeyOrIv,
  #[error("Bad MAC")]
  BadMac,
  #[error("Decryption failed")]
  Decrypt,
}

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
  let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
  mac.update(data);
  mac.finalize().into_bytes().into()
}

pub fn verify_mac(key: &[u8], data: &[u8], expected: &[u8]) -> Result<(), CryptoError> {
  if expected.is_empty() || expected.len() > 32 {
    return Err(CryptoError::BadMac);
  }
  let full = hmac_sha256(key, data);
  if bool::from(full[..expected.len()].ct_eq(expected)) {
    Ok(())
  } else {
    Err(CryptoError::BadMac)
  }
}

pub fn derive_secrets<const N: usize>(input: &[u8], salt: &[u8], info: &[u8]) -> [[u8; 32]; N] {
  let hk = Hkdf::<Sha256>::new(Some(salt), input);
  let mut okm = Zeroizing::new(vec![0u8; 32 * N]);
  hk.expand(info, &mut okm[..]).expect("N * 32 <= 255 * 32");
  let mut out = [[0u8; 32]; N];
  for (i, chunk) in out.iter_mut().enumerate() {
    chunk.copy_from_slice(&okm[i * 32..(i + 1) * 32]);
  }
  out
}

pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
  let enc = Aes256CbcEnc::new_from_slices(key, iv).map_err(|_| CryptoError::InvalidKeyOrIv)?;
  Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
  let dec = Aes256CbcDec::new_from_slices(key, iv).map_err(|_| CryptoError::InvalidKeyOrIv)?;
  dec
    .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
    .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
      .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
      .collect()
  }

  fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
  }

  #[test]
  fn hkdf_rfc5869_test_case_1() {
    let ikm = [0x0bu8; 22];
    let salt = unhex("000102030405060708090a0b0c");
    let info = unhex("f0f1f2f3f4f5f6f7f8f9");
    let out = derive_secrets::<2>(&ikm, &salt, &info);
    let flat: Vec<u8> = out.iter().flatten().copied().collect();
    assert_eq!(
      hex(&flat[..42]),
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
  }

  #[test]
  fn hmac_rfc4231_test_case_1() {
    let mac = hmac_sha256(&[0x0bu8; 20], b"Hi There");
    assert_eq!(
      hex(&mac),
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
  }

  #[test]
  fn verify_mac_truncated() {
    let mac = hmac_sha256(b"k", b"data");
    assert!(verify_mac(b"k", b"data", &mac[..8]).is_ok());
    let mut bad = mac[..8].to_vec();
    bad[0] ^= 1;
    assert!(matches!(
      verify_mac(b"k", b"data", &bad),
      Err(CryptoError::BadMac)
    ));
    assert!(verify_mac(b"k", b"data", &[]).is_err());
  }

  #[test]
  fn aes256_cbc_nist_sp800_38a_first_block() {
    let key = unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let iv = unhex("000102030405060708090a0b0c0d0e0f");
    let pt = unhex("6bc1bee22e409f96e93d7e117393172a");
    let ct = aes_cbc_encrypt(&key, &iv, &pt).unwrap();
    assert_eq!(ct.len(), 32);
    assert_eq!(hex(&ct[..16]), "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
    assert_eq!(aes_cbc_decrypt(&key, &iv, &ct).unwrap(), pt);
  }

  #[test]
  fn aes_cbc_roundtrip_various_lengths() {
    let key = [7u8; 32];
    let iv = [9u8; 16];
    for len in [0usize, 1, 15, 16, 17, 100] {
      let pt = vec![0xA5u8; len];
      let ct = aes_cbc_encrypt(&key, &iv, &pt).unwrap();
      assert_eq!(aes_cbc_decrypt(&key, &iv, &ct).unwrap(), pt);
    }
  }

  #[test]
  fn aes_cbc_rejects_bad_inputs() {
    assert!(aes_cbc_encrypt(&[0u8; 31], &[0u8; 16], b"x").is_err());
    assert!(aes_cbc_encrypt(&[0u8; 32], &[0u8; 15], b"x").is_err());

    assert!(aes_cbc_decrypt(&[0u8; 32], &[0u8; 16], &[0u8; 15]).is_err());
  }
}
