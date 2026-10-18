use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, EdwardsPoint, MontgomeryPoint, Scalar};
use sha2::{Digest, Sha512};

const BASEPOINT: [u8; 32] = {
  let mut base = [0u8; 32];
  base[0] = 9;
  base
};

pub fn get_basepoint() -> [u8; 32] {
  BASEPOINT
}
pub fn nonce_rnd(sk: &[u8; 32], msg: &[u8], rnd: &[u8]) -> Scalar {
  let mut h = Sha512::new();
  h.update([0xfeu8]);
  h.update([0xffu8; 31]);
  h.update(sk);
  h.update(msg);
  h.update(rnd);
  let digest: [u8; 64] = h.finalize().into();
  Scalar::from_bytes_mod_order_wide(&digest)
}
pub fn challenge(r: &[u8; 32], a: &[u8; 32], msg: &[u8]) -> Scalar {
  let mut h = Sha512::new();
  h.update(r);
  h.update(a);
  h.update(msg);
  let digest: [u8; 64] = h.finalize().into();
  Scalar::from_bytes_mod_order_wide(&digest)
}

#[inline(always)]
pub fn clamp_priv_key(priv_key: &mut [u8; 32]) -> [u8; 32] {
  priv_key[0] &= 248;
  priv_key[31] &= 127;
  priv_key[31] |= 64;
  *priv_key
}
pub fn unclamp_priv_key(priv_key: &mut [u8; 32]) -> [u8; 32] {
  priv_key[0] |= 7;
  priv_key[31] &= 127;
  priv_key[31] |= 64;
  *priv_key
}

pub fn scrub_pub_key(pub_key: &[u8]) -> Result<[u8; 32], &'static str> {
  let slice = match pub_key {
    key if key.len() == 32 => key,
    [5, key @ ..] if key.len() == 32 => {
      return Ok(key.try_into().unwrap());
    }
    _ => return Err("Invalid public key length or version byte"),
  };

  Ok(slice.try_into().unwrap())
}
pub fn check_len(key: &[u8], expected_len: usize, name: &'static str) -> Result<(), String> {
  let len = key.len();

  if len != expected_len {
    return Err(format!(
      "Invalid length for {name}: expected {expected_len}, got {len}"
    ));
  }

  Ok(())
}
pub fn pubkey_montgomery_to_edwards(pk: &[u8; 32], sign_bit: u8) -> Option<EdwardsPoint> {
  let mp = MontgomeryPoint(*pk);
  mp.to_edwards(sign_bit)
}
pub fn base_mult_scalar(a: &Scalar) -> [u8; 32] {
  let p = ED25519_BASEPOINT_POINT * a;
  p.compress().to_bytes()
}
