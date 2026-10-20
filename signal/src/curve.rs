use crate::utils::{
  base_mult_scalar, challenge, check_len, clamp_priv_key, get_basepoint, nonce_rnd,
  pubkey_montgomery_to_edwards, scrub_pub_key,
};
use curve25519_dalek::{MontgomeryPoint, Scalar};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;

pub fn create_key_pair_int(mut priv_key: [u8; 32]) -> ([u8; 33], [u8; 32]) {
  clamp_priv_key(&mut priv_key);
  let scalar = Scalar::from_bytes_mod_order(priv_key);
  let pub_key_raw = (scalar * MontgomeryPoint(get_basepoint())).to_bytes();
  let mut pub_key = [0u8; 33];
  pub_key[0] = 5; // version byte
  pub_key[1..33].copy_from_slice(&pub_key_raw);
  (pub_key, priv_key)
}

pub fn generate_key_pair_int() -> ([u8; 33], [u8; 32]) {
  let mut rng = OsRng;
  let mut priv_key = [0u8; 32];
  rng.fill_bytes(&mut priv_key);
  create_key_pair_int(priv_key)
}
pub fn generate_key_pairs_int(count: usize) -> Vec<([u8; 33], [u8; 32])> {
  let mut key_pairs = Vec::with_capacity(count);
  for _ in 0..count {
    key_pairs.push(generate_key_pair_int());
  }
  key_pairs
}

pub fn shared_secret_int(
  pub_key_bytes: &[u8],
  priv_key: [u8; 32],
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
  if pub_key_bytes.len() != 32 && pub_key_bytes.len() != 33 {
    return Err(Box::<dyn std::error::Error>::from(
      "Invalid public key length",
    ));
  }
  let pub_key_32: [u8; 32] = if pub_key_bytes.len() == 33 {
    if pub_key_bytes[0] != 5 {
      return Err(Box::<dyn std::error::Error>::from(
        "Invalid public key version byte",
      ));
    }
    pub_key_bytes[1..33]
      .try_into()
      .map_err(|_| Box::<dyn std::error::Error>::from("Invalid public key"))?
  } else {
    pub_key_bytes
      .try_into()
      .map_err(|_| Box::<dyn std::error::Error>::from("Invalid public key"))?
  };
  let mut clamped_priv = priv_key;
  clamp_priv_key(&mut clamped_priv);
  let scalar = Scalar::from_bytes_mod_order(clamped_priv);
  let shared = (scalar * MontgomeryPoint(pub_key_32)).to_bytes();

  Ok(shared)
}

pub fn verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, String> {
  let pub_key = scrub_pub_key(&public_key);
  check_len(signature, 64, "signature")?;
  let pk: [u8; 32] = pub_key?.try_into().unwrap();
  let sig: [u8; 64] = signature[..64].try_into().unwrap();

  // Convert the public key from Montgomery to Edwards form.
  let sign_bit = sig[63] & 128;
  let a_bytes = match pubkey_montgomery_to_edwards(&pk, sign_bit >> 7) {
    Some(p) => p.compress().to_bytes(),
    None => return Ok(false),
  };

  // Clear the sign bit from the signature for verification.
  let mut sig_clean = sig;
  sig_clean[63] &= 127;

  let signature = Signature::from_bytes(&sig_clean);
  let vk = match VerifyingKey::from_bytes(&a_bytes) {
    Ok(v) => v,
    Err(_) => return Ok(false),
  };
  // verify_strict, not verify: the cofactorless equation accepts low-order
  // keys and low-order R, which lets a forged signature pass. A bundle-supplied
  // identity key must never be able to authenticate that way.
  Ok(vk.verify_strict(msg, &signature).is_ok())
}
pub fn sign(secret_key: &[u8], msg: &[u8], opt_random: Option<&[u8]>) -> Result<[u8; 64], String> {
  check_len(secret_key, 32, "secret key")?;
  // The nonce must come from a CSPRNG. Deriving it as SHA512(sk||m) made it
  // deterministic, so two signatures over chosen messages recovered the
  // identity key (hidden-number-problem lattice attack). rnd stays
  // injectable so the libsignal-parity oracle and known-answer vectors can
  // still pin a fixed nonce.
  let mut generated = [0u8; 64];
  let rnd: [u8; 64] = match opt_random {
    Some(r) => {
      check_len(r, 64, "random data")?;
      r[..64].try_into().unwrap()
    }
    None => {
      OsRng.fill_bytes(&mut generated);
      generated
    }
  };
  let sk: [u8; 32] = secret_key[..32].try_into().unwrap();
  let sig = sign_internal(&sk, msg, &rnd);
  Ok(sig)
}

fn sign_internal(sk_raw: &[u8; 32], msg: &[u8], rnd: &[u8; 64]) -> [u8; 64] {
  let mut sk = *sk_raw;
  let sk = clamp_priv_key(&mut sk);
  let a = Scalar::from_bytes_mod_order(sk);
  // A = a*B (Edwards), packed. signBit = A[31] & 128.
  let a_bytes = base_mult_scalar(&a);
  // Get the sign bit from the public key.
  let sign_bit = a_bytes[31] & 128;

  // r (nonce) = SHA512(0xfe 0xff*31 || sk || m || rnd) mod L
  let r = nonce_rnd(&sk, msg, rnd);

  // R = r*B, packed
  let r_bytes = base_mult_scalar(&r);

  // h = SHA512(R || A || msg)
  let h = challenge(&r_bytes, &a_bytes, msg);

  // S = r + h*a mod L
  let s = r + h * a;
  let s_bytes = s.to_bytes();

  let mut sig = [0u8; 64];
  sig[..32].copy_from_slice(&r_bytes);
  sig[32..64].copy_from_slice(&s_bytes);
  // Set the sign bit in the signature.
  sig[63] |= sign_bit;
  sig
}

pub fn scalar_multiply(secret_key: &[u8], public_key: &[u8]) -> Result<[u8; 32], String> {
  let sk32: [u8; 32] = scrub_pub_key(secret_key)?;
  let pk32 = scrub_pub_key(public_key)?;
  let bytes = MontgomeryPoint(pk32).mul_clamped(sk32).to_bytes();
  // Contributory behaviour. A small-order peer key makes the output all-zero
  // and discards this side's private key entirely, which would let anyone
  // derive the same root key and chain key from public data alone. RFC 7748
  // §6.1 allows this abort and names the OR-fold as the constant-time form;
  // RFC 8418 §2 requires it for X25519. curve25519-dalek does not do it for
  // us — MontgomeryPoint::IDENTITY exists so the caller can.
  let mut acc = 0u8;
  for b in bytes.iter() {
    acc |= *b;
  }
  if acc == 0 {
    return Err("non-contributory X25519 shared secret: peer key is small-order".to_string());
  }
  Ok(bytes)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn hex_to_bytes(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
      out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
  }

  fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
  }

  #[test]
  fn test_sign_verify_roundtrip() {
    let sk = [0xABu8; 32];
    let msg = b"hello signal";
    let sig = sign(&sk, msg, None).unwrap();
    assert_eq!(sig.len(), 64);
    let (pk, _) = create_key_pair_int(sk);
    assert!(verify(&pk, msg, &sig).unwrap());
  }

  #[test]
  fn test_sign_verify_roundtrip_rnd() {
    let sk = [0xCDu8; 32];
    let rnd = [0xEFu8; 64];
    let msg = b"message with random";
    let sig = sign(&sk, msg, Some(&rnd)).unwrap();
    let (pk, _) = create_key_pair_int(sk);
    assert!(verify(&pk, msg, &sig).unwrap());
  }

  #[test]
  fn test_verify_rejects_tampered() {
    // [0x01; 32] is a degenerate seed (one bit per byte) and is now
    // tampering, not about the seed.
    let sk = [0x37u8; 32];
    let msg = b"integrity check";
    let sig = sign(&sk, msg, None).unwrap();
    let (pk, _) = create_key_pair_int(sk);
    assert!(!verify(&pk, b"tampered", &sig).unwrap());
  }

  #[test]
  fn test_generate_keypair_roundtrip() {
    let seed = [0x33u8; 32];
    let (pk, sk) = create_key_pair_int(seed);
    // dont forget to scrub the public key, since it may be 33 bytes with a version byte
    let pubkey = scrub_pub_key(&pk).unwrap();
    assert_eq!(pubkey.len(), 32);
    assert_eq!(sk.len(), 32);
    // deterministik
    let (pk2, sk2) = create_key_pair_int(seed);
    assert_eq!(pk, pk2);
    assert_eq!(sk, sk2);
  }

  #[test]
  fn test_scalar_multiply_dh_agreement() {
    let (alice_pk, alice_sk) = create_key_pair_int([0xAAu8; 32]);
    let (bob_pk, bob_sk) = create_key_pair_int([0xBBu8; 32]);
    let s_alice = scalar_multiply(&alice_sk, &bob_pk).unwrap();
    let s_bob = scalar_multiply(&bob_sk, &alice_pk).unwrap();
    assert_eq!(s_alice, s_bob);
    assert_ne!(s_alice, [0u8; 32]);
  }

  #[test]
  fn test_bad_lengths() {
    assert!(sign(&[0u8; 31], b"x", None).is_err());
    assert!(sign(&[0u8; 32], b"x", Some(&[0u8; 63])).is_err());
    assert!(verify(&[0u8; 31], b"x", &[0u8; 64]).is_err());
    assert!(verify(&[0u8; 32], b"x", &[0u8; 63]).is_err());
    assert!(scalar_multiply(&[0u8; 31], &[0u8; 32]).is_err());
    assert!(scalar_multiply(&[0u8; 32], &[0u8; 31]).is_err());
  }

  #[test]
  fn test_verify_rejects_low_order_public_key() {
    // u = 0 is a low-order Montgomery point; the Edwards point it maps to has
    // order 2. The cofactorless equation is satisfiable there with a
    // signature forged without the real key, so the signed-prekey check at
    // x3dh would accept any bundle naming this public key.
    let a_point = pubkey_montgomery_to_edwards(&[0u8; 32], 0).unwrap();
    let a_bytes = a_point.compress().to_bytes();
    assert!(
      a_point.is_small_order(),
      "u=0 must map to a small-order point"
    );

    // R = A with S = 0 satisfies [S]B == R + [h]A whenever h is odd.
    let mut msg: Vec<u8> = Vec::new();
    let mut found = false;
    for i in 0..64u8 {
      msg = [b"forged prekey bundle".as_slice(), &[i]].concat();
      if challenge(&a_bytes, &a_bytes, &msg).to_bytes()[0] & 1 == 1 {
        found = true;
        break;
      }
    }
    assert!(found, "expected an odd challenge for some probe message");

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&a_bytes);
    assert!(
      !verify(&[0u8; 32], &msg, &sig).unwrap(),
      "a low-order public key must never accept a forged signature"
    );
  }

  #[test]
  fn test_sign_nonce_is_random_without_rnd() {
    // RFC 8032 hashes a CSPRNG 32-byte prefix precisely so that two
    // signatures over chosen messages cannot recover the identity key via a
    // hidden-number-problem lattice attack. rnd = None must therefore not
    // fall back to the deterministic SHA512(sk||m) nonce.
    let sk = [0x77u8; 32];
    let msg = b"deterministic nonce leak";
    let s1 = sign(&sk, msg, None).unwrap();
    let s2 = sign(&sk, msg, None).unwrap();
    assert_ne!(s1, s2, "rnd = None must not derive a deterministic nonce");

    let rnd = [0xEFu8; 64];
    let a = sign(&sk, msg, Some(&rnd)).unwrap();
    let b = sign(&sk, msg, Some(&rnd)).unwrap();
    assert_eq!(
      a, b,
      "an explicit rnd must still reproduce a fixed signature"
    );
  }

  /// Every one of these forces X25519(sk, u) to all-zero, discarding the local
  /// private key's contribution entirely (cofactor 8). curve25519-js@0.0.4
  /// returns 0000..00 for each and raises nothing; RFC 7748 §6.1 permits
  /// aborting, RFC 8418 §2 requires it.
  ///
  /// Seven distinct field values, each in both of its wire spellings —
  /// fourteen byte strings. The two per value are related only by bit 255,
  /// which RFC 7748's decodeUCoordinate *masks* rather than reducing mod p, so
  /// they decode to the same coordinate. Testing both spellings pins that
  /// masking behaviour; a future change to how the coordinate is decoded would
  /// otherwise only show up on one of the two.
  ///
  /// The values are the complete set of u in F_p whose point has order
  /// dividing 8, which is what the ladder needs since a clamped scalar is
  /// always a multiple of 8: the order-2 point u = 0, the two order-4 points
  /// u in {1, p-1}, and the two order-8 points. u = p and u = p + 1 are not
  /// canonical encodings of anything; they are extra byte strings a peer can
  /// send that decode onto 0 and 1.
  const LOW_ORDER_POINTS: [&str; 14] = [
    // order 2
    "0000000000000000000000000000000000000000000000000000000000000000", // u = 0
    "0000000000000000000000000000000000000000000000000000000000000080", // u = 0, bit 255 set
    // order 4
    "0100000000000000000000000000000000000000000000000000000000000000", // u = 1
    "0100000000000000000000000000000000000000000000000000000000000080", // u = 1, bit 255 set
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // u = p - 1
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // u = p - 1, bit 255 set
    // order 8
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7", // ... bit 255 set
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880", // ... bit 255 set
    // non-canonical encodings, folding onto u = 0 and u = 1
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // u = p
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // u = p, bit 255 set
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // u = p + 1
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // u = p + 1, bit 255 set
  ];

  #[test]
  fn a_low_order_peer_key_is_rejected() {
    let sk = [7u8; 32];
    for p in LOW_ORDER_POINTS.iter() {
      let u = hex_to_bytes(p);
      // Match the message, not just is_err(): check_len would satisfy a
      // bare is_err() too, which would leave this test passing if the
      // contributory check were ever deleted.
      match scalar_multiply(&sk, &u) {
        Ok(_) => panic!("low-order point {} produced an accepted shared secret", p),
        Err(e) => assert!(
          e.contains("non-contributory"),
          "low-order point {} failed for the wrong reason: {}",
          p,
          e
        ),
      }
    }
  }

  #[test]
  fn a_valid_peer_key_still_computes() {
    let (pk_a, sk_a) = create_key_pair_int([3u8; 32]);
    let (pk_b, sk_b) = create_key_pair_int([9u8; 32]);
    assert_ne!(scalar_multiply(&sk_a, &pk_b).unwrap(), [0u8; 32]);
    assert_ne!(scalar_multiply(&sk_b, &pk_a).unwrap(), [0u8; 32]);
  }

  #[test]
  fn test_xeddsa_known_answer() {
    // Vektor tetap dari curve25519-js (implementasi yang dipakai libsignal):
    // sign(alice_sk, b"known answer test", rnd = 0xEF*64). Dihasilkan dari
    // curve25519-js, bukan dari kode ini — tetap vektor eksternal, kini
    // melalui jalur rnd karena nonce tanpa rnd sudah diacak.
    let sk = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let expected_sig = "7b5664ddd65206b6e4f72926c4b8095e5639f2d706491e59dc8a9948ad81c67ccb5e9ed8e285b8136cea2a015639be2bb89042ec34816aaa7becfca726415981";
    let msg = b"known answer test";
    let sig = sign(&sk, msg, Some(&[0xEFu8; 64])).unwrap();
    assert_eq!(bytes_to_hex(&sig), expected_sig);
    let (pk, _) = create_key_pair_int(sk);
    assert!(verify(&pk, msg, &sig).unwrap());
  }
}
