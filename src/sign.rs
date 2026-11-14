// Copyright (C) 2019-2026 Daniel Mueller <deso@posteo.net>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Context as _;
use anyhow::Result;
use anyhow::anyhow;

use openssl::bn::BigNum;

use ssh_agent_lib::proto::signature::RSA_SHA2_256;
use ssh_agent_lib::proto::signature::RSA_SHA2_512;

use ssh_key::Algorithm;
use ssh_key::HashAlg;
use ssh_key::Signature;
use ssh_key::private::Ed25519Keypair;
use ssh_key::private::KeypairData;
use ssh_key::private::RsaKeypair;

use ring::rand::SystemRandom;
use ring::rsa::KeyPairComponents as RsaKeyPairComponents;
use ring::signature::Ed25519KeyPair;
use ring::signature::RSA_PKCS1_SHA256;
use ring::signature::RSA_PKCS1_SHA512;
use ring::signature::RsaKeyPair;
use ring::signature::RsaPublicKeyComponents;


/// Sign a given blob of data with the given ed25519 private key.
fn sign_ed25519(key: &Ed25519Keypair, data: &[u8]) -> Result<Vec<u8>> {
  let seed = key.private.as_ref();
  let public = key.public.as_ref();

  let key_pair = Ed25519KeyPair::from_seed_and_public_key(seed, public)
    .with_context(|| "failed to create ed25519 key pair")?;

  let sig = key_pair.sign(data).as_ref().to_vec();
  Ok(sig)
}

/// Sign a given blob of data with the given RSA private key.
fn sign_rsa(key: &RsaKeypair, flags: u32, data: &[u8]) -> Result<Vec<u8>> {
  let padding_alg = if flags & RSA_SHA2_512 != 0 {
    &RSA_PKCS1_SHA512
  } else if flags & RSA_SHA2_256 != 0 {
    &RSA_PKCS1_SHA256
  } else {
    unimplemented!()
  };

  let one = BigNum::from_u32(1)?;
  let n = BigNum::from_slice(key.public.n.as_bytes())?;
  let e = BigNum::from_slice(key.public.e.as_bytes())?;
  let d = BigNum::from_slice(key.private.d.as_bytes())?;
  let p = BigNum::from_slice(key.private.p.as_bytes())?;
  let q = BigNum::from_slice(key.private.q.as_bytes())?;
  let q_inv = BigNum::from_slice(key.private.iqmp.as_bytes())?;
  let d_p = &d % &(&p - &one);
  let d_q = &d % &(&q - &one);

  let input = RsaKeyPairComponents {
    public_key: RsaPublicKeyComponents {
      n: n.to_vec(),
      e: e.to_vec(),
    },
    d: d.to_vec(),
    p: p.to_vec(),
    q: q.to_vec(),
    dP: d_p.to_vec(),
    dQ: d_q.to_vec(),
    qInv: q_inv.to_vec(),
  };

  let key_pair = RsaKeyPair::from_components(&input).context("failed to create RSA key pair")?;
  let mut sig = vec![0u8; key_pair.public().modulus_len()];

  let rng = SystemRandom::new();
  let () = key_pair
    .sign(padding_alg, &rng, data, &mut sig)
    .context("failed to sign data")?;
  Ok(sig)
}


pub trait Signer {
  fn sign(&self, flags: u32, data: &[u8]) -> Result<Signature>;
}

impl Signer for KeypairData {
  /// Sign data using a private key.
  fn sign(&self, flags: u32, data: &[u8]) -> Result<Signature> {
    // We use the ring crate for signing. In order to sign something we
    // first need to convert our private key into a key pair that the
    // crate can work with.
    let sig = match self {
      Self::Rsa(key) => {
        let algorithm = if flags & RSA_SHA2_512 != 0 {
          Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
          }
        } else if flags & RSA_SHA2_256 != 0 {
          Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
          }
        } else {
          Algorithm::Rsa { hash: None }
        };
        let signature = sign_rsa(key, flags, data).context("failed to sign request using RSA")?;

        Signature::new(algorithm, signature).context("failed to create signature")?
      },
      Self::Ed25519(key) => {
        let signature = sign_ed25519(key, data)?;

        Signature::new(Algorithm::Ed25519, signature).context("failed to create signature")?
      },
      _ => {
        let result = Err(anyhow!("failed to sign data"));
        if let Ok(alg) = self.algorithm() {
          return result.with_context(|| format!("{alg} keys are unsupported"))
        } else {
          return result.context("encountered unsupported key type")
        }
      },
    };

    Ok(sig)
  }
}


#[cfg(test)]
mod test {
  use super::*;

  use ssh_agent_lib::proto::PublicKey;

  use ssh_key::PrivateKey;

  use ring::signature::RSA_PKCS1_2048_8192_SHA256;

  use crate::files::load_public_key;
  use crate::files::test::load_unencrypted_private_key;
  use crate::keys::AuthorizedKey;
  use crate::keys::FromPem;


  /// Test the signing of data with an ed25519 private key.
  #[test]
  fn sign_ed25519() -> Result<()> {
    let privkey = load_unencrypted_private_key("tests/valid_keys/ed25519")?;
    let privkey = PrivateKey::from_pem(privkey)?;

    let data = "test-data";
    let _sig = privkey.key_data().sign(0, data.as_bytes())?;
    Ok(())
  }


  /// Test the signing of data with an RSA private key.
  #[expect(clippy::indexing_slicing)]
  #[test]
  fn sign_rsa() -> Result<()> {
    let privkey = load_unencrypted_private_key("tests/valid_keys/rsa2048")?;
    let privkey = PrivateKey::from_pem(privkey)?;

    let data = "test-data";
    let sig = privkey.key_data().sign(RSA_SHA2_256, data.as_bytes())?;

    let pubkey = load_public_key("tests/valid_keys/rsa2048.pub")?;
    let pubkey = AuthorizedKey::from_pem(pubkey)?.key;
    let pubkey = match &pubkey {
      PublicKey::Rsa(pubkey) => RsaPublicKeyComponents {
        // Remove leading zero. Yeah...
        n: &pubkey.n[1..],
        e: &pubkey.e,
      },
      _ => unreachable!(),
    };
    let () = pubkey.verify(&RSA_PKCS1_2048_8192_SHA256, data.as_bytes(), sig.as_bytes())?;

    Ok(())
  }
}
