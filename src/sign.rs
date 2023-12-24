// sign.rs

// *************************************************************************
// * Copyright (C) 2019-2023 Daniel Mueller (deso@posteo.net)              *
// *                                                                       *
// * This program is free software: you can redistribute it and/or modify  *
// * it under the terms of the GNU General Public License as published by  *
// * the Free Software Foundation, either version 3 of the License, or     *
// * (at your option) any later version.                                   *
// *                                                                       *
// * This program is distributed in the hope that it will be useful,       *
// * but WITHOUT ANY WARRANTY; without even the implied warranty of        *
// * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
// * GNU General Public License for more details.                          *
// *                                                                       *
// * You should have received a copy of the GNU General Public License     *
// * along with this program.  If not, see <http://www.gnu.org/licenses/>. *
// *************************************************************************

use anyhow::Context as _;
use anyhow::Result;

use openssl::bn::BigNum;

use ssh_agent_lib::proto::key_type::KeyTypeEnum;
use ssh_agent_lib::proto::private_key::Ed25519PrivateKey;
use ssh_agent_lib::proto::private_key::PrivateKey;
use ssh_agent_lib::proto::private_key::RsaPrivateKey;
use ssh_agent_lib::proto::signature::Signature;
use ssh_agent_lib::proto::signature::RSA_SHA2_256;
use ssh_agent_lib::proto::signature::RSA_SHA2_512;

use ring::rand::SystemRandom;
use ring::rsa::KeyPairComponents as RsaKeyPairComponents;
use ring::signature::Ed25519KeyPair;
use ring::signature::RsaKeyPair;
use ring::signature::RsaPublicKeyComponents;
use ring::signature::RSA_PKCS1_SHA256;
use ring::signature::RSA_PKCS1_SHA512;


/// Sign a given blob of data with the given ed25519 private key.
fn sign_ed25519(key: &Ed25519PrivateKey, data: &[u8]) -> Result<Vec<u8>> {
  let public = &key.enc_a;
  let seed = &key.k_enc_a;

  let key_pair = Ed25519KeyPair::from_seed_and_public_key(seed, public)
    .with_context(|| "failed to create ed25519 key pair")?;

  let sig = key_pair.sign(data).as_ref().to_vec();
  Ok(sig)
}

/// Sign a given blob of data with the given RSA private key.
fn sign_rsa(key: &RsaPrivateKey, flags: u32, data: &[u8]) -> Result<Vec<u8>> {
  let padding_alg = if flags & RSA_SHA2_512 != 0 {
    &RSA_PKCS1_SHA512
  } else if flags & RSA_SHA2_256 != 0 {
    &RSA_PKCS1_SHA256
  } else {
    unimplemented!()
  };

  let RsaPrivateKey {
    n,
    e,
    d,
    iqmp,
    p,
    q,
  } = key;

  let one = BigNum::from_u32(1)?;
  let n = BigNum::from_slice(n)?;
  let e = BigNum::from_slice(e)?;
  let d = BigNum::from_slice(d)?;
  let p = BigNum::from_slice(p)?;
  let q = BigNum::from_slice(q)?;
  let q_inv = BigNum::from_slice(iqmp)?;
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

impl Signer for PrivateKey {
  /// Sign data using a private key.
  fn sign(&self, flags: u32, data: &[u8]) -> Result<Signature> {
    // We use the ring crate for signing. In order to sign something we
    // first need to convert our private key into a key pair that the
    // crate can work with.
    let (alg, sig) = match self {
      PrivateKey::Dss { .. }
      | PrivateKey::EcDsa { .. }
      | PrivateKey::SkEcDsa { .. }
      | PrivateKey::SkEd25519 { .. } => unimplemented!(),
      PrivateKey::Rsa(key) => {
        let algorithm = if flags & RSA_SHA2_512 != 0 {
          "rsa-sha2-512"
        } else if flags & RSA_SHA2_256 != 0 {
          "rsa-sha2-256"
        } else {
          "ssh-rsa"
        };
        let signature = sign_rsa(key, flags, data).context("failed to sign request using RSA")?;

        (algorithm.to_string(), signature)
      },
      PrivateKey::Ed25519(key) => (self.key_type(), sign_ed25519(key, data)?),
    };

    let sig = Signature {
      algorithm: alg,
      blob: sig,
    };
    Ok(sig)
  }
}


#[cfg(test)]
mod test {
  use super::*;

  use ssh_agent_lib::proto::PublicKey;

  use ring::signature::RSA_PKCS1_2048_8192_SHA256;

  use crate::files::load_public_key;
  use crate::files::test::load_unencrypted_private_key;
  use crate::keys::FromPem;


  /// Test the signing of data with an ed25519 private key.
  #[test]
  fn sign_ed25519() -> Result<()> {
    let privkey = load_unencrypted_private_key("tests/valid_keys/ed25519")?;
    let privkey = PrivateKey::from_pem(privkey)?;

    let data = "test-data";
    let _ = privkey.sign(0, data.as_bytes())?;
    Ok(())
  }


  /// Test the signing of data with an RSA private key.
  #[test]
  fn sign_rsa() -> Result<()> {
    let privkey = load_unencrypted_private_key("tests/valid_keys/rsa2048")?;
    let privkey = PrivateKey::from_pem(privkey)?;

    let data = "test-data";
    let sig = privkey.sign(RSA_SHA2_256, data.as_bytes())?;

    let pubkey = load_public_key("tests/valid_keys/rsa2048.pub")?;
    let pubkey = PublicKey::from_pem(pubkey)?;
    let pubkey = match &pubkey {
      PublicKey::Rsa(pubkey) => RsaPublicKeyComponents {
        // Remove leading zero. Yeah...
        n: &pubkey.n[1..],
        e: &pubkey.e,
      },
      _ => unreachable!(),
    };
    let () = pubkey.verify(&RSA_PKCS1_2048_8192_SHA256, data.as_bytes(), &sig.blob)?;

    Ok(())
  }
}
