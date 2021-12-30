// sign.rs

// *************************************************************************
// * Copyright (C) 2019-2021 Daniel Mueller (deso@posteo.net)              *
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

use ssh_agent::proto::key_type::KeyTypeEnum;
use ssh_agent::proto::private_key::Ed25519PrivateKey;
use ssh_agent::proto::private_key::PrivateKey;
use ssh_agent::proto::signature::Signature;

use ring::signature::Ed25519KeyPair;


/// Sign a given blob of data with the given ed25519 private key.
fn sign_ed25519(key: &Ed25519PrivateKey, data: &[u8]) -> Result<Vec<u8>> {
  let public = &key.enc_a;
  let seed = &key.k_enc_a;

  let key_pair = Ed25519KeyPair::from_seed_and_public_key(seed, public)
    .with_context(|| "failed to create ed25519 key pair")?;

  let sig = key_pair
    .sign(data)
    .as_ref()
    .to_vec();
  Ok(sig)
}


pub trait Signer {
  fn sign(&self, data: &[u8]) -> Result<Signature>;
}

impl Signer for PrivateKey {
  /// Sign data using a private key.
  fn sign(&self, data: &[u8]) -> Result<Signature> {
    // We use the ring crate for signing. In order to sign something we
    // first need to convert our private key into a key pair that the
    // crate can work with.
    let sig = match self {
      PrivateKey::Dss{..} |
      PrivateKey::EcDsa{..} |
      PrivateKey::Rsa{..} => unimplemented!(),
      PrivateKey::Ed25519(key) => sign_ed25519(key, data)?,
    };

    let sig = Signature {
      algorithm: self.key_type(),
      blob: sig,
    };
    Ok(sig)
  }
}


#[cfg(test)]
mod test {
  use super::*;

  use crate::files::test::load_unencrypted_private_key;
  use crate::keys::FromPem;


  /// Test the signing of data with an ed25519 private key.
  #[test]
  fn sign_ed25519() -> Result<()> {
    let privkey = load_unencrypted_private_key("tests/valid_keys/ed25519")?;
    let privkey = PrivateKey::from_pem(privkey)?;

    let data = "test-data";
    let _ = privkey.sign(data.as_bytes())?;
    Ok(())
  }
}
