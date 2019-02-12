// sign.rs

// *************************************************************************
// * Copyright (C) 2019 Daniel Mueller (deso@posteo.net)                   *
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

use ssh_agent::proto::key_type::KeyTypeEnum;
use ssh_agent::proto::private_key::PrivateKey;
use ssh_agent::proto::signature::Signature;

use ring::signature::Ed25519KeyPair;

use untrusted::Input;

use crate::error::Result;
use crate::error::WithCtx;


pub trait Signer {
  fn sign(&self, data: &[u8]) -> Result<Signature>;
}

impl Signer for PrivateKey {
  /// Sign data using a private key.
  fn sign(&self, data: &[u8]) -> Result<Signature> {
    // We use the ring crate for signing. In order to sign something we
    // first need to convert our private key into a key pair that the
    // crate can work with.
    let key_pair = match self {
      PrivateKey::Dss{..} |
      PrivateKey::EcDsa{..} |
      PrivateKey::Rsa{..} => unimplemented!(),
      PrivateKey::Ed25519(key) => {
        let public = Input::from(&key.enc_a);
        let seed = Input::from(&key.k_enc_a);

        Ed25519KeyPair::from_seed_and_public_key(seed, public)
          .ctx(|| "failed to create ed25519 key pair")?
      },
    };

    let sig = Signature {
      algorithm: self.key_type(),
      blob: key_pair
        .sign(&data)
        .as_ref()
        .to_vec(),
    };
    Ok(sig)
  }
}
