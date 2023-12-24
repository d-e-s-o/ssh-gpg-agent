// keys.rs

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

use std::ops::DerefMut;
use std::str::from_utf8 as str_from_utf8;

use anyhow::anyhow;
use anyhow::Context as _;
use anyhow::Result;

use ssh_agent_lib::proto::private_key::Ed25519PrivateKey;
use ssh_agent_lib::proto::private_key::PrivateKey;
use ssh_agent_lib::proto::private_key::RsaPrivateKey;
use ssh_agent_lib::proto::public_key::Ed25519PublicKey;
use ssh_agent_lib::proto::public_key::PublicKey;
use ssh_agent_lib::proto::public_key::RsaPublicKey;

use ssh_keys::openssh::parse_private_key;
use ssh_keys::openssh::parse_public_key;
use ssh_keys::PrivateKey as SshPrivateKey;
use ssh_keys::PublicKey as SshPublicKey;

use crate::files::PemPrivateKey;
use crate::files::PemPublicKey;


/// Convert an ssh_keys PrivateKey into an ssh_agent PrivateKey.
fn convert_pub(key: SshPublicKey) -> PublicKey {
  match key {
    SshPublicKey::Rsa { exponent, modulus } => {
      let rsa = RsaPublicKey {
        e: exponent,
        n: modulus,
      };
      PublicKey::Rsa(rsa)
    },
    SshPublicKey::Ed25519(data) => {
      let ed25519 = Ed25519PublicKey {
        enc_a: data.to_vec(),
      };
      PublicKey::Ed25519(ed25519)
    },
  }
}


/// Convert an ssh_keys PrivateKey into an ssh_agent PrivateKey.
fn convert_priv(key: SshPrivateKey) -> PrivateKey {
  match key {
    SshPrivateKey::Rsa {
      n,
      e,
      d,
      iqmp,
      p,
      q,
    } => {
      let rsa = RsaPrivateKey {
        n,
        e,
        d,
        iqmp,
        p,
        q,
      };
      PrivateKey::Rsa(rsa)
    },
    SshPrivateKey::Ed25519(data) => {
      let mut key = data.to_vec();
      let public = key.split_off(32);
      let seed = key;

      let ed25519 = Ed25519PrivateKey {
        enc_a: public,
        k_enc_a: seed,
      };
      PrivateKey::Ed25519(ed25519)
    },
  }
}


/// A trait for construction from PEM encoded data.
pub trait FromPem<K>
where
  Self: Sized,
{
  fn from_pem(pem_key: K) -> Result<Self>;
}

impl FromPem<PemPrivateKey> for PrivateKey {
  fn from_pem(pem_key: PemPrivateKey) -> Result<Self> {
    let data = Vec::<_>::from(pem_key);
    let string = str_from_utf8(&data).with_context(|| "failed to convert private key to string")?;

    // Note that the SSH format actually supports having multiple keys
    // inside a single file...
    let mut keys = parse_private_key(string).with_context(|| "failed to parse private key")?;

    // ... but we don't :)
    match keys.deref_mut() {
      [_] => Ok(convert_priv(keys.swap_remove(0))),
      _ => {
        let err = Err(anyhow!(
          "private key file contains unsupported number of keys"
        ));
        err.with_context(|| "failed to read PEM encoded private key")
      },
    }
  }
}

impl FromPem<PemPublicKey> for PublicKey {
  fn from_pem(pem_key: PemPublicKey) -> Result<Self> {
    let data = Vec::<_>::from(pem_key);
    let string = str_from_utf8(&data).with_context(|| "failed to convert public key to string")?;
    let key = parse_public_key(string).with_context(|| "failed to parse public key")?;

    Ok(convert_pub(key))
  }
}
