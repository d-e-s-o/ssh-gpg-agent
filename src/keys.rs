// keys.rs

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

use std::str::from_utf8 as str_from_utf8;

use ssh_agent::proto::public_key::Ed25519PublicKey;
use ssh_agent::proto::public_key::PublicKey;

use ssh_keys::openssh::parse_public_key;
use ssh_keys::PublicKey as SshPublicKey;

use crate::error::Result;
use crate::error::WithCtx;
use crate::files::PemPublicKey;


/// Convert an ssh_keys PrivateKey into an ssh_agent PrivateKey.
fn convert_pub(key: SshPublicKey) -> PublicKey {
  match key {
    SshPublicKey::Rsa { .. } => unimplemented!(),
    SshPublicKey::Ed25519(data) => {
      let ed25519 = Ed25519PublicKey {
        enc_a: data.to_vec(),
      };
      PublicKey::Ed25519(ed25519)
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

impl FromPem<PemPublicKey> for PublicKey {
  fn from_pem(pem_key: PemPublicKey) -> Result<Self> {
    let data = Vec::<_>::from(pem_key);
    let string = str_from_utf8(&data)
      .ctx(|| "failed to convert public key to string")?;

    let key = parse_public_key(string)
      .ctx(|| "failed to parse public key")?;

    Ok(convert_pub(key))
  }
}
