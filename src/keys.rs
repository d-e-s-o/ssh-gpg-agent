// Copyright (C) 2019-2026 Daniel Mueller <deso@posteo.net>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::str::from_utf8 as str_from_utf8;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;

use ssh_agent_lib::proto::private_key::Ed25519PrivateKey;
use ssh_agent_lib::proto::private_key::PrivateKey;
use ssh_agent_lib::proto::private_key::RsaPrivateKey;
use ssh_agent_lib::proto::public_key::Ed25519PublicKey;
use ssh_agent_lib::proto::public_key::PublicKey;
use ssh_agent_lib::proto::public_key::RsaPublicKey;

use ssh_key::PrivateKey as SshPrivateKey;
use ssh_key::PublicKey as SshPublicKey;
use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;

use crate::files::PemPrivateKey;
use crate::files::PemPublicKey;


/// Convert an `ssh-key` `KeyData` into an `ssh_agent` `PublicKey`.
fn convert_pub(key: KeyData) -> Result<PublicKey> {
  let key = match key {
    KeyData::Rsa(data) => {
      let rsa = RsaPublicKey {
        e: data.e.as_bytes().to_vec(),
        n: data.n.as_bytes().to_vec(),
      };
      PublicKey::Rsa(rsa)
    },
    KeyData::Ed25519(data) => {
      let ed25519 = Ed25519PublicKey {
        enc_a: data.as_ref().to_vec(),
      };
      PublicKey::Ed25519(ed25519)
    },
    other => {
      let algorithm = other.algorithm();
      bail!("unsupported public key type: {algorithm}")
    },
  };
  Ok(key)
}


/// Convert an `ssh-key` `KeypairData` into an `ssh_agent` `PrivateKey`.
fn convert_priv(key: &KeypairData) -> Result<PrivateKey> {
  let key = match key {
    KeypairData::Rsa(key) => {
      let rsa = RsaPrivateKey {
        n: key.public.n.as_bytes().to_vec(),
        e: key.public.e.as_bytes().to_vec(),
        d: key.private.d.as_bytes().to_vec(),
        iqmp: key.private.iqmp.as_bytes().to_vec(),
        p: key.private.p.as_bytes().to_vec(),
        q: key.private.q.as_bytes().to_vec(),
      };
      PrivateKey::Rsa(rsa)
    },
    KeypairData::Ed25519(key) => {
      let ed25519 = Ed25519PrivateKey {
        enc_a: key.public.as_ref().to_vec(),
        k_enc_a: key.private.as_ref().to_vec(),
      };
      PrivateKey::Ed25519(ed25519)
    },
    other => {
      let algorithm = other
        .algorithm()
        .with_context(|| "failed to determine private key type")?;
      bail!("unsupported private key type: {algorithm}")
    },
  };
  Ok(key)
}


/// A public key along with the comment stored with it.
#[derive(Debug)]
pub struct AuthorizedKey {
  /// The public key.
  pub key: PublicKey,
  /// The key's comment.
  pub comment: String,
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
    // The `ssh-key` crate rejects white space around the PEM
    // boundaries, but we want to be lenient with input, so strip
    // whatever the file may contain.
    let key = SshPrivateKey::from_openssh(data.trim_ascii())
      .with_context(|| "failed to parse private key")?;

    // `ssh-key` hands us an encrypted key as is, so we have to check
    // for this case ourselves.
    if key.is_encrypted() {
      let err = Err(anyhow!("passphrase protected keys are not supported"));
      return err.with_context(|| "failed to read PEM encoded private key");
    }

    convert_priv(key.key_data())
  }
}

impl FromPem<PemPublicKey> for AuthorizedKey {
  fn from_pem(pem_key: PemPublicKey) -> Result<Self> {
    let data = Vec::<_>::from(pem_key);
    let string = str_from_utf8(&data).with_context(|| "failed to convert public key to string")?;
    // Note that the `ssh-key` crate does not tolerate leading white
    // space, but we want to be a bit more lenient with input, so strip
    // whatever the file may contain.
    let key =
      SshPublicKey::from_openssh(string.trim()).with_context(|| "failed to parse public key")?;
    let comment = key.comment().to_owned();

    let slf = Self {
      key: convert_pub(key.into())?,
      comment,
    };
    Ok(slf)
  }
}


#[cfg(test)]
mod test {
  use super::*;

  use ssh_agent_lib::proto::Blob;

  use crate::files::load_public_key;
  use crate::files::test::load_unencrypted_private_key;


  /// Verify that the public key contained in a private key is identical
  /// to the public key stored in its `.pub` counterpart.
  #[test]
  fn public_key_equivalence() {
    for name in ["ed25519", "rsa2048"] {
      let privkey = load_unencrypted_private_key(format!("tests/valid_keys/{name}")).unwrap();
      let privkey = PrivateKey::from_pem(privkey).unwrap();
      let blob = PublicKey::from(privkey)
        .to_blob()
        .with_context(|| "failed to serialize private key's public key")
        .unwrap();

      let pubkey = load_public_key(format!("tests/valid_keys/{name}.pub")).unwrap();
      let pubkey = AuthorizedKey::from_pem(pubkey).unwrap().key;
      let expected = pubkey.to_blob().expect("failed to serialize public key");

      assert_eq!(blob, expected, "public key mismatch for `{name}`");
    }
  }
}
