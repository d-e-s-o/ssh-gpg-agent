// Copyright (C) 2019-2026 Daniel Mueller <deso@posteo.net>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::str::from_utf8 as str_from_utf8;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;

use ssh_key::Algorithm;
use ssh_key::PrivateKey as SshPrivateKey;
use ssh_key::PublicKey as SshPublicKey;
use ssh_key::public::KeyData;

use crate::files::PemPrivateKey;
use crate::files::PemPublicKey;


/// Check that we are able to sign with a key using the given algorithm.
fn check_algorithm(algorithm: Algorithm, kind: &str) -> Result<()> {
  match algorithm {
    Algorithm::Rsa { .. } | Algorithm::Ed25519 => Ok(()),
    algorithm => bail!("unsupported {kind} key type: {algorithm}"),
  }
}


/// A public key along with the comment stored with it.
#[derive(Debug)]
pub struct AuthorizedKey {
  /// The public key.
  pub key: KeyData,
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

impl FromPem<PemPrivateKey> for SshPrivateKey {
  fn from_pem(pem_key: PemPrivateKey) -> Result<Self> {
    let data = Vec::<_>::from(pem_key);
    // The `ssh-key` crate rejects white space around the PEM
    // boundaries, but we want to be lenient with input, so strip
    // whatever the file may contain.
    let key = Self::from_openssh(data.trim_ascii()).context("failed to parse private key")?;

    // `ssh-key` hands us an encrypted key as is, so we have to check
    // for this case ourselves.
    if key.is_encrypted() {
      let err = Err(anyhow!("passphrase protected keys are not supported"));
      return err.with_context(|| "failed to read PEM encoded private key");
    }

    // Only keys we are actually able to sign with are of any use to
    // us.
    let algorithm = key
      .key_data()
      .algorithm()
      .context("failed to determine private key type")?;
    let () = check_algorithm(algorithm, "private")?;

    Ok(key)
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
    let () = check_algorithm(key.algorithm(), "public")?;
    let comment = key.comment().to_owned();

    let slf = Self {
      key: key.key_data().clone(),
      comment,
    };
    Ok(slf)
  }
}


#[cfg(test)]
mod test {
  use super::*;

  use crate::files::load_public_key;
  use crate::files::test::load_unencrypted_private_key;


  /// Serialize key data into the blob an agent reports for an identity.
  fn key_blob(key: &KeyData) -> Vec<u8> {
    SshPublicKey::from(key.clone())
      .to_bytes()
      .expect("failed to serialize public key")
  }


  /// Verify that the public key contained in a private key is identical
  /// to the public key stored in its `.pub` counterpart.
  #[test]
  fn public_key_equivalence() {
    for name in ["ed25519", "rsa2048"] {
      let privkey = load_unencrypted_private_key(format!("tests/valid_keys/{name}")).unwrap();
      let privkey = SshPrivateKey::from_pem(privkey).unwrap();

      let pubkey = load_public_key(format!("tests/valid_keys/{name}.pub")).unwrap();
      let pubkey = AuthorizedKey::from_pem(pubkey).unwrap().key;

      assert_eq!(
        key_blob(privkey.public_key().key_data()),
        key_blob(&pubkey),
        "public key blob mismatch for `{name}`"
      );

      // A key only ever travels the protocol as a blob, so make sure
      // the one we hand out decodes back into the key it came from.
      let decoded =
        SshPublicKey::from_bytes(&key_blob(&pubkey)).expect("failed to read public key blob");
      assert_eq!(
        decoded.key_data(),
        &pubkey,
        "public key blob round trip mismatch for `{name}`"
      );
    }
  }
}
