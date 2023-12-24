// files.rs

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

use std::ffi::OsStr;
use std::fs::File;
use std::fs::read_dir;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context as _;
use anyhow::Result;

use gpgme::Context;
use gpgme::Protocol;


/// The extension SSH public keys in a given directory that we recognize
/// and read.
const PUBLIC_EXT: &str = "pub";
/// The extension of GPG encrypted private keys in a given directory
/// that we recognize and attempt to decrypt.
const PRIVATE_EXT: &str = "gpg";


/// A public key in PEM encoded form, as it was loaded from file.
#[derive(Debug)]
pub struct PemPublicKey(Vec<u8>);

impl From<PemPublicKey> for Vec<u8> {
  fn from(key: PemPublicKey) -> Self {
    key.0
  }
}


/// A private key in PEM encoded form, as it was loaded from file.
#[derive(Debug)]
pub struct PemPrivateKey(Vec<u8>);

impl From<PemPrivateKey> for Vec<u8> {
  fn from(key: PemPrivateKey) -> Self {
    key.0
  }
}


/// Load a private SSH key from the given file. The file is assumed to
/// be GPG encrypted.
pub fn load_private_key(file: &Path) -> Result<PemPrivateKey> {
  let mut input =
    File::open(file).with_context(|| format!("failed to open {} for reading", file.display()))?;

  let mut gpg =
    Context::from_protocol(Protocol::OpenPgp).with_context(|| "failed to connect to GPG")?;

  let mut output = Vec::new();
  let _ = gpg
    .decrypt(&mut input, &mut output)
    .with_context(|| format!("failed to decrypt {}", file.display()))?;

  Ok(PemPrivateKey(output))
}


/// Load a public SSH key from the given file.
pub(crate) fn load_public_key<P>(file: P) -> Result<PemPublicKey>
where
  P: AsRef<Path>,
{
  let file = file.as_ref();
  let mut f =
    File::open(file).with_context(|| format!("failed to open {} for reading", file.display()))?;

  let mut data = Vec::new();
  let _ = f
    .read_to_end(&mut data)
    .with_context(|| format!("failed to read data from {}", file.display()))?;

  Ok(PemPublicKey(data))
}


/// Find all public keys that have a corresponding GPG encrypted private
/// key available as well. That is, we directly load all "key.pub" files
/// in the given directory that also have a corresponding "key.gpg"
/// available. The path to the encrypted secret key is returned as well.
pub fn public_keys<P>(dir: P) -> Result<impl Iterator<Item = Result<(PemPublicKey, PathBuf)>>>
where
  P: Into<PathBuf>,
{
  let dir = dir.into();

  read_dir(&dir)
    .with_context(|| format!("failed to read contents of {}", dir.display()))
    .map(move |x| {
      x.filter_map(move |entry| match entry {
        Ok(entry) => {
          let path = entry.path();
          if path.exists() && !path.is_dir() && path.extension() == Some(OsStr::new(PUBLIC_EXT)) {
            let mut gpg_path = path.clone();
            let _ = gpg_path.set_extension(OsStr::new(PRIVATE_EXT));

            if gpg_path.exists() && !gpg_path.is_dir() {
              Some(load_public_key(&path).map(|x| (x, gpg_path)))
            } else {
              None
            }
          } else {
            None
          }
        }
        Err(err) => Some(Err(err).with_context(|| {
          format!(
            "failed to read directory entry in {}",
            dir.display(),
          )
        })),
      })
    })
}


#[cfg(test)]
pub mod test {
  use super::*;

  use crate::keys::FromPem;

  use ssh_agent_lib::proto::private_key::PrivateKey;
  use ssh_agent_lib::proto::public_key::PublicKey;


  /// Load a private key from a plain text file. This function is for
  /// testing only. Throughout the program we assume GPG encrypted
  /// private keys.
  pub fn load_unencrypted_private_key<P>(file: P) -> Result<PemPrivateKey>
  where
    P: AsRef<Path>,
  {
    let file = file.as_ref();
    let mut input =
      File::open(file).with_context(|| format!("failed to open {} for reading", file.display()))?;

    let mut output = Vec::new();
    let _ = input
      .read_to_end(&mut output)
      .with_context(|| format!("failed to read data from {}", file.display()))?;

    Ok(PemPrivateKey(output))
  }


  /// Verify that we can load our test key.
  #[test]
  fn load_public_keys() -> Result<()> {
    let mut keys = public_keys("tests/valid_keys")?;
    let (_, path) = keys.next().unwrap()?;
    assert_eq!(path.to_str().unwrap(), "tests/valid_keys/ed25519.gpg");

    let (_, path) = keys.next().unwrap()?;
    assert_eq!(path.to_str().unwrap(), "tests/valid_keys/rsa2048.gpg");

    assert!(keys.next().is_none());
    Ok(())
  }


  /// Verify that invalid keys are not loaded.
  #[test]
  fn dont_load_invalid_public_keys() -> Result<()> {
    let keys = public_keys("tests/invalid_keys")?;
    assert_eq!(keys.count(), 0);
    Ok(())
  }


  /// Test the conversion into of an ed25519 public key object loaded
  /// from file into an ssh_agent style PublicKey.
  #[test]
  fn public_key_conversion_ed25519() -> Result<()> {
    let pubkey = load_public_key("tests/valid_keys/ed25519.pub")?;
    let _ = PublicKey::from_pem(pubkey)?;
    Ok(())
  }


  /// Test the conversion into of an ed25519 private key object loaded
  /// from file into an ssh_agent style PrivateKey.
  #[test]
  fn private_key_conversion_ed25519() -> Result<()> {
    let privkey = load_unencrypted_private_key("tests/valid_keys/ed25519")?;
    let _ = PrivateKey::from_pem(privkey)?;
    Ok(())
  }


  /// Test the conversion into of an RSA public key object loaded
  /// from file into an ssh_agent style PublicKey.
  #[test]
  fn public_key_conversion_rsa2048() -> Result<()> {
    let pubkey = load_public_key("tests/valid_keys/rsa2048.pub")?;
    let _ = PublicKey::from_pem(pubkey)?;
    Ok(())
  }


  /// Test the conversion into of an RSA private key object loaded
  /// from file into an ssh_agent style PrivateKey.
  #[test]
  fn private_key_conversion_rsa2048() -> Result<()> {
    let privkey = load_unencrypted_private_key("tests/valid_keys/rsa2048")?;
    let _ = PrivateKey::from_pem(privkey)?;
    Ok(())
  }
}
