// files.rs

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

use std::ffi::OsStr;
use std::fs::File;
use std::fs::read_dir;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

use gpgme::Context;
use gpgme::Protocol;

use crate::error::Result;
use crate::error::WithCtx;


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
  let mut input = File::open(file)
    .ctx(|| format!("failed to open {} for reading", file.to_string_lossy()))?;

  let mut gpg = Context::from_protocol(Protocol::OpenPgp)
    .ctx(|| "failed to connect to GPG")?;

  let mut output = Vec::new();
  let _ = gpg
    .decrypt(&mut input, &mut output)
    .ctx(|| format!("failed to decrypt {}", file.to_string_lossy()))?;

  Ok(PemPrivateKey(output))
}


/// Load a public SSH key from the given file.
fn load_public_key(file: &Path) -> Result<PemPublicKey> {
  let mut f = File::open(file)
    .ctx(|| format!("failed to open {} for reading", file.to_string_lossy()))?;

  let mut data = Vec::new();
  let _ = f
    .read_to_end(&mut data)
    .ctx(|| format!("failed to read data from {}", file.to_string_lossy()))?;

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
    .ctx(|| format!("failed to read contents of {}", dir.to_string_lossy()))
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
        Err(err) => Some(Err(err).ctx(|| {
          format!(
            "failed to read directory entry in {}",
            dir.to_string_lossy(),
          )
        })),
      })
    })
}
