// main.rs

// *************************************************************************
// * Copyright (C) 2019-2020 Daniel Mueller (deso@posteo.net)              *
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

#![warn(
  bad_style,
  dead_code,
  future_incompatible,
  illegal_floating_point_literal_pattern,
  improper_ctypes,
  intra_doc_link_resolution_failure,
  late_bound_lifetime_arguments,
  missing_copy_implementations,
  missing_debug_implementations,
  missing_docs,
  no_mangle_generic_items,
  non_shorthand_field_patterns,
  nonstandard_style,
  overflowing_literals,
  path_statements,
  patterns_in_fns_without_body,
  private_in_public,
  proc_macro_derive_resolution_fallback,
  renamed_and_removed_lints,
  rust_2018_compatibility,
  rust_2018_idioms,
  safe_packed_borrows,
  stable_features,
  trivial_bounds,
  trivial_numeric_casts,
  type_alias_bounds,
  tyvar_behind_raw_pointer,
  unconditional_recursion,
  unreachable_code,
  unreachable_patterns,
  unstable_features,
  unstable_name_collisions,
  unused,
  unused_comparisons,
  unused_import_braces,
  unused_lifetimes,
  unused_qualifications,
  unused_results,
  where_clauses_object_safety,
  while_true,
)]

//! `ssh-gpg-agent` is an SSH agent that can transparently handle GPG
//! encrypted SSH keys.

mod files;
mod keys;
mod sign;

use std::env::args_os;
use std::env::temp_dir;
use std::error::Error as StdError;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::remove_file;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::result::Result as StdResult;

use anyhow::anyhow;
use anyhow::Context as _;
use anyhow::Result;

use dirs::home_dir;

use log::error;
use log::info;

use ssh_agent::agent::Agent;
use ssh_agent::proto::Blob;
use ssh_agent::proto::from_bytes;
use ssh_agent::proto::message::Identity;
use ssh_agent::proto::message::Message;
use ssh_agent::proto::message::SignatureBlob;
use ssh_agent::proto::message::SignRequest;
use ssh_agent::proto::private_key::PrivateKey;
use ssh_agent::proto::public_key::PublicKey;

use crate::files::load_private_key;
use crate::files::public_keys;
use crate::keys::FromPem;
use crate::sign::Signer;


trait Mapper<T, E>
where
  Self: Sized,
{
  fn map_flat<F, U>(self, f: F) -> StdResult<U, E>
  where
    F: FnMut(T) -> StdResult<U, E>;
}

impl<T, E> Mapper<T, E> for StdResult<T, E> {
  fn map_flat<F, U>(self, mut f: F) -> StdResult<U, E>
  where
    F: FnMut(T) -> StdResult<U, E>,
  {
    match self {
      Ok(val) => f(val),
      Err(err) => Err(err),
    }
  }
}


/// The SSH agent supporting GPG encrypted SSH keys.
///
/// Upon creation the agent will load public keys that have
/// corresponding encrypted private keys inside its associated directory
/// and keep those public keys in memory. It explicitly does not cache
/// secret key material, but loads it on demand for each and every
/// request.
struct GpgKeyAgent {
  /// The directory in which to look for SSH key pairs.
  dir: PathBuf,
}

impl GpgKeyAgent {
  fn new<P>(dir: P) -> Self
  where
    P: Into<PathBuf>,
  {
    Self { dir: dir.into() }
  }

  /// Retrieve the agent's public keys.
  fn public_keys(&self) -> Result<impl Iterator<Item = Result<(PublicKey, PathBuf)>>> {
    let keys = public_keys(self.dir.clone())?
      .map(|x| {
        x.map_flat(|(key, path)| {
          PublicKey::from_pem(key)
            .map(|x| (x, path))
        })
      });
    Ok(keys)
  }

  /// Handle a request for all known identities.
  fn identities(&self) -> Result<Vec<Identity>> {
    let mut idents = Vec::new();
    for result in self.public_keys()? {
      let pubkey = result?.0;
      let blob = pubkey
        .to_blob()
        .with_context(|| "failed to serialize private key")?;
      let ident = Identity {
        pubkey_blob: blob,
        // The ssh-keys crate currently does not support handling of
        // comments and so we just fill in an empty string here.
        comment: String::new(),
      };

      idents.push(ident);
    }
    Ok(idents)
  }

  /// Load the private key corresponding to the given public key.
  fn find_private_key(&self, pubkey: &PublicKey) -> Option<Result<PathBuf>> {
    match self.public_keys() {
      Ok(mut keys) => keys.find_map(|x| match x {
        Ok((key, path)) => {
          if &key == pubkey {
            Some(Ok(path))
          } else {
            None
          }
        }
        Err(err) => Some(Err(err)),
      }),
      Err(err) => Some(Err(err)),
    }
  }

  /// Handle a sign request.
  fn sign(&self, request: &SignRequest) -> Result<SignatureBlob> {
    let pubkey = from_bytes::<PublicKey>(&request.pubkey_blob)
      .with_context(|| "failed to convert public key blob back to public key")?;

    if let Some(file) = self.find_private_key(&pubkey) {
      let key = PrivateKey::from_pem(load_private_key(&file?)?)?;
      let sig = key
        .sign(&request.data)
        .with_context(|| "failed to sign request data")?;
      let blob = sig
        .to_blob()
        .with_context(|| "failed to serialized signature")?;
      Ok(blob)
    } else {
      let err = Err(anyhow!("identity not found"));
      err.with_context(|| "failed to create signature")
    }
  }

  /// Handle a message to the agent.
  fn handle_message(&self, request: Message) -> Result<Message> {
    info!("Request: {:?}", request);
    let response = match request {
      Message::RequestIdentities => {
        Ok(Message::IdentitiesAnswer(self.identities()?))
      },
      Message::SignRequest(request) => {
        Ok(Message::SignResponse(self.sign(&request)?))
      },
      _ => {
        let err = Err(anyhow!("received unsupported message: {:?}", request));
        err.with_context(|| "failed to handle agent request")
      },
    };
    info!("Response {:?}", response);
    response
  }
}

impl Agent for GpgKeyAgent {
  type Error = ();

  fn handle(&self, message: Message) -> StdResult<Message, ()> {
    self.handle_message(message).or_else(|err| {
      error!("Error handling message: {:?}", err);
      Ok(Message::Failure)
    })
  }
}


/// A wrapper around a boxed error that allows us to use it in
/// conjunction with `anyhow`.
///
/// This type is required because `Box<dyn Error>` is lacking an
/// implementation of `std::error::Error`; for more details check
/// https://github.com/rust-lang/rust/issues/60759
#[derive(Debug)]
struct E(Box<dyn StdError + Send + Sync>);

impl Display for E {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "{}", self.0)
  }
}

impl StdError for E {}


/// Run the SSH agent.
fn main() -> Result<()> {
  env_logger::init();

  let dir = if let Some(dir) = args_os().nth(1) {
    dir.into()
  } else {
    home_dir()
      .ok_or_else(|| IoError::new(ErrorKind::NotFound, "no home directory found"))
      .with_context(|| "failed to retrieve home directory")?
      .join(".ssh")
  };

  let agent = GpgKeyAgent::new(dir);
  let socket = temp_dir().join("ssh-gpg-agent.sock");
  let _ = remove_file(&socket);

  agent
    .run_unix(&socket)
    .map_err(E)
    .with_context(|| "failed to start agent")?;
  Ok(())
}
