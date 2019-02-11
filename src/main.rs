// main.rs

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

#![deny(
  dead_code,
  illegal_floating_point_literal_pattern,
  improper_ctypes,
  intra_doc_link_resolution_failure,
  late_bound_lifetime_arguments,
  missing_copy_implementations,
  missing_debug_implementations,
  missing_docs,
  no_mangle_generic_items,
  non_shorthand_field_patterns,
  overflowing_literals,
  path_statements,
  patterns_in_fns_without_body,
  plugin_as_library,
  private_in_public,
  proc_macro_derive_resolution_fallback,
  safe_packed_borrows,
  stable_features,
  trivial_bounds,
  trivial_numeric_casts,
  type_alias_bounds,
  tyvar_behind_raw_pointer,
  unconditional_recursion,
  unions_with_drop_fields,
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
#![warn(
  bad_style,
  future_incompatible,
  nonstandard_style,
  renamed_and_removed_lints,
  rust_2018_compatibility,
  rust_2018_idioms,
)]

//! `ssh-gpg-agent` is an SSH agent that can transparently handle GPG
//! encrypted SSH keys.

mod error;
mod files;
mod keys;

use std::collections::HashMap;
use std::env::temp_dir;
use std::error::Error as StdError;
use std::fs::remove_file;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::result::Result as StdResult;

use dirs::home_dir;

use log::error;
use log::info;

use ssh_agent::agent::Agent;
use ssh_agent::proto::Blob;
use ssh_agent::proto::message::Identity;
use ssh_agent::proto::message::Message;
use ssh_agent::proto::public_key::PublicKey;

use crate::error::Error;
use crate::error::Result;
use crate::error::WithCtx;
use crate::files::public_keys;
use crate::keys::FromPem;


/// The SSH agent supporting GPG encrypted SSH keys.
///
/// Upon creation the agent will load public keys that have
/// corresponding encrypted private keys inside its associated directory
/// and keep those public keys in memory. It explicitly does not cache
/// secret key material, but loads it on demand for each and every
/// request.
struct GpgKeyAgent {
  /// A mapping from public keys (i.e., "identities") to paths to
  /// encrypted private keys. The private keys are loaded on demand for
  /// signing requests.
  keys: HashMap<PublicKey, PathBuf>,
}

impl GpgKeyAgent {
  fn new<P>(dir: P) -> Result<Self>
  where
    P: Into<PathBuf>,
  {
    let mut keys = HashMap::new();
    for result in public_keys(dir)? {
      let (key, path) = result?;
      let _ = keys.insert(PublicKey::from_pem(key)?, path);
    }

    Ok(Self { keys })
  }

  /// Handle a request for all known identities.
  fn identities(&self) -> Result<Vec<Identity>> {
    let mut idents = Vec::new();
    for key in self.keys.keys() {
      let pubkey = key.clone()
        .to_blob()
        .ctx(|| "failed to serialize private key")?;

      let ident = Identity {
        pubkey_blob: pubkey,
        // The ssh-keys crate currently does not support handling of
        // comments and so we just fill in an empty string here.
        comment: String::new(),
      };

      idents.push(ident);
    }
    Ok(idents)
  }

  /// Handle a message to the agent.
  fn handle_message(&self, request: Message) -> Result<Message> {
    info!("Request: {:?}", request);
    let response = match request {
      Message::RequestIdentities => {
        Ok(Message::IdentitiesAnswer(self.identities()?))
      },
      _ => {
        let err = Box::<dyn StdError>::from(format!("received unsupported message: {:?}", request));
        Err(Error::Any(err)).ctx(|| "failed to handle agent request")
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


/// Run the SSH agent.
fn main() -> Result<()> {
  env_logger::init();

  let ssh_dir = home_dir()
    .ok_or_else(|| IoError::new(ErrorKind::NotFound, "no home directory found"))
    .ctx(|| "failed to retrieve home directory")?
    .join(".ssh");

  let agent = GpgKeyAgent::new(ssh_dir)?;
  let socket = temp_dir().join("ssh-gpg-agent.sock");
  let _ = remove_file(&socket);

  agent.run_unix(&socket)
    .ctx(|| "failed to start agent")?;
  Ok(())
}
