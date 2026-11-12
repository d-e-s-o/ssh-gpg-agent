// Copyright (C) 2019-2026 Daniel Mueller <deso@posteo.net>
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ssh-gpg-agent` is an SSH agent that can transparently handle GPG
//! encrypted SSH keys.

mod files;
mod keys;
mod sign;

use std::env::args_os;
use std::env::temp_dir;
use std::ffi::OsString;
use std::fs::remove_file;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::ExitCode;
use std::result::Result as StdResult;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;

use dirs::home_dir;

use log::debug;
use log::error;
use log::info;

use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::async_trait;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::Blob;
use ssh_agent_lib::proto::from_bytes;
use ssh_agent_lib::proto::message::Identity;
use ssh_agent_lib::proto::message::Message;
use ssh_agent_lib::proto::message::SignRequest;
use ssh_agent_lib::proto::message::SignatureBlob;
use ssh_agent_lib::proto::private_key::PrivateKey;
use ssh_agent_lib::proto::public_key::PublicKey;

use tokio::net::UnixListener;
use tokio::runtime::Builder;

use crate::files::load_private_key;
use crate::files::public_keys;
use crate::keys::AuthorizedKey;
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
#[derive(Clone, Debug)]
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
  fn public_keys(&self) -> Result<impl Iterator<Item = Result<(AuthorizedKey, PathBuf)>>> {
    let keys = public_keys(self.dir.clone())?
      .map(|x| x.map_flat(|(key, path)| AuthorizedKey::from_pem(key).map(|x| (x, path))));
    Ok(keys)
  }

  /// Handle a request for all known identities.
  fn identities(&self) -> Result<Vec<Identity>> {
    let mut idents = Vec::new();
    for result in self.public_keys()? {
      let (AuthorizedKey { key, comment }, path) = result?;
      info!("found public key at `{}`", path.display());

      let blob = key
        .to_blob()
        .with_context(|| "failed to serialize public key")?;
      let ident = Identity {
        pubkey_blob: blob,
        comment,
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
          if &key.key == pubkey {
            Some(Ok(path))
          } else {
            None
          }
        },
        Err(err) => Some(Err(err)),
      }),
      Err(err) => Some(Err(err)),
    }
  }

  /// Handle a sign request.
  fn sign(&self, request: &SignRequest) -> Result<SignatureBlob> {
    let pubkey = from_bytes::<PublicKey>(&request.pubkey_blob)
      .with_context(|| "failed to convert public key blob back to public key")?;

    if let Some(result) = self.find_private_key(&pubkey) {
      let path = result?;
      info!("found matching private key at `{}`", path.display());

      let key = PrivateKey::from_pem(load_private_key(&path)?)?;
      let sig = key
        .sign(request.flags, &request.data)
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
    debug!("Request: {request:?}");
    let response = match request {
      Message::RequestIdentities => Ok(Message::IdentitiesAnswer(self.identities()?)),
      Message::SignRequest(request) => Ok(Message::SignResponse(self.sign(&request)?)),
      _ => {
        let err = Err(anyhow!("received unsupported message: {request:?}"));
        err.with_context(|| "failed to handle agent request")
      },
    };
    debug!("Response: {response:?}");
    response
  }
}

#[async_trait]
impl Session for GpgKeyAgent {
  async fn handle(&mut self, message: Message) -> StdResult<Message, AgentError> {
    // NB: Returning an error here would tear down the connection
    //     altogether, so communicate failures to the client by way of a
    //     `Failure` message.
    let response = self.handle_message(message).unwrap_or_else(|err| {
      error!("Error handling message: {err:?}");
      Message::Failure
    });
    Ok(response)
  }
}

impl Agent for GpgKeyAgent {
  fn new_session(&mut self) -> impl Session {
    self.clone()
  }
}


fn run(key_dir: PathBuf) -> Result<()> {
  env_logger::init();

  let agent = GpgKeyAgent::new(key_dir);
  let socket = temp_dir().join("ssh-gpg-agent.sock");
  let _result = remove_file(&socket);

  let runtime = Builder::new_current_thread()
    .enable_all()
    .build()
    .with_context(|| "failed to create runtime")?;

  // Binding a socket requires the runtime's I/O driver to be active.
  let _guard = runtime.enter();

  let listener = UnixListener::bind(&socket)
    .with_context(|| format!("failed to bind `{}`", socket.display()))?;

  runtime
    .block_on(agent.listen(listener))
    .with_context(|| "failed to start agent")?;
  Ok(())
}


fn main_impl<A, O>(args: A) -> Result<()>
where
  A: Fn() -> O,
  O: ExactSizeIterator<Item = OsString>,
{
  // Slightly ghetto argument parser helps us avoid unnecessary large
  // dependency on `clap`.
  if args().any(|arg| arg == "--help" || arg == "-h") {
    print!(
      "{name} {version} -- a SSH agent that supports PGP encrypted private SSH keys.

USAGE:
  {name} [OPTIONS] [KEY-DIR]

OPTIONS:
  -h, --help        Print help information
  -V, --version     Print version information
",
      name = env!("CARGO_CRATE_NAME"),
      version = env!("VERSION"),
    )
  } else if args().any(|arg| arg == "--version" || arg == "-V") {
    println!("{} {}", env!("CARGO_CRATE_NAME"), env!("VERSION"))
  } else {
    let mut args = args();

    let key_dir = if let Some(dir) = args.next() {
      dir.into()
    } else {
      home_dir()
        .ok_or_else(|| IoError::new(ErrorKind::NotFound, "no home directory found"))
        .with_context(|| "failed to retrieve home directory")?
        .join(".ssh")
    };

    if let Some(arg) = args.next() {
      bail!("unexpected argument '{}' found", arg.to_string_lossy())
    } else {
      run(key_dir)?
    }
  }
  Ok(())
}

/// Run the SSH agent.
fn main() -> ExitCode {
  // By convention the 0th argument contains the path to the program;
  // ignore it.
  let args = || args_os().skip(1);

  main_impl(args)
    .map(|_| ExitCode::SUCCESS)
    .map_err(|e| eprintln!("{e:?}"))
    .unwrap_or(ExitCode::FAILURE)
}
