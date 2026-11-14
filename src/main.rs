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

use log::info;

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::agent::listen;
use ssh_agent_lib::async_trait;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::Identity;
use ssh_agent_lib::proto::SignRequest;

use ssh_key::PrivateKey as SshPrivateKey;
use ssh_key::Signature;
use ssh_key::public::KeyData;

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

      let ident = Identity {
        pubkey: key,
        comment,
      };

      idents.push(ident);
    }
    Ok(idents)
  }

  /// Load the private key corresponding to the given public key.
  fn find_private_key(&self, pubkey: &KeyData) -> Option<Result<PathBuf>> {
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
  fn sign_request(&self, request: &SignRequest) -> Result<Signature> {
    if let Some(result) = self.find_private_key(&request.pubkey) {
      let path = result?;
      info!("found matching private key at `{}`", path.display());

      let key = SshPrivateKey::from_pem(load_private_key(&path)?)?;
      let sig = key
        .key_data()
        .sign(request.flags, &request.data)
        .with_context(|| "failed to sign request data")?;
      Ok(sig)
    } else {
      let err = Err(anyhow!("identity not found"));
      err.with_context(|| "failed to create signature")
    }
  }
}

// Note that `ssh-agent-lib` takes care of logging an error we return
// and of replying with a `Failure` message for us.
#[async_trait]
impl Session for GpgKeyAgent {
  async fn request_identities(&mut self) -> StdResult<Vec<Identity>, AgentError> {
    self
      .identities()
      .map_err(|err| AgentError::Other(err.into()))
  }

  async fn sign(&mut self, request: SignRequest) -> StdResult<Signature, AgentError> {
    self
      .sign_request(&request)
      .map_err(|err| AgentError::Other(err.into()))
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
    .block_on(listen(listener, agent))
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
