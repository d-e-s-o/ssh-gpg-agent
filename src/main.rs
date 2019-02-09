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

//! `ssh-gpg-agent` is an SSH agent that can transparently handle GPG
//! encrypted SSH keys.

use std::env::temp_dir;
use std::error::Error as StdError;
use std::fs::remove_file;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::result::Result;

use dirs::home_dir;

use log::error;

use ssh_agent::agent::Agent;
use ssh_agent::proto::message::Message;


/// The SSH agent supporting GPG encrypted SSH keys.
struct GpgKeyAgent {
}

impl GpgKeyAgent {
  fn new<P>(dir: P) -> Self
  where
    P: Into<PathBuf>,
  {
    Self {}
  }

  /// Handle a message to the agent.
  fn handle_message(&self, request: Message) -> Result<Message, ()> {
    unimplemented!()
  }
}

impl Agent for GpgKeyAgent {
  type Error = ();

  fn handle(&self, message: Message) -> Result<Message, ()> {
    self.handle_message(message).or_else(|err| {
      error!("Error handling message: {:?}", err);
      Ok(Message::Failure)
    })
  }
}


/// Run the SSH agent.
fn main() -> Result<(), Box<StdError>> {
  env_logger::init();

  let ssh_dir = home_dir()
    .ok_or_else(|| IoError::new(ErrorKind::NotFound, "no home directory found"))?
    .join(".ssh");

  let agent = GpgKeyAgent::new(ssh_dir);
  let socket = temp_dir().join("ssh-gpg-agent.sock");
  let _ = remove_file(&socket);

  agent.run_unix(&socket)?;
  Ok(())
}
