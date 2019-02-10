// error.rs

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

use std::borrow::Cow;
use std::error::Error as StdError;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io::Error as IoError;
use std::ops::Deref;
use std::result::Result as StdResult;


type Str = Cow<'static, str>;


fn fmt_err(err: &dyn StdError, fmt: &mut Formatter<'_>) -> FmtResult {
  write!(fmt, "{}", err)?;
  if let Some(cause) = err.cause() {
    write!(fmt, ": ")?;
    fmt_err(cause, fmt)?;
  }
  Ok(())
}


/// The error enum this crate works with.
#[derive(Debug)]
pub enum Error {
  Any(Box<dyn StdError>),
  Io(IoError),
}

impl Display for Error {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    match self {
      Error::Any(err) => fmt_err(err.deref(), f),
      Error::Io(err) => fmt_err(err, f),
    }
  }
}

impl From<Box<dyn StdError>> for Error {
  fn from(e: Box<dyn StdError>) -> Self {
    Error::Any(e)
  }
}

impl From<IoError> for Error {
  fn from(e: IoError) -> Self {
    Error::Io(e)
  }
}


pub struct CtxErr(Str, Error);

impl Debug for CtxErr {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    // For our intents and purposes the debug representation behaves
    // exactly like Display would, by printing a correctly formatted
    // error. This implementation is what is actually invoked when
    // displaying an error returned from `main`.
    write!(f, "{}: {}", self.0, self.1)
  }
}

impl<E> From<(Str, E)> for CtxErr
where
  E: Into<Error>,
{
  fn from(e: (Str, E)) -> Self {
    Self(e.0, e.1.into())
  }
}


pub type Result<T> = StdResult<T, CtxErr>;


pub trait WithCtx<T, E>
where
  Self: Sized,
  E: Into<Error>,
{
  fn ctx<F, S>(self, ctx: F) -> StdResult<T, CtxErr>
  where
    F: Fn() -> S,
    S: Into<Str>;
}

impl<T, E> WithCtx<T, E> for StdResult<T, E>
where
  E: Into<Error>,
{
  fn ctx<F, S>(self, ctx: F) -> StdResult<T, CtxErr>
  where
    F: Fn() -> S,
    S: Into<Str>,
  {
    self.map_err(|e| CtxErr(ctx().into(), e.into()))
  }
}
