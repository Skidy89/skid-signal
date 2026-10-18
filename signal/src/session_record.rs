use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use prost::Message;
use signal_proto::signal::session::{Chain, SessionEntry, SessionRecord};

pub const CLOSED_SESSIONS_MAX: usize = 40;
pub const SESSION_RECORD_VERSION: &str = "v1";
pub const BASE_KEY_OURS: i32 = 1;
pub const BASE_KEY_THEIRS: i32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
  #[error("Overwrite attempt")]
  OverwriteAttempt,
  #[error("Not Found")]
  NotFound,
  #[error("Tried to lookup a session using our basekey")]
  OurBaseKey,
  #[error("Corrupt sessions object")]
  Corrupt,
  #[error("Session has no index_info")]
  MissingIndexInfo,
  #[error("Unsupported SessionRecord version: {0}")]
  UnsupportedVersion(String),
  #[error("protobuf: {0}")]
  Decode(#[from] prost::DecodeError),
  #[error("Invalid buffer length: {0}")]
  InvalidBufferLength(usize),
}

pub type Result<T> = std::result::Result<T, SessionError>;

pub fn now_ms() -> i64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|d| d.as_millis() as i64)
    .unwrap_or(0)
}

#[inline]
fn key_id(key: &[u8]) -> String {
  B64.encode(key)
}

fn check_version(record: &SessionRecord) -> Result<()> {
  match record.version.as_str() {
    "" | SESSION_RECORD_VERSION => Ok(()),
    other => Err(SessionError::UnsupportedVersion(other.to_owned())),
  }
}

pub trait SessionEntryExt {
  fn base_key(&self) -> Option<&[u8]>;
  fn used(&self) -> i64;
  fn closed_at(&self) -> i64;
  fn is_closed(&self) -> bool;
  fn close(&mut self);
  fn open(&mut self);

  fn add_chain(&mut self, key: &[u8], chain: Chain) -> Result<()>;
  fn get_chain(&self, key: &[u8]) -> Option<&Chain>;
  fn get_chain_mut(&mut self, key: &[u8]) -> Option<&mut Chain>;
  fn delete_chain(&mut self, key: &[u8]) -> Result<()>;
  fn iter_chains(&self) -> Vec<(Vec<u8>, &Chain)>;
}

impl SessionEntryExt for SessionEntry {
  fn base_key(&self) -> Option<&[u8]> {
    self.index_info.as_ref().map(|i| i.base_key.as_slice())
  }

  fn used(&self) -> i64 {
    self.index_info.as_ref().map_or(0, |i| i.used)
  }

  fn closed_at(&self) -> i64 {
    self.index_info.as_ref().map_or(0, |i| i.closed_at)
  }

  #[inline]
  fn is_closed(&self) -> bool {
    self.index_info.as_ref().is_some_and(|i| i.is_closed)
  }

  fn close(&mut self) {
    if let Some(info) = self.index_info.as_mut() {
      if info.is_closed {
        eprintln!("Session already closed");
        return;
      }
      info.is_closed = true;
      info.closed_at = now_ms();
    }
  }

  fn open(&mut self) {
    if let Some(info) = self.index_info.as_mut() {
      if !info.is_closed {
        eprintln!("Session already open");
      }
      info.is_closed = false;
      info.closed_at = 0;
    }
  }

  fn add_chain(&mut self, key: &[u8], chain: Chain) -> Result<()> {
    let id = key_id(key);
    if self.chains.contains_key(&id) {
      return Err(SessionError::OverwriteAttempt);
    }
    self.chains.insert(id, chain);
    Ok(())
  }

  fn get_chain(&self, key: &[u8]) -> Option<&Chain> {
    self.chains.get(&key_id(key))
  }

  fn get_chain_mut(&mut self, key: &[u8]) -> Option<&mut Chain> {
    self.chains.get_mut(&key_id(key))
  }

  fn delete_chain(&mut self, key: &[u8]) -> Result<()> {
    self
      .chains
      .remove(&key_id(key))
      .map(|_| ())
      .ok_or(SessionError::NotFound)
  }

  fn iter_chains(&self) -> Vec<(Vec<u8>, &Chain)> {
    self
      .chains
      .iter()
      .filter_map(|(k, v)| B64.decode(k).ok().map(|k| (k, v)))
      .collect()
  }
}

pub trait SessionRecordExt: Sized {
  fn new() -> Self;
  fn serialize(&self) -> Vec<u8>;
  fn deserialize(buf: &[u8]) -> Result<Self>;

  fn have_open_session(&self) -> bool;
  fn get_session(&self, key: &[u8]) -> Result<Option<&SessionEntry>>;
  fn get_session_mut(&mut self, key: &[u8]) -> Option<&mut SessionEntry>;
  fn get_open_session(&self) -> Option<&SessionEntry>;
  fn get_open_session_mut(&mut self) -> Option<&mut SessionEntry>;
  fn set_session(&mut self, session: SessionEntry) -> Result<()>;
  fn get_sessions(&self) -> Vec<&SessionEntry>;

  fn close_session(&mut self, base_key: &[u8]);
  fn open_session(&mut self, base_key: &[u8]);
  fn remove_old_sessions(&mut self) -> Result<()>;
  fn delete_all_sessions(&mut self);
}

impl SessionRecordExt for SessionRecord {
  fn new() -> Self {
    Self::default()
  }

  fn serialize(&self) -> Vec<u8> {
    self.encode_to_vec()
  }

  fn deserialize(buf: &[u8]) -> Result<Self> {
    let record = Self::decode(buf)?;
    check_version(&record)?;
    Ok(record)
  }

  fn have_open_session(&self) -> bool {
    self
      .get_open_session()
      .is_some_and(|s| s.registration_id != 0)
  }

  fn get_session(&self, key: &[u8]) -> Result<Option<&SessionEntry>> {
    match self.sessions.get(&key_id(key)) {
      Some(s)
        if s
          .index_info
          .as_ref()
          .is_some_and(|i| i.base_key_type == BASE_KEY_OURS) =>
      {
        Err(SessionError::OurBaseKey)
      }
      other => Ok(other),
    }
  }

  fn get_session_mut(&mut self, key: &[u8]) -> Option<&mut SessionEntry> {
    self.sessions.get_mut(&key_id(key))
  }

  fn get_open_session(&self) -> Option<&SessionEntry> {
    self.sessions.values().find(|s| !s.is_closed())
  }

  fn get_open_session_mut(&mut self) -> Option<&mut SessionEntry> {
    self.sessions.values_mut().find(|s| !s.is_closed())
  }

  fn set_session(&mut self, session: SessionEntry) -> Result<()> {
    let id = key_id(session.base_key().ok_or(SessionError::MissingIndexInfo)?);
    self.sessions.insert(id, session);
    if self.version.is_empty() {
      self.version = SESSION_RECORD_VERSION.to_owned();
    }
    Ok(())
  }

  fn get_sessions(&self) -> Vec<&SessionEntry> {
    let mut v: Vec<&SessionEntry> = self.sessions.values().collect();
    v.sort_by_key(|s| s.used());
    v
  }

  fn close_session(&mut self, base_key: &[u8]) {
    if let Some(s) = self.get_session_mut(base_key) {
      s.close();
    }
  }

  fn open_session(&mut self, base_key: &[u8]) {
    if let Some(s) = self.get_session_mut(base_key) {
      s.open();
    }
  }

  fn remove_old_sessions(&mut self) -> Result<()> {
    while self.sessions.len() > CLOSED_SESSIONS_MAX {
      let oldest = self
        .sessions
        .iter()
        .filter(|(_, s)| s.is_closed())
        .min_by_key(|(_, s)| s.closed_at())
        .map(|(k, _)| k.clone())
        .ok_or(SessionError::Corrupt)?;
      self.sessions.remove(&oldest);
    }
    Ok(())
  }

  fn delete_all_sessions(&mut self) {
    self.sessions.clear();
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use signal_proto::signal::session::SessionIndexInfo;

  fn entry(base_key: &[u8], base_key_type: i32) -> SessionEntry {
    SessionEntry {
      registration_id: 1,
      index_info: Some(SessionIndexInfo {
        base_key: base_key.to_vec(),
        base_key_type,
        ..Default::default()
      }),
      ..Default::default()
    }
  }

  #[test]
  fn empty_record_is_zero_bytes() {
    assert!(SessionRecord::new().serialize().is_empty());
  }

  #[test]
  fn roundtrip() {
    let mut r = SessionRecord::new();
    r.set_session(entry(&[1, 2, 3], BASE_KEY_THEIRS)).unwrap();
    let back = SessionRecord::deserialize(&r.serialize()).unwrap();
    assert_eq!(r, back);
    assert!(back.have_open_session());
  }

  #[test]
  fn our_base_key_is_rejected() {
    let mut r = SessionRecord::new();
    r.set_session(entry(&[9], BASE_KEY_OURS)).unwrap();
    assert!(matches!(r.get_session(&[9]), Err(SessionError::OurBaseKey)));
  }

  #[test]
  fn close_and_open() {
    let mut r = SessionRecord::new();
    r.set_session(entry(&[1], BASE_KEY_THEIRS)).unwrap();
    r.close_session(&[1]);
    assert!(!r.have_open_session());
    r.open_session(&[1]);
    assert!(r.have_open_session());
  }
}
