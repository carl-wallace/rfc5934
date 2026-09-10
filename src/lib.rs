#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

extern crate alloc;

pub mod apex;
pub mod collection;
pub mod common;
pub mod community;
pub mod dod;
pub mod error;
pub mod message;
pub mod oid;
pub mod seqnum;
pub mod signed;
pub mod status;
pub mod update;

pub use collection::{ContentCollection, ContentWithAttributes};
pub use common::{StatusCode, TampMsgRef, TargetIdentifier, TerseOrVerbose, V1, V2};
pub use message::{MessageType, TampMessage};
pub use oid::{ID_CT_CONTENT_COLLECTION, ID_CT_TAMP_UPDATE};
pub use update::{TampUpdate, TrustAnchorUpdate};
