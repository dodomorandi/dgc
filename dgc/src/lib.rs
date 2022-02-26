#![warn(missing_docs)]
#![doc(html_logo_url = "https://github.com/rust-italia/dgc/raw/main/dgc-rust-logo.svg")]
#![doc = include_str!("../README.md")]
mod cwt;
mod dgc;
mod dgc_container;
mod parse;
mod recovery;
mod test;
mod trustlist;
mod vaccination;
mod valuesets;
use std::borrow::Cow;

pub use crate::dgc::*;
pub use cwt::*;
pub use dgc_container::*;
pub use parse::*;
pub use recovery::*;
pub use test::*;
pub use trustlist::*;
pub use vaccination::*;
pub use valuesets::*;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{de, Deserialize, Deserializer};

fn deserialize_partial_datetime<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Cow::<str>::deserialize(deserializer)?;
    if let Ok(parsed) = DateTime::parse_from_rfc3339(&*raw) {
        return Ok(parsed.into());
    }

    let parsed = NaiveDate::parse_from_str(&*raw, "%F").map_err(de::Error::custom)?;
    Ok(DateTime::from_utc(parsed.and_hms(0, 0, 0), Utc))
}
