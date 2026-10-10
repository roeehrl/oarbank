//! The coordinator's settings as the agent applies them (docs/design/settings.md, "What the agent gets").
//!
//! Every heartbeat reply carries the node's complete effective `policy` and `limits` with a revision. The agent checks
//! each key against the generated table ([`crate::settings_table`]): a value of the right type and range is applied;
//! anything else (a wrong type, out of range, missing, unknown to this agent) is refused, reported back with the reason,
//! and the key keeps the value it had (before the first heartbeat: the table's default). Nothing falls back silently.

use serde_json::{Map, Value};

use crate::capacity::Schedule;
use crate::json::int_of;
use crate::settings_table::DEFS;

/// The directive section a key travels in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Policy,
    Limits,
}

/// What a value must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Number,
    Integer,
    Bool,
    Strings,
    Object,
    Schedule,
    Choice,
    Text,
}

/// One key of the table.
#[derive(Debug, Clone, Copy)]
pub struct Def {
    pub key: &'static str,
    pub section: Section,
    pub kind: Kind,
    pub nullable: bool,
    pub min: Option<f64>,
    pub exclusive_min: bool,
    pub max: Option<f64>,
    pub choices: &'static [&'static str],
    /// JSON text.
    pub default: &'static str,
}

impl Def {
    pub fn default_value(&self) -> Value {
        serde_json::from_str(self.default).unwrap_or(Value::Null)
    }

    /// The value normalized (an integral double of an integer key becomes an integer), or why it is refused.
    pub fn check(&self, v: &Value) -> Result<Value, String> {
        if v.is_null() {
            return if self.nullable { Ok(Value::Null) } else { Err("a value is required".into()) };
        }
        match self.kind {
            Kind::Bool => v.as_bool().map(Value::Bool).ok_or_else(|| format!("expected true or false, got {v}")),
            Kind::Number | Kind::Integer => {
                let x = v.as_f64().filter(|_| v.is_number()).ok_or_else(|| format!("expected a number, got {v}"))?;
                if let Some(lo) = self.min {
                    if (self.exclusive_min && x <= lo) || (!self.exclusive_min && x < lo) {
                        return Err(format!("{x} is out of range (must be {} {lo})", if self.exclusive_min { "above" } else { "at least" }));
                    }
                }
                if let Some(hi) = self.max {
                    if x > hi {
                        return Err(format!("{x} is out of range (at most {hi})"));
                    }
                }
                if self.kind == Kind::Integer {
                    return int_of(Some(v)).map(Value::from).ok_or_else(|| format!("{x} is not a whole number"));
                }
                Ok(v.clone())
            }
            Kind::Strings => match v.as_array() {
                Some(a) if a.iter().all(Value::is_string) => Ok(v.clone()),
                _ => Err(format!("expected a list of strings, got {v}")),
            },
            Kind::Object => v.is_object().then(|| v.clone()).ok_or_else(|| format!("expected an object, got {v}")),
            Kind::Schedule => Schedule::from_json(v)
                .map(|_| v.clone())
                .ok_or_else(|| format!("expected {{start, end, days}} with HH:MM times, got {v}")),
            Kind::Choice => match v.as_str() {
                Some(s) if self.choices.contains(&s) => Ok(v.clone()),
                _ => Err(format!("expected one of {}, got {v}", self.choices.join(", "))),
            },
            Kind::Text => v.is_string().then(|| v.clone()).ok_or_else(|| format!("expected text, got {v}")),
        }
    }
}

/// A key the agent refused, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub key: String,
    pub reason: String,
}

/// The keys of one section.
pub fn defs(section: Section) -> impl Iterator<Item = &'static Def> {
    DEFS.iter().filter(move |d| d.section == section)
}

pub fn def(key: &str) -> Option<&'static Def> {
    DEFS.iter().find(|d| d.key == key)
}

/// A section's complete defaults: what the agent applies before it hears from the coordinator.
pub fn defaults(section: Section) -> Value {
    Value::Object(defs(section).map(|d| (d.key.to_string(), d.default_value())).collect())
}

/// Check a section the coordinator sent: (the section as applied, the keys refused). A refused or missing key keeps
/// `previous`'s value (the last applied, or the defaults); a key this agent does not know is refused and not applied.
pub fn validate(section: Section, incoming: &Value, previous: &Value) -> (Value, Vec<Rejected>) {
    let mut out = Map::new();
    let mut rejected = vec![];
    let empty = Map::new();
    let inc = incoming.as_object().unwrap_or(&empty);
    if !incoming.is_object() {
        rejected.push(Rejected { key: format!("{section:?}").to_lowercase(), reason: format!("expected an object, got {incoming}") });
    }
    for d in defs(section) {
        let keep = || previous.get(d.key).cloned().unwrap_or_else(|| d.default_value());
        let v = match inc.get(d.key) {
            None => {
                if incoming.is_object() {
                    rejected.push(Rejected { key: d.key.into(), reason: "missing from the coordinator's settings".into() });
                }
                keep()
            }
            Some(v) => match d.check(v) {
                Ok(v) => v,
                Err(reason) => {
                    rejected.push(Rejected { key: d.key.into(), reason });
                    keep()
                }
            },
        };
        out.insert(d.key.into(), v);
    }
    for k in inc.keys().filter(|k| def(k).is_none_or(|d| d.section != section)) {
        rejected.push(Rejected { key: k.clone(), reason: "not a setting this agent version knows".into() });
    }
    (Value::Object(out), rejected)
}
