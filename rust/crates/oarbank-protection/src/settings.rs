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

/// Which way a safety key is stricter (a boolean: off < on; a choice: its `choices` order; none, an unset cap or no
/// bound, is the loosest value). A machine's managed policy may only move a key this way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tighten {
    None,
    Lower,
    Higher,
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
    /// The stricter direction (a safety key), or `Tighten::None` (a preference).
    pub tighten: Tighten,
    /// A machine's managed policy may set it, tighten-only (docs/design/settings.md, "Managed on this machine").
    pub managed: bool,
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

/// A key a machine's managed policy sets (docs/design/settings.md, "Managed on this machine"): the value it names, and
/// whether it binds (it is stricter than what the coordinator sent, so it is what applies).
#[derive(Debug, Clone, PartialEq)]
pub struct Managed {
    pub key: String,
    pub value: Value,
    pub binding: bool,
}

/// `b` is strictly stricter than `a` on `d`'s scale (a boolean: off < on; a choice: its `choices` order; null, an unset
/// cap or no bound, the loosest of all). A preference (`Tighten::None`) has no scale: nothing is stricter.
fn stricter(d: &Def, a: &Value, b: &Value) -> bool {
    let rank = |v: &Value| match v {
        Value::Bool(x) => Some(f64::from(u8::from(*x))),
        Value::Number(n) => n.as_f64(),
        Value::String(s) => d.choices.iter().position(|c| c == s).map(|i| i as f64),
        _ => None,
    };
    match (d.tighten, rank(a), rank(b)) {
        (Tighten::None, ..) | (_, _, None) => false,
        (_, None, Some(_)) => true,
        (Tighten::Lower, Some(x), Some(y)) => y < x,
        (Tighten::Higher, Some(x), Some(y)) => y > x,
    }
}

/// The stricter of two values of `d` (equal strictness, or a preference: `a`).
pub fn tighter(d: &Def, a: &Value, b: &Value) -> Value {
    if stricter(d, a, b) { b.clone() } else { a.clone() }
}

/// A managed value converted to the key's kind, then checked. Profiles and registry policies carry what their tools
/// write: a boolean as 0/1 or "true", a decimal as text ("1.5"), so the conversion is lenient; the check is not.
pub fn coerce_managed(d: &Def, v: &Value) -> Result<Value, String> {
    let c = match (d.kind, v) {
        (Kind::Bool, Value::Number(n)) => match n.as_f64() {
            Some(x) if x == 0.0 => Value::Bool(false),
            Some(x) if x == 1.0 => Value::Bool(true),
            _ => v.clone(),
        },
        (Kind::Bool, Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Value::Bool(true),
            "false" | "0" | "no" => Value::Bool(false),
            _ => v.clone(),
        },
        (Kind::Number | Kind::Integer, Value::String(s)) => {
            let t = s.trim();
            t.parse::<i64>().map(Value::from).ok()
                .or_else(|| t.parse::<f64>().ok().and_then(serde_json::Number::from_f64).map(Value::Number))
                .unwrap_or_else(|| v.clone())
        }
        _ => v.clone(),
    };
    d.check(&c)
}

const NOT_MANAGEABLE: &str = "not a setting managed policy may set";

/// Lay a machine's managed settings over one section as applied from the coordinator: each managed key of this
/// section can only tighten it. Returns (the section in force, the managed keys of this section, the ones refused: a
/// key managed policy may not set, or a value that is not valid for it). Keys of the other section are left to its
/// call, and keys of neither to [`unknown_managed`], so each refusal is reported once.
pub fn apply_managed(section: Section, applied: &Value, managed: &Map<String, Value>) -> (Value, Vec<Managed>, Vec<Rejected>) {
    let mut out = applied.as_object().cloned().unwrap_or_default();
    let (mut set, mut refused) = (vec![], vec![]);
    for (k, v) in managed {
        let Some(d) = def(k).filter(|d| d.section == section) else { continue };
        if !d.managed {
            refused.push(Rejected { key: k.clone(), reason: NOT_MANAGEABLE.into() });
            continue;
        }
        match coerce_managed(d, v) {
            Err(reason) => refused.push(Rejected { key: k.clone(), reason }),
            Ok(m) => {
                let current = out.get(d.key).cloned().unwrap_or_else(|| d.default_value());
                let binding = stricter(d, &current, &m);
                if binding {
                    out.insert(d.key.into(), m.clone());
                }
                set.push(Managed { key: k.clone(), value: m, binding });
            }
        }
    }
    (Value::Object(out), set, refused)
}

/// The managed keys no section knows, refused.
pub fn unknown_managed(managed: &Map<String, Value>) -> Vec<Rejected> {
    managed.keys().filter(|k| def(k).is_none()).map(|k| Rejected { key: k.clone(), reason: NOT_MANAGEABLE.into() }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn d(key: &str) -> &'static Def {
        def(key).unwrap()
    }

    #[test]
    fn the_stricter_value_wins_each_way() {
        assert_eq!(tighter(d("jobs"), &json!(4), &json!(2)), json!(2));            // Lower: smaller is stricter
        assert_eq!(tighter(d("jobs"), &json!(2), &json!(4)), json!(2));
        assert_eq!(tighter(d("os_reserve_gb"), &json!(4), &json!(8)), json!(8));   // Higher: larger
        assert_eq!(tighter(d("os_reserve_gb"), &json!(8), &json!(4.5)), json!(8));
        assert_eq!(tighter(d("run_on_battery"), &json!(true), &json!(false)), json!(false));   // Lower: off is stricter
        assert_eq!(tighter(d("hard_limits"), &json!(false), &json!(true)), json!(true));       // Higher: on
        assert_eq!(tighter(d("enforce"), &json!("soft"), &json!("hard")), json!("hard"));      // choices order
        assert_eq!(tighter(d("enforce"), &json!("hard"), &json!("soft")), json!("hard"));
        assert_eq!(tighter(d("mem_gb"), &json!(null), &json!(16)), json!(16));     // an unset cap is the loosest
        assert_eq!(tighter(d("mem_gb"), &json!(16), &json!(null)), json!(16));
        assert_eq!(tighter(d("jobs"), &json!(2), &json!(2.0)), json!(2));          // equal: the first
        assert_eq!(tighter(d("nice"), &json!(10), &json!(19)), json!(10));         // a preference has no scale
    }

    #[test]
    fn managed_values_are_converted_leniently_and_checked() {
        assert_eq!(coerce_managed(d("run_on_battery"), &json!(0)), Ok(json!(false)));
        assert_eq!(coerce_managed(d("run_on_battery"), &json!("Yes")), Ok(json!(true)));
        assert_eq!(coerce_managed(d("os_reserve_gb"), &json!("1.5")), Ok(json!(1.5)));
        assert_eq!(coerce_managed(d("jobs"), &json!("3")), Ok(json!(3)));
        assert_eq!(coerce_managed(d("enforce"), &json!("hard")), Ok(json!("hard")));
        assert!(coerce_managed(d("run_on_battery"), &json!(2)).is_err());
        assert!(coerce_managed(d("jobs"), &json!("1.5")).is_err());                 // not a whole number
        assert!(coerce_managed(d("jobs"), &json!(0)).is_err());                     // below the minimum
        assert!(coerce_managed(d("enforce"), &json!("strict")).is_err());
    }

    #[test]
    fn managed_settings_only_tighten() {
        let mut applied = defaults(Section::Limits);
        applied["jobs"] = json!(2);
        let managed = json!({"jobs": 4, "mem_gb": "16", "enforce": "hard", "schedule": null, "cpu_cores": "lots",
                             "run_on_battery": true, "nonsense": 1});
        let (out, set, refused) = apply_managed(Section::Limits, &applied, managed.as_object().unwrap());
        assert_eq!((&out["jobs"], &out["mem_gb"], &out["enforce"]), (&json!(2), &json!(16), &json!("hard")));
        assert_eq!(out["cpu_cores"], json!(null));
        assert_eq!(set, vec![
            Managed { key: "jobs".into(), value: json!(4), binding: false },
            Managed { key: "mem_gb".into(), value: json!(16), binding: true },
            Managed { key: "enforce".into(), value: json!("hard"), binding: true },
        ]);
        let keys: Vec<&str> = refused.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, ["schedule", "cpu_cores"]);                                // not manageable; invalid
        assert_eq!(refused[0].reason, NOT_MANAGEABLE);
        // the policy section's keys are its own call's; a key of neither is refused once, by unknown_managed
        let (_, set, refused) = apply_managed(Section::Policy, &defaults(Section::Policy), managed.as_object().unwrap());
        assert_eq!((set.len(), set[0].binding, refused.len()), (1, false, 0));      // run_on_battery true: looser
        assert_eq!(unknown_managed(managed.as_object().unwrap()), vec![Rejected { key: "nonsense".into(), reason: NOT_MANAGEABLE.into() }]);
    }
}
