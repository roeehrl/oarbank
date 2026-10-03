//! Lenient accessors over `serde_json::Value` with the agent's wire semantics: a wrong type reads as
//! missing, an integral double is an integer, and `null` versus missing stays under the caller's control.

use serde_json::{Map, Number, Value};

/// `v[k]` when `v` is an object.
pub(crate) fn get<'a>(v: Option<&'a Value>, k: &str) -> Option<&'a Value> {
    v.and_then(|v| v.as_object()).and_then(|o| o.get(k))
}

pub(crate) fn f64_of(v: Option<&Value>) -> Option<f64> {
    v.and_then(|v| v.as_f64())
}

/// An integer, or a finite integral double below 9e15.
pub(crate) fn int_of(v: Option<&Value>) -> Option<i64> {
    let n = v?.as_number()?;
    if let Some(i) = n.as_i64() {
        return Some(i);
    }
    if n.is_u64() {
        return None;
    }
    let d = n.as_f64()?;
    (d.is_finite() && d.round() == d && d.abs() < 9e15).then_some(d as i64)
}

pub(crate) fn str_of(v: Option<&Value>) -> Option<&str> {
    v.and_then(|v| v.as_str())
}

pub(crate) fn bool_of(v: Option<&Value>) -> Option<bool> {
    v.and_then(|v| v.as_bool())
}

pub(crate) fn is_object(v: Option<&Value>) -> bool {
    v.is_some_and(|v| v.is_object())
}

pub(crate) fn is_null(v: Option<&Value>) -> bool {
    v.is_some_and(|v| v.is_null())
}

/// A number rounded to `places` decimals for compact telemetry (non-finite: null).
pub fn rounded(x: f64, places: i32) -> Value {
    if !x.is_finite() {
        return Value::Null;
    }
    let m = 10f64.powi(places);
    num((x * m).round() / m)
}

pub(crate) fn num(x: f64) -> Value {
    Number::from_f64(x)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

pub(crate) fn opt_num(x: Option<f64>) -> Value {
    x.map(num).unwrap_or(Value::Null)
}

pub(crate) fn opt_int(x: Option<i64>) -> Value {
    x.map(Value::from).unwrap_or(Value::Null)
}

pub(crate) fn opt_str(x: Option<&str>) -> Value {
    x.map(Value::from).unwrap_or(Value::Null)
}

pub(crate) fn strings(xs: &[String]) -> Value {
    Value::Array(xs.iter().map(|s| Value::from(s.as_str())).collect())
}

/// Build an object from (key, value) pairs.
pub(crate) fn obj<I: IntoIterator<Item = (&'static str, Value)>>(pairs: I) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}
