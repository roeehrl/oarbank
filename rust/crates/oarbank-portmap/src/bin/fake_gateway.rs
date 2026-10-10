//! A fake NAT-PMP, PCP and UPnP gateway on loopback, for end-to-end tests (built only with the `fake` feature, never
//! shipped). It prints its addresses as one JSON line, then reads commands, one JSON object per line:
//! `{"op": "reboot"}`, `{"op": "config", ...FakeConfig fields}`, `{"op": "foreign", "port", "client", "internal_port",
//! "description"}`, `{"op": "external", "ip", "announce": "127.0.0.1:P"}`, `{"op": "mappings"}` (prints the mappings,
//! pinholes and deletes), `{"op": "quit"}`.

use oarbank_portmap::fake::{FakeConfig, FakeGateway};
use serde_json::{json, Value};
use std::io::BufRead;

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("runtime");
    rt.block_on(async {
        let cfg: FakeConfig = std::env::args().nth(1).and_then(|a| serde_json::from_str(&a).ok()).unwrap_or_default();
        let gw = FakeGateway::start(cfg).await.expect("fake gateway");
        println!("{}", json!({"pmp": gw.pmp.to_string(), "ssdp": gw.ssdp.to_string(), "http": gw.http.to_string(),
                              "pcp_v6": gw.pcp_v6.map(|a| a.to_string())}));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        std::thread::spawn(move || {
            for l in std::io::stdin().lock().lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        while let Some(line) = rx.recv().await {
            let Ok(c) = serde_json::from_str::<Value>(&line) else { continue };
            match c["op"].as_str() {
                Some("reboot") => gw.reboot(),
                Some("config") => {
                    let mut cur = serde_json::to_value(gw.with(|s| s.cfg.clone())).unwrap_or_default();
                    if let (Some(o), Some(n)) = (cur.as_object_mut(), c.as_object()) {
                        for (k, v) in n.iter().filter(|(k, _)| *k != "op") {
                            o.insert(k.clone(), v.clone());
                        }
                    }
                    if let Ok(cfg) = serde_json::from_value::<FakeConfig>(cur) {
                        gw.with(|s| s.cfg = cfg);
                    }
                }
                Some("foreign") => {
                    let client = c["client"].as_str().and_then(|s| s.parse().ok()).unwrap_or([192, 168, 1, 31].into());
                    gw.with(|s| s.add_foreign(c["port"].as_u64().unwrap_or(0) as u16, client, c["internal_port"].as_u64().unwrap_or(0) as u16,
                                              c["description"].as_str().unwrap_or("another device"), None));
                }
                Some("external") => {
                    if let Some(ip) = c["ip"].as_str().and_then(|s| s.parse().ok()) {
                        gw.set_external(ip, c["announce"].as_str().and_then(|s| s.parse().ok())).await;
                    }
                }
                Some("mappings") => {
                    let v = gw.with(|s| json!({"mappings": s.mappings, "pinholes": s.pinholes, "deletes": s.deletes, "requests": s.requests,
                                               "epoch": s.epoch(), "external": s.external.to_string()}));
                    println!("{v}");
                }
                Some("quit") => break,
                _ => {}
            }
        }
    });
}
