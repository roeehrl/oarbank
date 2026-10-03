//! The per-job egress proxy for `net.mode = "egress-allowlist"` (spec/sandbox.md, "Network"; the SDK's
//! `egress_proxy` is the reference). The job's sandbox lets it reach only this proxy's port; the proxy lets through
//! only the module's approved hosts, refuses IP literals, and refuses a name resolving to any address that is not
//! public (loopback, link-local, private, multicast), so a DNS answer cannot turn an allowed name into a local service.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct Proxy {
    pub port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn start(allow: Vec<String>) -> std::io::Result<Proxy> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let port = l.local_addr()?.port();
    let allow = Arc::new(allow);
    let task = tokio::spawn(async move {
        while let Ok((c, _)) = l.accept().await {
            let allow = allow.clone();
            tokio::spawn(async move {
                let _ = serve(c, &allow).await;
            });
        }
    });
    Ok(Proxy { port, task })
}

async fn deny(mut c: TcpStream, why: String) -> std::io::Result<()> {
    tracing::info!(why = %why, "egress proxy refused a connection");
    c.write_all(format!("HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{why}", why.len()).as_bytes()).await
}

async fn resolve_public(host: &str, port: u16) -> Result<SocketAddr, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await.map_err(|e| e.to_string())?.collect();
    if addrs.is_empty() {
        return Err(format!("{host}: no address"));
    }
    for a in &addrs {
        if !oarbank_core::egress::is_global(a.ip()) || a.ip().is_multicast() {
            return Err(format!("{host} resolves to {}, which is not a public address", a.ip()));
        }
    }
    Ok(addrs[0])
}

async fn serve(mut c: TcpStream, allow: &[String]) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut buf = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16384 {
        let n = c.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let line = text.split("\r\n").next().unwrap_or("");
    let mut parts = line.split(' ');
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let end = head.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(head.len());
    let (host, port, rest, connect) = if method == "CONNECT" {
        let (h, p) = target.rsplit_once(':').unwrap_or((target, "443"));
        (h.trim_matches(['[', ']']).to_string(), p.parse().unwrap_or(443), head[end..].to_vec(), true)
    } else if let Some(t) = target.strip_prefix("http://") {
        let hp = t.split('/').next().unwrap_or("");
        let (h, p) = hp.split_once(':').unwrap_or((hp, "80"));
        (h.to_string(), p.parse().unwrap_or(80), head.clone(), false)
    } else {
        return deny(c, "only CONNECT and absolute http:// requests".into()).await;
    };
    if !oarbank_core::egress::allowed(allow, &host, port) {
        return deny(c, format!("{host}:{port} is not in the module's allow list")).await;
    }
    let addr = match resolve_public(&host, port).await {
        Ok(a) => a,
        Err(e) => return deny(c, e).await,
    };
    let mut up = match TcpStream::connect(addr).await {
        Ok(u) => u,
        Err(e) => return deny(c, format!("{host}:{port}: {e}")).await,
    };
    if connect {
        c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    }
    if !rest.is_empty() {
        up.write_all(&rest).await?;
    }
    tokio::io::copy_bidirectional(&mut c, &mut up).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refuses_hosts_outside_the_list_ip_literals_and_local_names() {
        let p = start(vec!["api.example.org".into(), "localhost:9".into()]).await.unwrap();
        for target in ["evil.example.org:443", "127.0.0.1:9", "localhost:9"] {
            let mut s = TcpStream::connect(("127.0.0.1", p.port)).await.unwrap();
            s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await.unwrap();
            let mut b = vec![0u8; 512];
            let n = s.read(&mut b).await.unwrap();
            assert!(String::from_utf8_lossy(&b[..n]).starts_with("HTTP/1.1 403"), "{target}");
        }
    }
}
