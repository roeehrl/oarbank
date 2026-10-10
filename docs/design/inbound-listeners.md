# Inbound listeners: a module accepts connections from the internet

Status: built in **core 2.10** and **oarbank-sdk 1.6** (PLAN D47, D48, D49; invariant S24). See Implementation status
at the end for what the build adds to the design and what remains to verify on real routers.

## The problem

Some workloads must accept connections from the internet: a node of a peer-to-peer network that publishes its address
(on a chain, in a registry), a public inference endpoint, a relay. Oarbank had no inbound path at all, by design:
module processes never listen (seccomp refuses `listen`, Seatbelt has no bind rule, an AppContainer has no server
capability, and the conformance kit fails a service that listens), agents are outbound-only, and nothing in the agent
spoke UPnP, NAT-PMP or PCP. Home networks add the rest of the problem: the machine sits behind a router (sometimes two),
its public address may change, routers reboot and forget their mappings, and the router's port-mapping support ranges
from good to buggy to absent.

## The decisions

- **D47, inbound listeners.** The **agent** owns every listener. It accepts TCP connections on the node and relays the
  bytes of each one to the module through the existing endpoint channel (service-endpoints.md): the module gets one
  end of a fresh connected pair, exactly like a connection from a job, and the agent copies bytes between the TCP socket
  and its own end. Module code still never listens, binds or holds an internet socket. A listener exists on a node only
  when all of these hold:
  1. the module version's `[sandbox].net.inbound` entry is approved by digest (a new top-risk grant);
  2. the owner assigned it to the node: the node's **owner-signed statement** lists `<module>/<listener>` with its
     external port policy (for a listener served by a workload, D45, the workload's assignment to the node is required
     as well);
  3. the module is enabled on the node, a running endpoint service (or workload) of the module lists the listener;
  4. no kill switch is engaged (`listeners.disable` for the node or the fleet), the machine's managed policy does not
     forbid listeners (`inbound_listeners = false`), and the node's protection mode is not `strict_yield` (a node that
     yields completely would hold an open port nobody answers).

  A compromised coordinator therefore cannot open a port: it cannot sign a statement (signing mode), and the managed
  policy key cannot be overridden from it.
- **D48, port mapping.** The agent maps its own listeners on the router with **PCP** (RFC 6887), **NAT-PMP** (RFC
  6886) and **UPnP IGD** v1 and v2, probed in that order of preference. Leases are short and renewed early (PCP and
  NAT-PMP 2 hours, UPnP 1 hour, renewed at half life, PCP at a random point between 1/2 and 5/8); every request is
  written to a **write-ahead journal** before it is sent; every mapping is verified; a router reboot (epoch reset), a
  change of the public address, a change of network and a sleep and wake each lead to re-mapping; conflicts follow a
  deterministic policy; mappings are removed when the listener goes, when the agent stops, when Oarbank is uninstalled
  and when the node is retired. The agent never maps a port for another address, never maps a port below 1024, and
  **never deletes a mapping it did not make**. Manual forwarding by the owner is a first-class mode, not an error.
- **D49, reachability probe.** Reachability is proven by a **dial-back from outside**: by default a fleet node on
  another network (the coordinator picks one whose public address differs), else an endpoint the owner runs
  (`oarbank-agent probe-endpoint`); a third-party service (a public STUN server, for the address check only) is used
  only if the owner names one. The prober dials only the address the node's own router reported for the listener, never
  a host a module names; the probe carries a random id and the listener answers it itself with a secret nonce only the
  target node knows, so the probe never reaches the module and an echo server cannot fake success.

Rejected: passing the accepted TCP socket to the module (`SCM_RIGHTS`, `WSADuplicateSocket`). Zero copy, but whether
Seatbelt and an AppContainer let a confined process use an inherited internet socket without a network grant is
unverified, and the agent would lose the byte limits and idle timeouts it enforces while relaying. Relaying costs one
copy, which is irrelevant at the bandwidths of these workloads. Rejected: a relay node inside the fleet for unreachable
nodes (deferred: several earning networks treat many workers behind one address as related, and a relay node becomes a
single point of failure and a target). Rejected: Tailscale Funnel and Cloudflare Tunnel (HTTPS on a hostname only;
useless for protocols that publish an IP address and a port).

## The manifest (SDK)

```toml
[sandbox]
net = { mode = "egress-any" }

[[sandbox.net.inbound]]
name = "peer"
port_hint = 9000
port_policy = "stable"
max_conns = 256
max_conns_per_ip = 16
new_conns_per_ip_per_s = 4
idle_timeout_s = 120

[[services]]
name = "node"
exec = ["python", "-I", "{bundle}/node_service.py"]
lifecycle = "always"
endpoint = true
listeners = ["peer"]                  # connections to the `peer` listener arrive on this service's endpoint channel
```

`[sandbox].net.inbound` (each entry; manifest rule 22, errors in `oarbank-sdk check`, at install and in the catalogue):

| Key | Values | Meaning |
|---|---|---|
| `name` | `^[a-z][a-z0-9_]*$`, unique | the listener's name; the node statement and every report call it `<module>/<name>` |
| `protocol` | `tcp` | TCP only. UDP is designed for (the same lifecycle) but not built: forwarding UDP through the agent needs a per-flow table and brings amplification questions |
| `port_hint` | 1024–65535, optional | the external port the module would like; the owner decides the real one per node |
| `port_policy` | `stable` (default), `flexible` | `stable`: the external port is published somewhere costly to change (a chain, a registry), so a port someone else holds is refused rather than replaced; `flexible`: the agent may take the next free port of a small range. It sets the default `fallback` (below); the owner may override it per node |
| `tls` | `passthrough` (default), `none` | the agent relays bytes untouched; the workload terminates its own TLS if any. Termination in the agent is not built (it needs certificates, and an IP-addressed endpoint has no name to certify) |
| `handover` | `connections` (default), `listen_fd` | `connections`: each connection arrives on the endpoint channel (all OSes). `listen_fd` (macOS and Linux): the agent passes the service an inherited, already-listening unix socket it made, for third-party servers that serve on an inherited socket (below) |
| `proxy_protocol` | bool, default false (true with `listen_fd`) | the agent writes a PROXY protocol v2 header before the first byte of each connection; otherwise the client's address arrives in the `connection` message only (with `listen_fd` there is no message, so the header is the only way a server learns it) |
| `max_conns` | 1–65535, default 256 | open connections at once |
| `max_conns_per_ip` | 1–65535, default 16 | open connections at once from one client address (IPv6: per /64) |
| `new_conns_per_ip_per_s` | > 0, default 4 | new connections per second from one client address (a token bucket with a burst of twice the rate) |
| `idle_timeout_s` | 1–86400, default 120 | a connection with no bytes either way for this long is closed |
| `max_bytes_per_s` | > 0, optional | a byte-rate cap per listener, both directions together |

The limits are the module's ceilings. The owner may lower each of them per node (statement, below), never raise them.

Rules:
1. A listener needs exactly one endpoint service (or workload) of the module that lists it in `listeners`; a name in
   a service's `listeners` must be an `inbound` entry.
2. A service with `listeners` is an endpoint service (`endpoint = true`) with `lifecycle = "always"`: a listener is
   wanted for as long as the module is enabled on the node, so its service runs that long. An endpoint service needs at
   least one pool **or** at least one listener (service-endpoints.md rule 1 is relaxed accordingly).
3. `inbound` and `services[].listeners` need `requires.core >= 2.10` (rule 12's table gains a 2.10 row).
4. `inbound` is a node-side grant: it is part of the version's sandbox requests, approved by digest, and shown at
   approval as "accepts connections from the internet on nodes the owner assigns: listener peer (TCP, port 9000 wanted,
   stable; at most 256 connections, 16 per address, 4 new a second per address, idle 120 s)".

`inbound` does not need an egress mode: answering on an accepted connection is not egress. `egress-any` is needed only
when the workload also dials out to arbitrary peers.

## The owner's configuration on the node (statement)

The node statement (`oarbank.node/v1`, docs/protocol.md "Node statement") gains `listeners`, signed with the rest:

```json
"listeners": {"mymodule/peer": {"external_port": 9000, "fallback": "refuse", "mapping": "auto", "ipv6": "auto",
                                "bind": "default_route", "internal_port": null,
                                "limits": {"max_conns": 64}, "allow": ["198.51.100.0/24"]}}
```

| Key | Values | Default | Meaning |
|---|---|---|---|
| `external_port` | 1024–65535 | the manifest's `port_hint`, else the internal port | the port to ask the router for |
| `fallback` | `refuse`, `next_free:<a>-<b>`, `router_choice` | `refuse` for `port_policy = "stable"`, `next_free:<p>-<p+15>` for `flexible` | what happens when the router says the port is taken: `refuse` stops and reports `PORT_TAKEN` with the router's account of who holds it; `next_free` walks the range in order and takes the first port that maps and verifies (the same inputs always give the same port, so a restart lands on the same one while it is free); `router_choice` takes the port the router assigns (IGDv2 `AddAnyPortMapping`, NAT-PMP and PCP substitution) |
| `mapping` | `auto`, `pcp`, `natpmp`, `upnp`, `manual`, `none` | `auto` | `auto` probes PCP, NAT-PMP and UPnP; `manual`: the owner forwarded the port on the router by hand, the agent only verifies reachability; `none`: the machine has a public address and nothing is mapped |
| `ipv6` | `auto`, `off` | `auto` | `auto`: when the node has a global IPv6 address on the default route, the listener also accepts on it and asks the router for an IPv6 pinhole (PCP, or IGDv2 `WANIPv6FirewallControl`) |
| `bind` | `default_route`, an IP address | `default_route` | the address the listener binds: the node's address on the default route (re-bound when the network changes), or a literal address |
| `internal_port` | 1024–65535, or null | null | the port the agent binds; null: a port derived from the listener's name in the node's internal range (`listener_port_range`, default 41000–41999), the same on every start while it is free. Set it when forwarding by hand, so the forward never moves |
| `limits` | any of the manifest's limit keys | the manifest's | per-node lowering of the module's ceilings; a value above the manifest's is refused (the manifest's applies) |
| `allow` | CIDRs | none (everyone) | only these client addresses may connect |

The statement entry is the owner's assignment of the listener to the node: no entry, no listener. Operation
`listeners.configure` (T2, admin) adds or changes an entry, `listeners.remove` (T1) removes it; either rebuilds the
statement, which the owner signs in signing mode (`oarbank node sign <node>`) before the node applies it.

## The data path (agent)

1. **Bind.** The agent binds the internal port on the chosen address (never the wildcard) and, with IPv6 on, a second
   socket on the node's global IPv6 address: on the external port when it is free locally (IPv6 has no translation, so
   the address the world dials is the node's own), else on the internal port.
2. **Accept**, then in order: the kill switch, the allowlist (the owner's `allow` intersected with the module's
   narrowing, below), the per-address token bucket and connection cap, the listener's cap. A refused connection is
   closed at once and counted by reason.
3. **Probes.** While a dial-back is expected for the listener (D49), the agent reads the first bytes of each new
   connection for at most 2 s; a probe (the magic `OARBANK-PROBE/1 ` and the probe id, a line) is answered by the agent
   itself and closed. Any other bytes are kept and relayed first, so a client that speaks first loses nothing. With no
   probe expected, connections go straight through. A probe that arrives from the node's own network (a private,
   loopback or link-local source, or the node's own external address through a hairpinning router) proves nothing; the
   listener answers it with `OARBANK-PROBE/1 SAME <nonce>`, and the prober reports `same_network`.
4. **Hand-over** (`handover = "connections"`). The agent makes a connected pair, sends the module's end on the endpoint channel as
   `{"op": "connection", "conn": n, "listener": "peer", "peer": "203.0.113.5:51000"}` (no `attempt`), and relays bytes
   between the TCP socket and its own end, with the idle timeout and the byte-rate cap. With `proxy_protocol`, the first
   bytes the module reads are a PROXY v2 header with the client's address and the address the agent accepted on.
   **Socket activation** (`handover = "listen_fd"`, macOS and Linux). Many third-party servers cannot take connections
   from an Oarbank channel but can serve on an inherited listening socket (uvicorn's `--fd`, the systemd `LISTEN_FDS`
   convention of many Go and Rust servers). The agent creates a unix socket in a directory only its own account can
   enter, calls `listen` on it itself, and passes the listening descriptor to the service's `start` (inherited by what
   `start` leaves running, as the endpoint channel is) in `OARBANK_LISTEN_FD_<NAME>=fd:<n>`; for each accepted TCP
   connection the agent connects to that socket and relays bytes. The service only calls `accept`, which its sandbox
   allows; `listen` and `bind` stay refused for module code (checked before building: under the deny-default Seatbelt
   profile a service accepts on such an inherited socket and is refused its own unix and TCP listening sockets with
   `EPERM`; Linux seccomp refuses `listen`, not `accept`). The SDK's `exec_with_listen_fds` moves the sockets to
   descriptors 3 and up and sets `LISTEN_FDS`, `LISTEN_FDNAMES` and `LISTEN_PID` before it executes a server that
   follows the systemd convention. Windows has no equivalent for its pipes: there a `listen_fd` listener is refused
   (`LISTENER_HANDOVER_UNSUPPORTED`) and `oarbank-sdk check` warns about it for a module that supports Windows.
5. **Narrowing by the module.** The service may send `{"op": "listener_allow", "listener": "peer", "cidrs": [...]}` (a
   list of validators, say): the agent intersects it with the owner's allowlist; a module can only ever narrow. `cidrs:
   null` drops the module's narrowing; `"append": true` adds to the list instead of replacing it (lines stay under 4096
   bytes, so a long list arrives in several messages).
6. **Announcements.** The agent writes `OARBANK_LISTENERS_FILE` (JSON, `{name: announcement}`) before the service
   starts and sends `{"op": "listener", "name": "peer", "external": "198.51.100.7:9000", "external_v6":
   "[2001:db8::7]:9000", "state": "...", "since": <unix time>}` on the channel after hello and on every change. `state`
   is `unmapped` (no mapping yet, or it failed), `mapped_unverified` (the router holds the mapping; no dial-back has
   confirmed it yet, or no prober is available), `reachable` (a dial-back succeeded at this address) or `unreachable`
   (the mapping verified but a dial-back failed). A workload that publishes its address re-publishes it when
   `external` changes (respecting its network's own rate limits). The agent never announces `reachable` or
   `mapped_unverified` for longer than one verify interval while the router holds no mapping (TLA+
   `AnnouncedImpliesMapped`).
7. **The service's state.** While the service runs and has said hello, connections are relayed. While it is starting,
   restarting or held down by host protection, the listener stays bound and its mapping stays in place, but new
   connections are closed at once (`held`), so a quick return needs no re-mapping. When the listener is no longer
   wanted (entry removed, module disabled, version without the grant, kill switch, managed policy), the listener closes
   and its mapping is removed.

## Port mapping

One lifecycle per listener and address family, run by the agent's port-mapping manager:

```text
            ┌──────────── network change / wake / gateway change ─────────────┐
            v                                                                  │
  Idle ─► Probing ─► Requesting ─► Mapped(lease, until) ─► Renewing ─► Mapped ─┘
            │            │              │   │                  │
            │            │              │   └ verify fails / epoch reset / external address change ─► Requesting
            │            ├ conflict ─► (next_free: next port) ─► Requesting   (refuse: PortTaken, owner told)
            │            └ refused (606, 729, not authorized) ─► Unmappable (doctor result, retried with backoff)
            └ no gateway answers ─► Unmappable (retried with backoff)
  Any ─► Removing (listener gone, agent stop, uninstall, retire) ─► Removed (journal cleared)
```

- **Discovery.** NAT-PMP and PCP talk to the default gateway on UDP 5351 (`ANNOUNCE` for PCP, the external-address
  request for NAT-PMP, 250 ms then 500 ms). UPnP searches with SSDP for `InternetGatewayDevice:2` and `:1`, preferring
  IGD:2 and `WANIPConnection:2` over `:1` over `WANPPPConnection:1` (igd-next); a device whose description sits on
  another address than the default gateway is used only when no gateway-addressed device answers. In `auto`, a gateway
  that answers PCP is used with PCP, else NAT-PMP, else UPnP; a protocol that answers but refuses the request (not
  authorized, PCP `NOT_AUTHORIZED`, UPnP 606) falls through to the next. A positive probe is trusted for 10 minutes, a
  negative one is retried with a backoff from 5 s to 10 minutes.
- **Request.** The intended mapping is written to the journal (`<home>/state/portmaps.json`: protocol, gateway,
  external and internal address and port, PCP nonce, UPnP control URL and the description
  `oarbank:<node-id prefix>:<module>/<listener>`) **before** the request goes out, then requested. PCP uses
  `PREFER_FAILURE` when `fallback = refuse`. The port the gateway assigned (NAT-PMP, PCP, `AddAnyPortMapping`) is read
  back and recorded.
- **Verify.** UPnP: `GetSpecificPortMappingEntry` after every add and every 5 minutes, checking the internal client,
  internal port and description. NAT-PMP and PCP: the response is the verification, plus the epoch check on every
  renewal. A verify that fails makes the mapping lost at once: the module is told `unmapped`, and the agent requests
  again.
- **Renew.** NAT-PMP at half life; PCP at a random point between 1/2 and 5/8 of the lifetime, with the same nonce; UPnP
  leases of 3600 s at half life. A router that accepts only permanent mappings (UPnP 725, or 402 for a non-zero lease)
  gets lease 0; the journal entry is marked `permanent`, the mapping is deleted on every stop and at the next start, and
  the owner sees `PERMANENT_ONLY_ROUTER` in advance: a crashed or uninstalled agent could leave such a mapping until it
  starts again.
- **Recover.** Epoch reset (PCP, NAT-PMP: the router's seconds-since-start more than 2 s below what the last answer
  predicts) means the router lost its state: re-map at once. A change of the external address (NAT-PMP and PCP
  announcements on UDP 5350, a PCP or NAT-PMP response, UPnP `GetExternalIPAddress`, the STUN check when the owner turned
  it on): update, announce, and have reachability checked again. A network change (the default gateway, the node's
  address on the default route or its global IPv6 address changed; checked every 5 s) and a wake from sleep (a jump
  between the monotonic and the wall clock): the old mappings are invalidated without being released (the old gateway
  may be gone), the agent probes and maps again, and it releases the old mapping on the old gateway if that gateway is
  still the default (Wi-Fi to Ethernet on one LAN changes the internal address: the old mapping points at an address
  the node no longer has).
- **Conflicts.** UPnP 718 `ConflictInMappingEntry`, a NAT-PMP or PCP substitution, or `CANNOT_PROVIDE_EXTERNAL`
  follow the listener's `fallback`. With `refuse`, the listener's mapping stops with `PORT_TAKEN` and the router's
  account of who holds the port (UPnP lists the internal client). With `next_free`, the next port of the range. With
  `router_choice`, the assigned port. The module is told the external port either way.
- **Cleanup.** A mapping is deleted when its listener is no longer wanted, when the agent stops, when Oarbank is
  uninstalled (the launcher's uninstall runs `oarbank-agent portmap release-all`) and when the node is retired (the agent
  releases everything when the coordinator answers `node_retired`). At start the agent reads its journal and deletes
  every journaled mapping it no longer wants, and on UPnP routers that list mappings (`GetGenericPortMappingEntry`) also
  every mapping whose description carries its own node-id prefix **and** whose internal client is its own address.
  Nothing else is ever deleted: before a UPnP delete the agent reads the entry back and deletes only when the internal
  client and the description are its own (NAT-PMP and PCP deletes are keyed by the requesting host's own address, and
  PCP's by the mapping's nonce). Short leases are the backstop when an agent dies and never comes back.
- **Owner-visible list.** Every mapping the agent holds (protocol, gateway, external and internal address and port,
  lease, expiry, last verification) is in the heartbeat, on the node page and in `oarbank listener mappings`; the agent
  also lists other mappings the router reports for this node's address (it never touches them, but the owner should
  see them).

### IPv6

With `ipv6 = "auto"` and a global IPv6 address on the default route, the agent asks for a pinhole: PCP `MAP` with the
IPv6 internal address (a PCP server opens the firewall for it), else UPnP IGDv2 `WANIPv6FirewallControl` `AddPinhole`
(any remote host, TCP, lease 3600 s, `UpdatePinhole` at half life, `DeletePinhole` on removal, verified with
`CheckPinholeWorking` where the router has it). A router whose IPv6 firewall is off needs no pinhole; a router that
refuses (`InboundPinholeNotAllowed`, no firewall control service) gets `IPV6_PINHOLE_NEEDED` with the owner's fix.

### Why our own PCP and NAT-PMP, and igd-next for UPnP

`portmapper` (n0) does all three, but its API is one mapping for one local port. The lifecycle, the journal, many
listeners per node, verification, epochs, the cleanup guarantees and their TLA+ model live above every crate's API, so
the agent has its own small PCP and NAT-PMP clients (RFC 6886, 6887: small fixed wire formats) in the
`oarbank-portmap` crate and uses `igd-next` (MIT) for UPnP discovery and SOAP, adding the two actions it lacks
(`GetSpecificPortMappingEntry`, and the pinhole verification) on igd-next's own request path.

## Reachability and the doctor

The agent classifies each listener (and family) from local facts and one outside view:

| Input | How |
|---|---|
| Interface address | public (not RFC 1918, not 100.64.0.0/10, not link-local or loopback) means no NAT on this host |
| Gateway's external address | PCP MAP response, NAT-PMP external address, UPnP `GetExternalIPAddress` |
| Observed public address | the coordinator's view of the node's source address when it is public; the STUN check only when the owner named a STUN server |
| Mapping protocol present | the probes above |
| Dial-back | the prober connects to the listener's external address and port and completes the nonce exchange |
| Local firewall | macOS Application Firewall state for the agent, Windows Defender Firewall rule, nftables/ufw/firewalld active on Linux |
| Address history | the external addresses of the last 30 days, kept on the node |

| Result | Condition | What the owner reads (and the fix) |
|---|---|---|
| `REACHABLE` | dial-back succeeded | "Reachable from the internet at 198.51.100.7:9000 (mapped by UPnP, renewed 12 minutes ago)." |
| `PUBLIC_ADDRESS` | the interface address is public | "This machine has a public address; no router mapping is needed. Make sure no firewall blocks port 9000." |
| `NO_MAPPING_PROTOCOL` | no PCP, NAT-PMP or UPnP answer, one NAT | "Your router does not accept automatic port mapping. Turn on UPnP or NAT-PMP in its settings, or forward TCP port 9000 to this machine (192.168.1.20, port 41000) by hand and set the listener's mapping to manual." |
| `DOUBLE_NAT` | the gateway's external address is private, or differs from the observed address | "This machine is behind two routers. The mapping on the inner router works, but the outer one (often the provider's modem) blocks it. Put the provider's device in bridge mode, or forward port 9000 on both devices, or run this workload on a machine that is reachable." |
| `CGNAT` | the gateway's external address is in 100.64.0.0/10, or the observed address is shared | "Your internet provider shares one public address among many customers (carrier-grade NAT). Port forwarding cannot work. Ask the provider for a public IPv4 address (often a paid option), use IPv6 if the workload accepts it, or run the workload elsewhere." |
| `PORT_TAKEN` | `fallback = refuse` and the router holds the port for another client | "Port 9000 on your router is already forwarded to another device (192.168.1.31). Free it in the router's settings, choose another external port for this listener, or allow a fallback range." |
| `MAPPED_UNREACHABLE` | mapping verified, one NAT, dial-back failed | "The router accepted the mapping but connections from outside do not arrive. Check the router's own firewall, an upstream firewall, or whether your provider blocks inbound ports." |
| `FIREWALL_BLOCKED` | dial-back failed and this machine's firewall does not allow the agent | "This machine's firewall blocks incoming connections for Oarbank. Allow oarbank-agent in the firewall settings (as an administrator: `oarbank-agent firewall allow`)." |
| `MAPPED_UNVERIFIED` | the mapping verified, no prober has checked it yet (or none is available) | "Mapped by NAT-PMP at 198.51.100.7:9000; not yet checked from outside. Add a node on another network, or set a probe endpoint, to confirm it." |
| `MANUAL_UNVERIFIED` | `mapping = manual`, not yet checked | "You forward port 9000 by hand; not yet checked from outside." |
| `DYNAMIC_ADDRESS` (flag) | the external address changed in the last 30 days | "Your public address changes (last change 3 days ago). The workload is told each new address; expect a few minutes without connections after each change." |
| `PERMANENT_ONLY_ROUTER` (flag) | UPnP 725 or 402 seen | "Your router keeps port mappings until they are deleted. Oarbank deletes its mapping when it stops; if this machine is removed without uninstalling Oarbank, delete it in the router's settings." |
| `IPV6_REACHABLE` / `IPV6_PINHOLE_NEEDED` (flags) | a global IPv6 address; a pinhole opened, or refused | "Reachable over IPv6 at [2001:db8::7]:9000." / "Your router's IPv6 firewall blocks inbound connections and does not accept automatic pinholes; allow TCP port 9000 to this machine in its IPv6 firewall settings." |

The texts come from one table in the agent (`oarbank-portmap` `classify`), so the console, the CLI and the heartbeat
say the same; the coordinator renders the agent's `result`, `text` and `fix` as they are.

### The dial-back probe (D49)

- **When.** After a mapping is made or its external address changes, every 30 minutes while mapped, and on
  `listeners.probe` (T0; the node page's Check now). At most one probe per listener a minute.
- **Who dials.** The coordinator picks an online node, not the target, preferring one whose public address (the
  external address its own router reports, or the coordinator's view of a public source address) is known and differs
  from the target's, so the probe really comes from outside (hairpinning on consumer routers is unreliable, so a probe
  from inside the LAN proves nothing); the target checks the probe's source address itself and answers `SAME` to one
  from its own network, so a prober whose network is unknown is safe to try. Without one, the target's agent uses the owner's probe endpoint (`listener_probe_endpoint`, a fleet
  setting naming an `https://` URL of an `oarbank-agent probe-endpoint` the owner runs on another network); without
  that, the listener stays `mapped_unverified` (never `unreachable`, and no workload is stopped for it).
- **Wire.** The coordinator creates a probe (`probe_id`: 16 random bytes, hex; `nonce`: 16 random bytes, hex) and sends
  the target `listener_probes: [{probe_id, key, nonce, expires_at}]` and the prober `dial_probes: [{probe_id, host,
  port, nonce}]`, with `host` the target's external address for that listener as its router reported it. The prober
  connects (5 s), writes `OARBANK-PROBE/1 <probe_id>\n`, reads one line (5 s, at most 128 bytes) and succeeds only if
  the line is `OARBANK-PROBE/1 OK <nonce>` (`OARBANK-PROBE/1 SAME <nonce>`: the probe reached the node from its own
  network, reported as `same_network`, and the coordinator tries another prober). The target's listener answers a probe
  line for an expected `probe_id` with that reply, and refuses an unknown or expired one. The nonce never travels before the reply, so only the real target
  can answer. The prober reports `probe_results: [{probe_id, ok, detail, rtt_ms}]`; the coordinator sends the target
  `listener_reachability: {key: {state: "reachable"|"unreachable"|"no_prober", at, via, detail}}`.
- **Own endpoint.** `POST <url>` with `{"host", "port", "probe_id"}`; the endpoint dials as a prober does and answers
  `{"ok": true, "line": "<what it read>"}`; the agent checks the line against the nonce it made.
- **STUN.** With `listener_stun_server` set (`host:port`), the agent sends one RFC 8489 binding request from the
  listener's address every 30 minutes and uses `XOR-MAPPED-ADDRESS` as the observed address. Off by default; the
  owner sees which probe and which address check were used.

## Firewalls

| OS | What happens |
|---|---|
| macOS | The agent is a Developer ID–signed launchd daemon. With the Application Firewall on and "Automatically allow downloaded signed software" off, `oarbank-agent firewall allow` (run by the launcher at install, as root) adds the agent with `socketfilterfw --add` and `--unblockapp`; `oarbank-agent firewall status` reports the state, and the doctor's `FIREWALL_BLOCKED` names the fix. |
| Linux | `oarbank-agent firewall status` reports whether nftables, ufw or firewalld is active; `oarbank-agent firewall allow` (root) adds an `inet oarbank` nftables table accepting only the listener ports, with a per-address connection limit; the doctor names the rule otherwise. |
| Windows | The elevated helper (`OarbankHelper`) creates an inbound Defender Firewall rule for the agent's full path and the exact port when a listener opens and removes it when it closes (`{"op": "firewall_allow" | "firewall_remove", "port": P}`), as Microsoft recommends, so a first listen never raises a prompt that would create block rules. |

## Protocol (docs/protocol.md)

Heartbeat additions (every heartbeat, when the node has or had a listener):

```json
"listeners": [{"key": "mymodule/peer", "service": "mymodule/node", "state": "listening|held|closed|refused",
               "refused": null, "detail": null, "statement_seq": 7,
               "bind": "192.168.1.20:41000", "bind_v6": "[2001:db8::7]:9000",
               "external": "198.51.100.7:9000", "external_v6": "[2001:db8::7]:9000",
               "announced": "reachable", "since": 1790000000.0,
               "reachability": {"result": "REACHABLE", "flags": ["DYNAMIC_ADDRESS"], "text": "…", "fix": null,
                                "via": "fleet:n_…", "at": 1790000000.0},
               "conns": {"open": 3, "accepted": 1200, "bytes_in": 1048576, "bytes_out": 2097152,
                         "refused": {"rate": 2, "cap": 0, "per_ip": 1, "allow": 0, "held": 0, "disabled": 0}},
               "probe_wanted": false}],
"portmaps": [{"key": "mymodule/peer", "family": "ipv4", "protocol": "upnp", "gateway": "192.168.1.1",
              "external": "198.51.100.7:9000", "internal": "192.168.1.20:41000", "lease_s": 3600,
              "expires_at": 1790003600.0, "verified_at": 1790000000.0, "permanent": false, "state": "mapped",
              "error": null}],
"network": {"gateway": "192.168.1.1", "local": "192.168.1.20", "local_v6": "2001:db8::7",
            "gateway_external": "198.51.100.7", "observed": null,
            "protocols": {"pcp": false, "natpmp": true, "upnp": "IGD:2"}, "checked_at": 1790000000.0,
            "router_mappings": [{"protocol": "TCP", "external_port": 8080, "internal": "192.168.1.20:8080",
                                 "description": "…", "ours": false}],
            "firewall": {"kind": "macos-alf", "enabled": true, "agent_allowed": true}},
"probe_results": [{"probe_id": "…", "ok": true, "detail": null, "rtt_ms": 41.0}],
"listener_talkers": {"mymodule/peer": [{"addr": "203.0.113.5", "conns": 40, "refused": 2, "last": 1790000000.0}]}
```

`refused` codes: `LISTENER_NOT_GRANTED` (the module version on this node has no such `inbound` entry),
`LISTENER_NO_TARGET` (no enabled service or workload of the module lists it), `MODULE_DISABLED`,
`LISTENER_HANDOVER_UNSUPPORTED` (`listen_fd` on Windows),
`LISTENERS_DISABLED` (kill switch), `LISTENERS_FORBIDDEN` (managed policy), `LISTENER_STRICT_YIELD`,
`LISTENER_BIND_FAILED` (with the OS error), `PORT_TAKEN` (the mapping only; the listener still accepts on the LAN).
`listener_talkers` (the 24-hour top client addresses, at most 20 per listener) is sent only on the heartbeat after a
`send_listener_talkers` directive, which the coordinator sets while an operator has a listener's page open.

Directive additions:

| Directive | Meaning |
|---|---|
| `statement.listeners` | the owner's listener entries for this node (above) |
| `listeners_disabled` | the kill switch (`listeners.disable` for the node or the fleet): close every listener and remove every mapping now |
| `listener_probes` | dial-backs to expect: `[{probe_id, key, nonce, expires_at}]` |
| `dial_probes` | dial-backs to make for other nodes: `[{probe_id, host, port, nonce}]` |
| `listener_reachability` | `{key: {state, at, via, detail}}`: the outcome of the latest probe of each of this node's listeners |
| `observed_addr` | the node's source address as the coordinator saw it, when it is a public address (else absent) |
| `send_listener_talkers` | send `listener_talkers` once |

Node policy (settings registry) gains `inbound_listeners` (bool, default true, managed: tighten-only, so a machine's
managed policy can forbid listeners), `listener_port_range` (the internal port range, default `41000-41999`),
`listener_probe_endpoint` and `listener_stun_server` (fleet, default null: no third party is ever contacted).

## Coordinator

- **Statement.** `statements.content` gains `listeners` from the listener configuration (`system_state`
  `listener_config`: `{node_id: {key: entry}}`), only for keys whose module version on the node requests that inbound
  listener with approved grants; `listeners` is a signed field.
- **Operations** (D14 registry, all audited): `listeners.configure` (T2, admin; the preview names the node, the port,
  the module and the limits, and says the statement must be signed), `listeners.remove` (T1), `listeners.disable` (T0,
  operator; a node or the fleet), `listeners.resume` (T1), `listeners.probe` (T0). `nodes.sign_statement` now covers
  listeners.
- **Reports.** The heartbeat's `listeners`, `portmaps` and `network` are kept as the node's `listeners_json`; the node
  page's Network card, the module page and `oarbank listener list|show|mappings` render it.
- **Probes.** A table `listener_probes(probe_id, node_id, key, host, port, nonce, prober, via, state, detail,
  created_at, done_at)`; a probe is scheduled from a report's `probe_wanted` or `listeners.probe`, rate-limited to one
  a minute per listener, and expires after 60 s.
- **Explain and alerts.** `LISTENER_UNAVAILABLE` (with the agent's `refused` code), `PORT_TAKEN`, `DOUBLE_NAT`,
  `CGNAT`, `NO_MAPPING_PROTOCOL`, `MAPPED_UNREACHABLE`, `FIREWALL_BLOCKED`; alerts `listener_unreachable` (P3),
  `listener_saturated` (P4, connections refused for the cap).
- **Invariant S24.** Every listener and router mapping a node reports belongs to an approved grant (the module version
  on that node requests that inbound listener and its grants are approved by digest), an assignment (the node's
  statement lists it; a workload's listener also needs the workload's assignment) and the statement the node applied
  (its `statement_seq`). Checked from heartbeats (`invariants.py`, `oarbank verify`).
- **Retire.** The retire preview warns "router mappings may persist until their lease expires" when the node has
  mappings and is offline; an online node releases them when it is told it is retired.

## Agent CLI

`oarbank-agent portmap status` (the journal and what each mapping's gateway says now), `oarbank-agent portmap
release-all` (deletes every journaled mapping; the launcher's uninstall step), `oarbank-agent firewall status|allow`,
`oarbank-agent probe-endpoint --bind <addr:port>` (the owner-run dial-back endpoint).

## Threat model

| Threat | Defence |
|---|---|
| A module opens a port nobody approved | three gates: approved grant by digest, the owner's signed statement entry, the service or workload assignment; managed policy can forbid it |
| A compromised coordinator opens a port | statements are signed by the owner's release key and the agent refuses unsigned ones in signing mode |
| Flood, slow clients, connection exhaustion | per-address token bucket and cap, listener cap, idle timeout, byte-rate cap, SYN cookies (OS default); refusals are counted and alerted (`listener_saturated`) |
| The machine becomes a proxy into the LAN | the agent relays only to the module's channel, never to an address; no UDP; no code forwards to loopback or the LAN |
| UPnP abuse (CallStranger-style callbacks, mapping for others) | the agent is a client only: it never answers SSDP, never subscribes to events, maps only its own address and ports ≥ 1024, with short leases, journaled |
| Deleting someone else's mapping | UPnP deletes only after reading the entry back (own internal client and description); NAT-PMP and PCP deletes are keyed by the host's own address and PCP's nonce (TLA+ `NoForeignDelete`) |
| A stale mapping left open | short leases, the journal, cleanup at start, on stop, uninstall and retirement (TLA+ `EventuallyClean`; permanent-only routers are the documented exception) |
| Client address spoofing through PROXY protocol | the agent writes the header itself; nothing from the network is passed through as one |
| Probe abuse (the prober used to scan) | a prober dials only the address the target's own router reported, at a port of a listener the owner configured, at most once a minute per listener, with a 5 s timeout, and sends one line |
| A probe forged by an echo server or a hairpinning router | the reply must carry the nonce, which only the coordinator and the target know before the reply |
| Data about who connects | per-listener counters by default; client addresses only in a rolling 24-hour top-talkers table on the node, sent only while an operator has the listener's page open |
| Kill switch | `listeners.disable` (T0, a node or the fleet) closes every listener and removes every mapping at the next heartbeat |

## Verification

| Layer | Tests |
|---|---|
| Fake gateways | in-process, on loopback: a fake IGD (SSDP responder, description, SOAP for v1 and v2: 718, 724, 725, 402, 606, permanent-only mode, `AddAnyPortMapping` substitution, listing, pinholes, a reboot that drops state), a fake NAT-PMP server (epoch, lifetime clamping, announcements, reboot) and a fake PCP server (nonce check, `PREFER_FAILURE`, substitution, epoch, IPv6 pinholes); every test points the agent at them explicitly, so no test ever talks to a real router |
| Property tests | the lifecycle against a model router under random sequences of map, renew, verify, crash and restart from the journal, router reboot, address and network change, foreign mappings and lease expiry; the TLA+ properties checked on every trace |
| TLA+ | `specs/OarbankPortmap.tla`: `NoForeignDelete`, `AnnouncedImpliesMapped`, `EventuallyClean` (permanent-only routers must show up as a counterexample unless the agent starts again) and `AtMostOneExternalPortPerListener`; weakened variants (no write-ahead journal, delete by port only, no epoch check) fail |
| Soak | hours of virtual time with renewals, router reboots, address and network changes against the fake gateways: zero stale mappings at the end, no lapse in a held mapping beyond one verify interval |
| Agent | the data path: caps, token buckets, idle timeout, the PROXY v2 header bytes, the allowlist intersection, the kill switch, probes, the hand-over through the endpoint channel |
| End to end | `tests/rust/test_agent_listeners.py`: a real coordinator and agent, a module whose endpoint service answers on a public listener, a fake gateway: mapped, verified, probed by a second agent, a client served through the relay, a router reboot recovered, the kill switch removing the mapping, the uninstall step releasing it |
| SDK | manifest rules; the service helper receiving listener connections and announcements; the conformance kit's **listener** suite (it plays the agent: hands connections in, checks the service answers and still never listens) |
| Coordinator | statement building and signing with listeners, the operations, probe scheduling, explain codes, S24 |
| Real routers (manual) | listed under Implementation status |
