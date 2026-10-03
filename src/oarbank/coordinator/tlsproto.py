"""The agent listener's HTTP protocol: uvicorn's h11 protocol, plus the TLS peer certificate (DER) of each connection
in the request state (`request.state.tls_peer_der`), which uvicorn does not expose. The certificate was already
verified against the coordinator CA by the TLS layer (client certificates are optional; enrollment has none)."""
from uvicorn.protocols.http.h11_impl import H11Protocol


class PeerCertH11(H11Protocol):
    def connection_made(self, transport):
        super().connection_made(transport)
        so = transport.get_extra_info("ssl_object")
        der = so.getpeercert(binary_form=True) if so is not None else None
        self.app_state = {**self.app_state, "tls_peer_der": der}     # per connection: never shared between peers
