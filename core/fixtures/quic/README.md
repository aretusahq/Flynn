# QUIC Initial fixtures

Real client Initial datagrams from Apple's QUIC stack (Network.framework,
the stack Safari uses), captured on 20 Oct 2026 by connecting to a UDP
listener on 127.0.0.1 with the TLS server name `www.flynn-quic.test`.
Nothing answered, so no server data and no personal traffic is involved.

- `apple-initial-0.bin`, `apple-initial-1.bin`: the first two datagrams. The
  ClientHello (with a post-quantum key share) is split across them, so the
  name can only be read after both.
- `apple-initial-2.bin`: a retransmission.

QUIC v1, 8-byte destination connection ID `e2fb224780f3a1e4`.
