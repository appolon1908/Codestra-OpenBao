# Caddy handoff contract for `bao.codestra.media`

Caddy configuration remains owned by the edge/infrastructure authority. This
repository does not install, reload or replace Caddy and does not alter SSH or
firewall SSH rules.

The reviewed edge change must satisfy all of these conditions:

- accept public traffic only on HTTPS with TLS 1.3;
- retain `bao.codestra.media` as the only public OpenBao hostname;
- require the approved strong administrative/browser authentication gate;
- join only the private OpenBao client network;
- connect to OpenBao 8200 with server verification and a dedicated mTLS client
  certificate;
- never expose, route or probe Raft port 8201 publicly;
- deny initialization, unseal, rekey, generate-root, raw-storage and recovery
  paths from the public route;
- preserve the client address only from the trusted proxy CIDR;
- omit query strings and authorization data from access logs; and
- keep bootstrap and root-token operations outside browser access.

Workload agents should use a private listener/route. They must not traverse the
public browser route merely for deployment convenience. The edge owner must
provide a pre/post sanitized configuration checksum, TLS 1.3 evidence, mTLS
upstream evidence and rollback command before production activation.

The current production host was observed using Nginx rather than Caddy on
2026-09-01. That is a production preflight mismatch, not authority for this
repository to replace the edge without the owning infrastructure review.
