from __future__ import annotations

import argparse
import re
from pathlib import Path


BUSINESSES = (
    "codestra",
    "moneybee",
    "beyvra",
    "breero",
    "larim-a",
    "transportation",
    "booked4seasons",
    "social",
    "klyrow",
    "telnexa",
    "kyqra",
    "restaurant",
    "provisioning",
)
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def render(business: str) -> str:
    if not SLUG.fullmatch(business):
        raise ValueError(f"invalid business slug: {business}")
    blocks = [
        f'''path "kv-platform/data/observability/clients/{business}/alloy" {{
  capabilities = ["read"]
}}''',
        f'''path "kv-platform/data/observability/clients/{business}/opentelemetry" {{
  capabilities = ["read"]
}}''',
        f'''path "pki-platform-issuing/issue/telemetry-client-{business}" {{
  capabilities = ["create", "update"]
}}''',
        '''path "auth/token/lookup-self" {
  capabilities = ["read"]
}''',
        '''path "auth/token/renew-self" {
  capabilities = ["update"]
}''',
        '''path "sys/leases/renew" {
  capabilities = ["update"]
}''',
        '''path "auth/token/create*" {
  capabilities = ["deny"]
}''',
        '''path "sys/mounts/*" {
  capabilities = ["deny"]
}''',
        '''path "sys/auth/*" {
  capabilities = ["deny"]
}''',
        '''path "sys/audit/*" {
  capabilities = ["deny"]
}''',
    ]
    if business == "beyvra":
        blocks.extend(
            [
                '''path "kv-beyvra/data/*/production/broker-exchange-custody/*" {
  capabilities = ["deny"]
}''',
                '''path "kv-beyvra/metadata/*/production/broker-exchange-custody/*" {
  capabilities = ["deny"]
}''',
                '''path "transit-beyvra/sign/*" {
  capabilities = ["deny"]
}''',
                '''path "transit-beyvra/decrypt/*" {
  capabilities = ["deny"]
}''',
                '''path "transit-beyvra/export/*" {
  capabilities = ["deny"]
}''',
                '''path "database/creds/beyvra-trading-*" {
  capabilities = ["deny"]
}''',
            ]
        )
    return "\n\n".join(blocks) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for business in BUSINESSES:
        destination = args.output_dir / f"telemetry-{business}.hcl"
        destination.write_text(render(business), encoding="utf-8")


if __name__ == "__main__":
    main()
