#!/usr/bin/env python3
import sys

head=sys.argv[1]
base=sys.argv[2]

SECTIONS=["ob-01-kv","ob-02-auth","ob-03-policy","ob-04-dynamic-creds","ob-05-pki","ob-06-transit","ob-07-rotation","ob-08-tenancy","ob-09-audit","ob-10-ha","ob-11-seal","ob-12-dr","ob-13-control-api","ob-14-integrations","ob-15-cicd","ob-16-certification"]
SECTION_SET=set(SECTIONS)

if head=="governance/development-control-plane-v1" and base=="main":
    print("PROMOTION_ALLOWED=YES governance_bootstrap")
    raise SystemExit(0)

if head.startswith("subsection/"):
    name=head.split("/",1)[1]
    if "--" not in name:
        print("PROMOTION_ALLOWED=NO malformed_subsection")
        raise SystemExit(1)
    section=name.split("--",1)[0]
    ok=section in SECTION_SET and base==section
    print("PROMOTION_ALLOWED="+("YES" if ok else "NO"),"subsection_to_section")
    raise SystemExit(0 if ok else 1)

if head in SECTION_SET:
    ok=base=="development"
    print("PROMOTION_ALLOWED="+("YES" if ok else "NO"),"section_to_development")
    raise SystemExit(0 if ok else 1)

ok=(head,base) in {
    ("development","test"),
    ("test","staging"),
    ("staging","production"),
    ("production","main"),
}
print("PROMOTION_ALLOWED="+("YES" if ok else "NO"),f"head={head}",f"base={base}")
raise SystemExit(0 if ok else 1)
