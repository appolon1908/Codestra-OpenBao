#!/usr/bin/env python3
import argparse, json, os, pathlib

p=argparse.ArgumentParser()
p.add_argument("--head")
p.add_argument("--base")
p.add_argument("--head-repo")
p.add_argument("--base-repo")
a=p.parse_args()

head=a.head or os.environ.get("GITHUB_HEAD_REF","")
base=a.base or os.environ.get("GITHUB_BASE_REF","")
head_repo=a.head_repo or os.environ.get("GITHUB_HEAD_REPO","")
base_repo=a.base_repo or os.environ.get("GITHUB_BASE_REPO","")

policy=json.loads(pathlib.Path("governance/promotion-policy.json").read_text())
sections=set(policy["authoritative_sections"])

if head_repo and base_repo and head_repo != base_repo:
    print(f"PROMOTION_GUARD=BLOCK fork head_repo={head_repo} base_repo={base_repo}")
    raise SystemExit(1)

b=policy["bootstrap_exception"]
if head==b["head"] and base==b["base"]:
    print("PROMOTION_GUARD=PASS bootstrap")
    raise SystemExit(0)

if head.startswith("subsection/"):
    name=head.split("/",1)[1]
    if "--" not in name:
        print("PROMOTION_GUARD=BLOCK malformed_subsection")
        raise SystemExit(1)
    section=name.split("--",1)[0]
    ok=section in sections and base==section
elif head in sections:
    ok=base=="development"
else:
    ok=(head,base) in {
        ("development","test"),
        ("test","staging"),
        ("staging","production"),
        ("production","main"),
    }

if not ok:
    print(f"PROMOTION_GUARD=BLOCK head={head} base={base}")
    raise SystemExit(1)

print(f"PROMOTION_GUARD=PASS head={head} base={base}")
