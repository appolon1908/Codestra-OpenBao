#!/usr/bin/env python3
import json,os,pathlib,sys
REQ={"codestra","moneybee","beyvra","breero","larim-a","transportation","booked4seasons","social","klyrow","telnexa","kyqra","restaurant","provisioning"}; HOST='bao.codestra.media'
def fail(m): print('ERROR: '+m,file=sys.stderr); raise SystemExit(1)
p=pathlib.Path('codestra/enterprise-profile.v1.json')
if not p.exists(): fail('missing enterprise profile')
d=json.loads(p.read_text())
if d.get('canonicalHostname')!=HOST: fail('wrong canonical hostname')
if d.get('schemaVersion')!='1.0' or d.get('status')!='SOURCE_PREPARED_NOT_DEPLOYED': fail('invalid schema/status')
miss=REQ-set(d.get('businessScope',[]))
if miss: fail('missing businesses: '+', '.join(sorted(miss)))
if not d.get('features') or not d.get('secretDomains'): fail('secrets/features must be defined')
if d.get('identity',{}).get('rootTokenDailyUse') is not False: fail('root token daily use must remain disabled')
if not d.get('financialTradingBoundary',{}).get('dedicatedPolicyCompartment'): fail('Beyvra trading compartment required')
print('Codestra enterprise profile validation PASS: '+os.environ.get('GITHUB_REPOSITORY','openbao'))
