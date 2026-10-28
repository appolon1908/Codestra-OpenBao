#!/usr/bin/env python3
"""Collect and validate unsigned, nonpublishing image/plugin candidate evidence.

This is deliberately separate from protected release evidence. It neither
authorizes runtime use nor changes findings/acceptance for a patched old version.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import re
import tarfile
from pathlib import Path
from write_openbao_source_image_evidence import vulnerability_counts

SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
BLOCKED = {"CVE-2026-84304", "CVE-2026-84445", "CVE-2026-56851",
           "GHSA-gcjh-h69q-9w9g", "CVE-2026-81870"}
FIXED_CEL_OTEL_MODULES = {
    "github.com/google/cel-go": "v0.30.0",
    "github.com/go-logr/logr": "v1.4.4",
    "go.opentelemetry.io/otel": "v1.45.0",
    "go.opentelemetry.io/otel/metric": "v1.45.0",
    "go.opentelemetry.io/otel/trace": "v1.45.0",
}

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024*1024), b""):
            h.update(block)
    return h.hexdigest()

def load(path):
    return json.loads(path.read_text())

def write(path, obj):
    path.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")

def require(condition, message):
    if not condition:
        raise ValueError(message)

def fresh(value, now):
    require(isinstance(value,str), "missing evidence timestamp")
    stamp = dt.datetime.fromisoformat(value.replace("Z","+00:00"))
    require(stamp.tzinfo is not None, "timestamp has no timezone")
    require(-dt.timedelta(minutes=10) <= now-stamp <= dt.timedelta(hours=24),
            "stale or future evidence timestamp")
    return stamp

def snapshot_image(archive, root):
    """Construct an actual local OCI manifest using verified Docker-save blobs.

    Docker .Id is the configuration hash, never the manifest digest. Docker-save
    layers are uncompressed; verify their hashes against the configuration DiffIDs.
    No registry/publishing or signing occurs here.
    """
    inspect = load(root/"image-inspect.json")
    with tarfile.open(archive,"r:") as saved:
        def read(name):
            member = saved.getmember(name)
            require(member.isfile(), "image archive member must be a regular file")
            return saved.extractfile(member).read()
        manifest = json.loads(read("manifest.json"))
        require(len(manifest)==1, "archive must contain exactly one image")
        entry = manifest[0]
        config = read(entry["Config"])
        config_id = "sha256:"+hashlib.sha256(config).hexdigest()
        require(config_id == inspect["Id"], "archive configuration differs from inspected image")
        metadata = json.loads(config)
        layers = []
        for name in entry["Layers"]:
            member = saved.getmember(name)
            require(member.isfile(), "image layer must be a regular file")
            h = hashlib.sha256()
            with saved.extractfile(member) as stream:
                for block in iter(lambda: stream.read(1024*1024), b""):
                    h.update(block)
            layers.append({"mediaType":"application/vnd.oci.image.layer.v1.tar",
                           "digest":"sha256:"+h.hexdigest(),"size":member.size})
        diffids = [layer["digest"] for layer in layers]
        require(diffids == metadata["rootfs"]["diff_ids"] == inspect["RootFS"]["Layers"],
                "archive layers differ from image DiffIDs")
    (root/"image-config.json").write_bytes(config)
    oci = {"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
           "config":{"mediaType":"application/vnd.oci.image.config.v1+json",
                     "digest":config_id,"size":len(config)}, "layers":layers}
    write(root/"oci-manifest.json",oci)
    write(root/"oci-descriptor.json",{
        "mediaType":oci["mediaType"],"digest":"sha256:"+sha(root/"oci-manifest.json"),
        "size":(root/"oci-manifest.json").stat().st_size,
        "docker_save_archive_sha256":sha(archive),
        "scope":"locally constructed unsigned OCI manifest; not a registry digest"})

def evaluate(root, source_sha, source_tree, run_id, run_attempt, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    require(bool(SHA.fullmatch(source_sha)) and bool(SHA.fullmatch(source_tree)), "invalid source identity")
    build = load(root/"build.json")
    for key, expected in (("source_sha",source_sha),("source_tree",source_tree),
                          ("run_id",run_id),("run_attempt",run_attempt)):
        require(build.get(key)==expected, "build "+key+" mismatch")
    require(run_id>0 and run_attempt>0, "invalid CI run identity")
    require(build.get("repository")=="appolon1908/Codestra-OpenBao", "wrong source repository")
    require(build.get("upstream")=="dd9c19c37a878cf4a81b18efb8d6f0599c7da923", "wrong imported upstream identity")
    for field in ("go_mod_sha256","go_sum_sha256","plugin_manifest_sha256","plugin_source_tree_sha256",
                  "vendor_tree_sha256","backport_patch_sha256","test_fixture_overlay_sha256"):
        require(isinstance(build.get(field),str) and bool(re.fullmatch(r"[0-9a-f]{64}",build[field])),
                "missing provenance digest: "+field)
    require(build.get("go_version")=="go1.26.10", "wrong candidate Go toolchain")
    require(build.get("runtime_authorized") is False, "candidate cannot authorize runtime")
    fixtures = load(root/"test-fixture-overlay.json")
    require(sha(root/"test-fixture-overlay.json")==build["test_fixture_overlay_sha256"] and
            fixtures.get("test_only") is True and fixtures.get("assertions_removed") is False and
            fixtures.get("reusable_private_key_material_stored") is False, "invalid test fixture provenance")
    inspect = load(root/"image-inspect.json")
    config_id = inspect["Id"]
    require(bool(DIGEST.fullmatch(config_id)), "invalid image configuration ID")
    require(inspect.get("Architecture")=="amd64" and inspect.get("Os")=="linux", "wrong image platform")
    require(inspect["Config"].get("User") in ("65532","65532:65532","nonroot"), "image must be non-root")
    config = load(root/"image-config.json")
    require("sha256:"+sha(root/"image-config.json")==config_id, "image configuration checksum mismatch")
    require(config["config"]["Labels"]["org.opencontainers.image.revision"]==source_sha,
            "image source revision mismatch")
    require(inspect["Config"]["Labels"]["org.opencontainers.image.revision"]==source_sha,
            "inspected image revision mismatch")
    oci = load(root/"oci-manifest.json")
    descriptor = load(root/"oci-descriptor.json")
    require(oci.get("schemaVersion")==2 and oci.get("mediaType")=="application/vnd.oci.image.manifest.v1+json",
            "invalid OCI manifest")
    require(oci["config"]["digest"]==config_id and
            oci["config"]["size"]==(root/"image-config.json").stat().st_size, "OCI configuration mismatch")
    require(descriptor["digest"]=="sha256:"+sha(root/"oci-manifest.json") and
            descriptor["size"]==(root/"oci-manifest.json").stat().st_size, "OCI descriptor mismatch")
    require([layer["digest"] for layer in oci["layers"]]==config["rootfs"]["diff_ids"]==inspect["RootFS"]["Layers"],
            "OCI layer identity mismatch")
    require(sha(root/"bao")==sha(root/"bao-from-image"), "image contains a different OpenBao binary")
    for name in ("bao","plugin-root/codestra-jwt-replay"):
        require(sha(root/name)==build["binaries"][name], "binary checksum mismatch: "+name)
    backport = load(root/"jose-v3-backport.json")
    require(backport.get("module_version")=="v3.0.5" and backport.get("vulnerability_acceptance") is False,
            "backport must retain original module identity without acceptance")
    require(backport.get("requires_go_mod_flag")=="-mod=vendor", "missing vendor build binding")
    require(backport.get("patch_sha256")==build["backport_patch_sha256"], "backport patch identity mismatch")
    require(backport.get("vendor_tree_sha256")==build["vendor_tree_sha256"], "vendor tree identity mismatch")
    overlay = load(root/"dependency-overlay.json")
    require(overlay.get("status")=="PASS" and overlay.get("go_mod_tidy_performed") is True,
            "missing reconciled dependency overlay")
    for name,overlay_key,build_key in (("prepared-go.mod","go_mod_sha256_after","go_mod_sha256"),
                                       ("prepared-go.sum","go_sum_sha256_after","go_sum_sha256")):
        require(sha(root/name)==build[build_key]==overlay.get(overlay_key), "prepared module identity mismatch")
    require(sha(root/"accepted-plugin-manifest.json")==build["plugin_manifest_sha256"],
            "accepted plugin manifest provenance mismatch")
    manifest = load(root/"backport-manifest.json")
    require(manifest.get("upstream_fix")=="a0111f82742fa92bceec9ede40845e73319e6230" and
            manifest.get("patch_sha256")==sha(root/"security.patch")==build["backport_patch_sha256"],
            "maintainer-origin patch identity mismatch")
    require(manifest.get("files")==backport.get("files") and
            sha(root/"vendor-modules.txt")==backport.get("vendor_modules_sha256"),
            "vendor patch provenance mismatch")
    for name in ("bao","plugin"):
        version = (root/(name+"-go-version.txt")).read_text()
        require(re.search(r":\s+go1\.26\.10\s*$",version,re.M) is not None, "wrong compiled toolchain")
        required={**FIXED_CEL_OTEL_MODULES,**({"go.opentelemetry.io/otel/sdk":"v1.45.0"} if name=="bao" else {})}
        for module, version_pin in {**required,"github.com/go-jose/go-jose/v3":"v3.0.5",
                                    "github.com/go-jose/go-jose/v4":"v4.1.6",
                                    "golang.org/x/net":"v0.62.0",
                                    "golang.org/x/text":"v0.43.0",
                                    "google.golang.org/grpc":"v1.83.2"}.items():
            require(re.search(r"dep\s+"+re.escape(module)+r"\s+"+re.escape(version_pin)+r"(\s|$)",version),
                    "compiled dependency mismatch: "+module)
        sdk_versions=re.findall(r"dep\s+go\.opentelemetry\.io/otel/sdk\s+(\S+)",version)
        require(not sdk_versions or set(sdk_versions)=={"v1.45.0"}, "compiled optional SDK dependency mismatch")
    tools = load(root/"tool-versions.json")
    require(tools["trivy"]["Version"]=="0.74.0" and tools["syft"]["version"]=="1.51.1",
            "unexpected scanner/SBOM tool version")
    require(load(root/"trivy-version.json")==tools["trivy"] and
            load(root/"syft-version.json")==tools["syft"], "raw tool version mismatch")
    syft = load(root/"image-syft.json")
    require(syft["source"]["type"]=="image" and syft["source"]["metadata"]["imageID"]==config_id,
            "image SBOM configuration mismatch")
    require(syft["descriptor"]["name"]=="syft" and syft["descriptor"]["version"]=="1.51.1",
            "image SBOM generator mismatch")
    db = load(root/"db-metadata.json")
    require(db.get("Version")==2, "wrong vulnerability DB schema")
    updated = fresh(db.get("UpdatedAt"),now)
    downloaded = fresh(db.get("DownloadedAt"),now)
    require(updated<=downloaded+dt.timedelta(minutes=10), "DB timestamps out of order")
    require(re.fullmatch(r"[0-9a-f]{64}",(root/"db.sha256").read_text().strip()), "missing DB checksum")
    subjects = {}
    for name, artifact, artifact_type, binary in (
        ("image",build["local_image"],"container_image","bao"),
        ("plugin",build["plugin_scan_root"],"filesystem","codestra-jwt-replay")):
        report = load(root/(name+"-trivy.json"))
        critical,high,unknown,_ = vulnerability_counts(report)
        require(report.get("ArtifactName")==artifact and report.get("ArtifactType")==artifact_type,
                "wrong scan subject: "+name)
        require(report.get("Trivy",{}).get("Version")=="0.74.0", "wrong scan tool version")
        scanned = fresh(report.get("CreatedAt"),now)
        require(scanned+dt.timedelta(minutes=10)>=downloaded, "scan predates frozen database")
        if name=="image":
            require(report.get("Metadata",{}).get("ImageID")==config_id, "scan image configuration mismatch")
        require(any(r["Type"]=="gobinary" and Path(r["Target"]).name==binary
                    for r in report["Results"]), "binary not observed by scanner: "+name)
        sbom = load(root/(name+"-sbom.json"))
        if name=="image":
            require(sbom.get("spdxVersion")=="SPDX-2.3" and bool(sbom.get("packages")), "missing image SPDX packages")
        else:
            require(sbom.get("bomFormat")=="CycloneDX" and sbom.get("specVersion")=="1.7" and
                    bool(sbom.get("components")), "missing plugin CycloneDX components")
            component = sbom["metadata"]["component"]
            require(component["name"]=="codestra-jwt-replay" and
                    component["version"]=="sha256:"+build["binaries"]["plugin-root/codestra-jwt-replay"],
                    "plugin SBOM binary mismatch")
            require(any(t.get("name")=="syft" and t.get("version")=="1.51.1"
                        for t in sbom["metadata"]["tools"]["components"]), "plugin SBOM generator mismatch")
        inventory = sbom["packages"] if name=="image" else sbom["components"]
        versions = {}
        for package in inventory:
            versions.setdefault(package.get("name"),set()).add(package.get("versionInfo") if name=="image" else package.get("version"))
        required={**FIXED_CEL_OTEL_MODULES,**({"go.opentelemetry.io/otel/sdk":"v1.45.0"} if name=="image" else {})}
        for module,version in {**required,"github.com/go-jose/go-jose/v3":"v3.0.5","github.com/go-jose/go-jose/v4":"v4.1.6",
                               "golang.org/x/net":"v0.62.0","golang.org/x/text":"v0.43.0",
                               "google.golang.org/grpc":"v1.83.2","stdlib":"go1.26.10"}.items():
            require(versions.get(module)=={version}, "SBOM dependency identity mismatch: "+module)
        require("go.opentelemetry.io/otel/sdk" not in versions or
                versions["go.opentelemetry.io/otel/sdk"]=={"v1.45.0"}, "SBOM optional SDK dependency mismatch")
        findings = [v for result in report["Results"] for v in result.get("Vulnerabilities") or []]
        known = sorted({v["VulnerabilityID"] for v in findings if v["VulnerabilityID"] in BLOCKED})
        subjects[name] = {"critical":critical,"high":high,"unknown":unknown,
                          "blocked_cves":known,"status":"FAIL" if critical or high or unknown or known else "PASS",
                          "scan_created_at":report["CreatedAt"]}
    return {"schema_version":1, "evidence_complete":True,
            "status":"PASS" if all(s["status"]=="PASS" for s in subjects.values()) else "FAIL",
            "source_sha":source_sha,"source_tree":source_tree,"run_id":run_id,"run_attempt":run_attempt,
            "image_config_id":config_id, "local_oci_manifest_digest":descriptor["digest"],
            "binaries":build["binaries"], "subjects":subjects,
            "runtime_authorized":False,"published":False,"signed":False,"vulnerability_acceptance":False,
            "files":{p.relative_to(root).as_posix():sha(p) for p in sorted(root.rglob("*"))
                     if p.is_file() and p.name!="candidate-evidence.json"}}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir",type=Path,required=True)
    parser.add_argument("--docker-save",type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument("--source-tree")
    parser.add_argument("--run-id",type=int)
    parser.add_argument("--run-attempt",type=int)
    args = parser.parse_args()
    if args.docker_save:
        snapshot_image(args.docker_save,args.evidence_dir)
        return 0
    args.evidence_dir.mkdir(parents=True,exist_ok=True)
    try:
        evidence = evaluate(args.evidence_dir,args.source_sha or "",args.source_tree or "",args.run_id,args.run_attempt)
    except (ValueError,KeyError,TypeError,OSError,json.JSONDecodeError) as error:
        evidence = {"schema_version":1,"status":"FAIL","evidence_complete":False,"error":str(error),
                    "source_sha":args.source_sha,"source_tree":args.source_tree,
                    "runtime_authorized":False,"published":False,"signed":False,"vulnerability_acceptance":False}
    write(args.evidence_dir/"candidate-evidence.json",evidence)
    print("OPENBAO_CANDIDATE_ARTIFACT_GATE="+evidence["status"])
    return 0 if evidence["status"]=="PASS" else 1

if __name__=="__main__":
    raise SystemExit(main())
