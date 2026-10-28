"""Exact local artifact evidence must survive findings and fail closed."""
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("candidate_evidence",ROOT/"scripts/collect_openbao_candidate_evidence.py")
MODULE=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
NOW=dt.datetime(2026,10,28,17,tzinfo=dt.timezone.utc)
SOURCE="a"*40
TREE="b"*40
def write(root,name,value):
    path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
    MODULE.write(path,value)
def change(root,name,fn):
    doc=MODULE.load(root/name);fn(doc);write(root,name,doc)

class CandidateEvidenceTests(unittest.TestCase):
    def fixture(self,root):
        (root/"plugin-root").mkdir()
        for name in ("bao","bao-from-image","plugin-root/codestra-jwt-replay"):
            (root/name).write_bytes(b"fixture binary")
        config={"config":{"Labels":{"org.opencontainers.image.revision":SOURCE}},
                "rootfs":{"diff_ids":["sha256:"+"c"*64]}}
        write(root,"image-config.json",config)
        config_id="sha256:"+MODULE.sha(root/"image-config.json")
        write(root,"image-inspect.json",{"Id":config_id,"Architecture":"amd64","Os":"linux",
            "Config":{"User":"65532","Labels":{"org.opencontainers.image.revision":SOURCE}},
            "RootFS":{"Layers":config["rootfs"]["diff_ids"]}})
        write(root,"oci-manifest.json",{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"digest":config_id,"size":(root/"image-config.json").stat().st_size},
            "layers":[{"digest":config["rootfs"]["diff_ids"][0]}]})
        write(root,"oci-descriptor.json",{"digest":"sha256:"+MODULE.sha(root/"oci-manifest.json"),
            "size":(root/"oci-manifest.json").stat().st_size})
        for name in ("prepared-go.mod","prepared-go.sum","vendor-modules.txt","security.patch"):
            (root/name).write_text("fixture\\n")
        write(root,"accepted-plugin-manifest.json",{"name":"codestra-jwt-replay"})
        files={"jwk.go":{"before":"0"*64,"after":"1"*64}}
        write(root,"backport-manifest.json",{"upstream_fix":"a0111f82742fa92bceec9ede40845e73319e6230",
              "patch_sha256":MODULE.sha(root/"security.patch"),"files":files})
        write(root,"build.json",{"source_sha":SOURCE,"source_tree":TREE,"run_id":1,"run_attempt":1,
            "go_version":"go1.26.10","runtime_authorized":False,"local_image":"candidate:test",
            "plugin_scan_root":"/fixture/plugin-root","vendor_tree_sha256":"d"*64,
            "repository":"appolon1908/Codestra-OpenBao","upstream":"dd9c19c37a878cf4a81b18efb8d6f0599c7da923",
            "go_mod_sha256":MODULE.sha(root/"prepared-go.mod"),"go_sum_sha256":MODULE.sha(root/"prepared-go.sum"),
            "plugin_manifest_sha256":MODULE.sha(root/"accepted-plugin-manifest.json"),"plugin_source_tree_sha256":"1"*64,
            "backport_patch_sha256":MODULE.sha(root/"security.patch"),"binaries":{n:MODULE.sha(root/n) for n in ("bao","plugin-root/codestra-jwt-replay")}})
        write(root,"jose-v3-backport.json",{"module_version":"v3.0.5","vulnerability_acceptance":False,
            "requires_go_mod_flag":"-mod=vendor","patch_sha256":MODULE.sha(root/"security.patch"),"vendor_tree_sha256":"d"*64,
            "files":files,"vendor_modules_sha256":MODULE.sha(root/"vendor-modules.txt")})
        write(root,"dependency-overlay.json",{"status":"PASS","go_mod_tidy_performed":True,
            "go_mod_sha256_after":MODULE.sha(root/"prepared-go.mod"),"go_sum_sha256_after":MODULE.sha(root/"prepared-go.sum")})
        for name in ("bao","plugin"):
            (root/(name+"-go-version.txt")).write_text(
                "binary: go1.26.10\n"+
                "\n".join(" dep "+m+" "+v for m,v in (
                 ("github.com/go-jose/go-jose/v3","v3.0.5"),("github.com/go-jose/go-jose/v4","v4.1.6"),
                 ("golang.org/x/net","v0.62.0"),("golang.org/x/text","v0.43.0"),
                 ("google.golang.org/grpc","v1.83.2")))+"\n")
        write(root,"tool-versions.json",{"trivy":{"Version":"0.74.0"},"syft":{"version":"1.51.1"}})
        write(root,"trivy-version.json",{"Version":"0.74.0"})
        write(root,"syft-version.json",{"version":"1.51.1"})
        write(root,"image-syft.json",{"source":{"type":"image","metadata":{"imageID":config_id}},
              "descriptor":{"name":"syft","version":"1.51.1"}})
        write(root,"db-metadata.json",{"Version":2,"UpdatedAt":NOW.isoformat(),"DownloadedAt":NOW.isoformat()})
        (root/"db.sha256").write_text("f"*64+"\n")
        for name,artifact,kind,binary in (("image","candidate:test","container_image","bao"),
                                       ("plugin","/fixture/plugin-root","filesystem","codestra-jwt-replay")):
            write(root,name+"-trivy.json",{"SchemaVersion":2,"Trivy":{"Version":"0.74.0"},
                "CreatedAt":NOW.isoformat(),"ArtifactType":kind,"ArtifactName":artifact,
                "Metadata":{"ImageID":config_id},
                "Results":[{"Target":"/"+binary,"Type":"gobinary","Vulnerabilities":[]}]})
        inventory={"github.com/go-jose/go-jose/v3":"v3.0.5","github.com/go-jose/go-jose/v4":"v4.1.6",
                   "golang.org/x/net":"v0.62.0","golang.org/x/text":"v0.43.0",
                   "google.golang.org/grpc":"v1.83.2","stdlib":"go1.26.10"}
        write(root,"image-sbom.json",{"spdxVersion":"SPDX-2.3",
            "packages":[{"name":name,"versionInfo":version} for name,version in inventory.items()]})
        write(root,"plugin-sbom.json",{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"name":name,"version":version} for name,version in inventory.items()],
            "metadata":{"component":{"name":"codestra-jwt-replay","version":"sha256:"+MODULE.sha(root/"plugin-root/codestra-jwt-replay")},
                        "tools":{"components":[{"name":"syft","version":"1.51.1"}]}}})
    def evaluate(self,root):
        return MODULE.evaluate(root,SOURCE,TREE,1,1,NOW)
    def test_complete_unsigned_candidate_passes_without_runtime_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root); result=self.evaluate(root)
            self.assertEqual(result["status"],"PASS")
            self.assertTrue(result["evidence_complete"])
            for name in ("runtime_authorized","published","signed","vulnerability_acceptance"):
                self.assertIs(result[name],False)
            self.assertNotEqual(result["image_config_id"],result["local_oci_manifest_digest"])
    def test_each_gated_severity_preserves_both_raw_reports_and_fails(self):
        for subject in ("image","plugin"):
            for severity in ("HIGH","CRITICAL","UNKNOWN"):
                with self.subTest(subject=subject,severity=severity),tempfile.TemporaryDirectory() as tmp:
                    root=Path(tmp);self.fixture(root)
                    change(root,subject+"-trivy.json",lambda d:d["Results"][0]["Vulnerabilities"].append(
                        {"VulnerabilityID":"CVE-fixture","PkgName":"fixture","Severity":severity}))
                    before={n:MODULE.sha(root/n) for n in ("image-trivy.json","plugin-trivy.json")}
                    result=self.evaluate(root)
                    self.assertEqual(result["status"],"FAIL")
                    self.assertTrue(result["evidence_complete"])
                    self.assertEqual(before,{n:MODULE.sha(root/n) for n in before})
    def test_known_remediated_cve_still_fails_at_low(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root)
            change(root,"image-trivy.json",lambda d:d["Results"][0]["Vulnerabilities"].append(
                {"VulnerabilityID":"CVE-2026-84445","PkgName":"grpc","Severity":"LOW"}))
            self.assertEqual(self.evaluate(root)["status"],"FAIL")
    def test_wrong_identity_stale_or_malformed_evidence_is_refused(self):
        cases=[
            ("build.json",lambda d:d.update(source_sha="c"*40)),
            ("build.json",lambda d:d.update(source_tree="c"*40)),
            ("build.json",lambda d:d.update(run_id=2)),
            ("build.json",lambda d:d.pop("plugin_source_tree_sha256")),
            ("dependency-overlay.json",lambda d:d.update(go_mod_sha256_after="0"*64)),
            ("backport-manifest.json",lambda d:d.update(upstream_fix="0"*40)),
            ("plugin-sbom.json",lambda d:d.update(components=[{"name":"fixture"}])),
            ("image-sbom.json",lambda d:d.update(packages=[{"name":"fixture"}])),
            ("image-syft.json",lambda d:d["source"]["metadata"].update(imageID="sha256:"+"0"*64)),
            ("plugin-sbom.json",lambda d:d["metadata"]["component"].update(version="sha256:"+"0"*64)),
            ("trivy-version.json",lambda d:d.update(Version="wrong")),
            ("image-trivy.json",lambda d:d["Metadata"].update(ImageID="sha256:"+"0"*64)),
            ("plugin-trivy.json",lambda d:d.update(ArtifactName="/unrelated")),
            ("plugin-trivy.json",lambda d:d["Results"][0].update(Target="/other")),
            ("image-trivy.json",lambda d:d.update(CreatedAt="2026-09-19T00:00:00Z")),
            ("image-trivy.json",lambda d:d["Results"][0].update(Vulnerabilities=[{"Severity":"bad"}])),
            ("oci-descriptor.json",lambda d:d.update(digest="sha256:"+"0"*64)),
            ("jose-v3-backport.json",lambda d:d.update(vulnerability_acceptance=True)),
            ("db-metadata.json",lambda d:d.update(UpdatedAt="2026-09-19T00:00:00Z")),
            ("tool-versions.json",lambda d:d["trivy"].update(Version="0.75.0")),
        ]
        for name,mutate in cases:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.fixture(root);change(root,name,mutate)
                with self.assertRaises((ValueError,KeyError)):
                    self.evaluate(root)
    def test_missing_db_or_changed_binary_cannot_pass(self):
        for name in ("db-metadata.json","db.sha256","plugin-root/codestra-jwt-replay","bao-from-image"):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.fixture(root)
                if name.endswith(".json") or name.endswith(".sha256"): (root/name).unlink()
                else: (root/name).write_bytes(b"tampered")
                with self.assertRaises((ValueError,FileNotFoundError)):
                    self.evaluate(root)
    def test_oci_snapshot_hashes_real_config_and_uncompressed_layers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            layer=b"raw tar fixture"
            diffid="sha256:"+hashlib.sha256(layer).hexdigest()
            config=json.dumps({"rootfs":{"diff_ids":[diffid]}}).encode()
            config_id="sha256:"+hashlib.sha256(config).hexdigest()
            write(root,"image-inspect.json",{"Id":config_id,"RootFS":{"Layers":[diffid]}})
            archive=root/"image.tar"
            with tarfile.open(archive,"w") as saved:
                for name,body in {"manifest.json":json.dumps([{"Config":"config.json","Layers":["layer.tar"]}]).encode(),
                                  "config.json":config,"layer.tar":layer}.items():
                    member=tarfile.TarInfo(name);member.size=len(body);saved.addfile(member,io.BytesIO(body))
            MODULE.snapshot_image(archive,root)
            manifest=MODULE.load(root/"oci-manifest.json")
            self.assertEqual(manifest["layers"][0]["digest"],diffid)
            self.assertEqual(manifest["config"]["digest"],config_id)
            self.assertEqual(MODULE.load(root/"oci-descriptor.json")["digest"],"sha256:"+MODULE.sha(root/"oci-manifest.json"))
            change(root,"image-inspect.json",lambda d:d.update(Id="sha256:"+"0"*64))
            with self.assertRaisesRegex(ValueError,"configuration"):
                MODULE.snapshot_image(archive,root)

if __name__=="__main__":
    unittest.main()
