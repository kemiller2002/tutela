#!/usr/bin/env python3
"""Inspect and safely upgrade an installed Tutela runtime."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from src.tutela_install import INSTALL_SCHEMA_VERSION,TUTELA_VERSION,templates

class UpgradeError(RuntimeError): pass
def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def inspect(root):
 root=Path(root); mp=root/".tutela/install.json"
 if not mp.exists(): return {"status":"UNMANAGED","currentVersion":None,"targetVersion":TUTELA_VERSION,"changes":[]}
 try: m=json.loads(mp.read_text())
 except (ValueError,OSError): return {"status":"INCOMPATIBLE","currentVersion":None,"targetVersion":TUTELA_VERSION,"changes":["invalid install manifest"]}
 if m.get("schemaVersion")!=INSTALL_SCHEMA_VERSION:
  return {"status":"INCOMPATIBLE","currentVersion":m.get("tutelaVersion"),"targetVersion":TUTELA_VERSION,"changes":["unsupported install manifest schema"]}
 owned=m.get("ownership",{}); changes=[]
 for rel in owned.get("repository",[]):
  changes.append({"path":rel,"ownership":"repository","action":"PRESERVE"})
 for rel in owned.get("tutela",[]):
  changes.append({"path":rel,"ownership":"tutela","action":"REFRESH"})
 status="CURRENT" if m.get("tutelaVersion")==TUTELA_VERSION else "UPGRADE_AVAILABLE"
 return {"status":status,"currentVersion":m.get("tutelaVersion"),"targetVersion":TUTELA_VERSION,"changes":changes,"manifest":m}

def upgrade(root):
 root=Path(root); report=inspect(root)
 if report["status"]=="UNMANAGED": raise UpgradeError("installation is unmanaged; bootstrap first")
 if report["status"]=="INCOMPATIBLE": raise UpgradeError("installation manifest is incompatible")
 m=report["manifest"]; before={}
 for rel in m["ownership"].get("repository",[]):
  p=root/rel
  if p.exists(): before[rel]=digest(p)
 generated=templates(m["repository"],m.get("installedRef","HEAD"))
 # Only refresh Tutela-owned assets. Runtime is copied from this exact upgrade tool checkout.
 workflow=generated[".github/workflows/tutela-security.yml"]
 wp=root/".github/workflows/tutela-security.yml"; wp.parent.mkdir(parents=True,exist_ok=True); wp.write_text(workflow)
 source=Path(__file__).with_name("tutela_gate.py"); rp=root/".tutela/runtime/tutela_gate.py"; rp.parent.mkdir(parents=True,exist_ok=True); rp.write_text(source.read_text())
 m["tutelaVersion"]=TUTELA_VERSION; (root/".tutela/install.json").write_text(json.dumps(m,indent=2)+"\n")
 for rel,d in before.items():
  if digest(root/rel)!=d: raise UpgradeError("repository-owned security state changed during upgrade")
 return {"status":"UPGRADED","fromVersion":report["currentVersion"],"toVersion":TUTELA_VERSION,
         "refreshed":[".tutela/runtime/tutela_gate.py",".github/workflows/tutela-security.yml"],
         "preserved":sorted(before)}

def main(argv=None):
 p=argparse.ArgumentParser(description="Inspect or safely upgrade a Tutela installation")
 p.add_argument("root"); p.add_argument("--apply",action="store_true"); a=p.parse_args(argv)
 try: r=upgrade(a.root) if a.apply else inspect(a.root)
 except UpgradeError as exc:
  print(json.dumps({"status":"REFUSED","errorType":type(exc).__name__})); return 4
 print(json.dumps(r,indent=2,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
