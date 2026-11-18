#!/usr/bin/env python3
"""Export a user-supplied Motorola CPS2 XCTB to Radio Foundry DM32UV CSV ZIP.

Use a blank template ZIP exported by the target Radio Foundry application.
The six filenames and column headers are retained; the source archive is never changed.
"""
from __future__ import annotations
import argparse, csv, hashlib, io, json, zipfile
from pathlib import Path
from xctb_common import normalize, dm32

REQUIRED={'channels.csv','contacts.csv','zones.csv','rx-group-lists.csv','dtmf-contacts.csv','aprs.csv'}

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('source_xctb',type=Path)
 p.add_argument('--schema',required=True,type=Path,help='Radio Foundry CSV ZIP providing column headers (may contain empty example rows)')
 p.add_argument('--output',required=True,type=Path)
 a=p.parse_args()
 if not a.source_xctb.is_file() or not a.schema.is_file():p.error('Input XCTB and schema ZIP must exist')
 if a.output.exists():p.error('Refusing to overwrite an existing output ZIP')
 if a.output.resolve() in (a.source_xctb.resolve(),a.schema.resolve()):p.error('Output must differ from inputs')
 with zipfile.ZipFile(a.schema) as z:
  if set(z.namelist())!=REQUIRED: p.error('Schema ZIP must contain the six original Radio Foundry CSV filenames')
  for name in REQUIRED:
   row=next(csv.reader(io.StringIO(z.read(name).decode('utf-8-sig'))),[])
   if not row:p.error(f'Missing CSV headers: {name}')
 model=normalize(a.source_xctb)
 if any(m['channel_index'] is None for z in model['zones'] for m in z['members']):raise ValueError('Unresolved zone channel reference: cannot safely convert')
 if any(m['channel_index'] is None for l in model['scan_roam_lists'] for m in l['members']):raise ValueError('Unresolved scan/roam channel reference: cannot safely convert')
 a.output.parent.mkdir(parents=True,exist_ok=True)
 try:
  dm32(model,a.schema,a.output)
  with zipfile.ZipFile(a.output) as z:
   assert z.testzip() is None
   rows=list(csv.DictReader(io.StringIO(z.read('channels.csv').decode('utf-8-sig'))))
   invalid=[(x['Number'],x['Bandwidth (kHz)']) for x in rows if x['Bandwidth (kHz)'] not in ('12.5','25')]
   if invalid:raise ValueError('Unsupported Foundry bandwidth: '+str(invalid[:3]))
 except Exception:
  a.output.unlink(missing_ok=True)
  raise
 print(json.dumps({'output':str(a.output),'channels':len(model['channels']),'zones':len(model['zones']),'contacts':len(model['contacts']),'source_sha256':model['source_sha256'],'output_sha256':hashlib.sha256(a.output.read_bytes()).hexdigest(),'validated':'CSV references and ZIP integrity; CPS import not tested for this source'},indent=2))
if __name__=='__main__':main()
