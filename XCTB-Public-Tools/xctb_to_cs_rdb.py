#!/usr/bin/env python3
"""Experimental Motorola XCTB -> Connect Systems CS711/CS811 RDB from a genuine donor.

Converts known channels, contacts, one RX group, zones, scan/roam lists,
auto-scan and verified analog tone fields. Uses the CPS-confirmed scan-list
inventory at 0x33500 and CPS-confirmed CS811 continuation-zone records.
Original donor model/serial and unrelated binary fields are retained. Destination
CPS must open, save, and verify every setting; NEVER directly program output.
No factory/hardware passwords, user codeplugs, secrets, or site profiles are bundled.
"""
from __future__ import annotations
import argparse, hashlib, json, struct, collections
from pathlib import Path
from xctb_common import normalize

SIZE=376832
CONTACT_AT=0x3880;CONTACT_BYTES=44;CONTACT_CAP=100
CH_ALIAS=0x15880;CH_AT=0x1d580;CH_BYTES=32;CH_CAP=1000
ZONE_AT=0x25280;ZONE_BYTES=80;ZONE_CAP=64
SCAN_AT=0x2b800;SCAN_BYTES=128;SCAN_CAP=32;SCAN_INDEX=0x33500
ROAM_AT=0x58640;ROAM_BYTES=108;ROAM_CAP=16;ROAM_INDEX=0x58630;ROAM_INDEX_CAP=12

def wstr(buf,pos,length,val):
 raw=str(val).encode('utf-16le')
 if len(raw)>length:raise ValueError(f'Too long for UTF-16 field ({length} bytes): {val!r}')
 buf[pos:pos+length]=raw.ljust(length,b'\0')

def label(val,n,used):
 name=' '.join(str(val or 'Unnamed').replace('|','/').split()).strip()[:16]
 if not name:name=f'Item{n}'
 if name.casefold() in used:
  suff=f'~{n}';name=(name[:16-len(suff)]+suff)
 if name.casefold() in used:raise ValueError('Duplicate field label after truncation: '+name)
 used.add(name.casefold());return name

def tone(kind,value,invert=False):
 if kind in ('CSQ',None,''):return 0xffff
 if kind=='TPL':
  txt=f'{round(float(value)*10):04d}'
  if len(txt)!=4:raise ValueError('CTCSS out of range')
  return int(txt,16)
 if kind=='DPL':
  txt=str(value).replace('D','').replace('N','').replace('I','').zfill(3)
  if len(txt)!=3 or not txt.isdigit():raise ValueError('Invalid DPL: '+str(value))
  return (0xc000 if invert else 0x8000)|int(txt,16)
 raise ValueError('Unsupported tone type: '+str(kind))

def analog_flags(ch):
 rx={'CSQ':0,'TPL':1,'DPL':2}
 tx={'CSQ':0,'TPL':4,'DPL':8}
 return rx[ch['rx_tone_type'] or 'CSQ']|tx[ch['tx_tone_type'] or 'CSQ']

def patch(src,donor,model_name,alias):
 if len(donor)!=SIZE:raise ValueError('Unsupported RDB donor length; expected 376832')
 actual=donor[0x2000:0x2005].decode('ascii','replace')
 if actual!=model_name:raise ValueError(f'Donor radio model {actual!r} does not match --model {model_name!r}')
 if model_name=='CS801':print('WARNING: CS801 layout NOT verified with a genuine CPS sample; investigate before import')
 channels=src['channels'];contacts=src['contacts'];zones=src['zones'];groups=src['rx_groups']
 scan=[x for x in src['scan_roam_lists'] if x['type']=='scan']
 roam=[x for x in src['scan_roam_lists'] if x['type']=='roam']
 if not 0<len(channels)<=CH_CAP or len(contacts)>CONTACT_CAP:raise ValueError('Channel/contact capacity exceeded')
 if len(groups)>1:raise ValueError('More than one RX group is not supported by this observed RDB layout')
 if len(scan)>SCAN_CAP or len(roam)>min(ROAM_CAP,ROAM_INDEX_CAP):raise ValueError('Scan/roam list inventory capacity exceeded')
 if any(c['index']!=i for i,c in enumerate(channels,1)):raise ValueError('Noncontiguous source channel numbering')
 if any(any(m['channel_index'] is None for m in x['members']) for x in zones+scan+roam):raise ValueError('Unresolved source channel reference; refusing lossy export')
 if any(len(x['members'])>32 for x in scan+roam):raise ValueError('Scan/roam member list exceeds observed 32-member capacity')
 if len(zones)>ZONE_CAP:raise ValueError('Zone capacity exceeded')
 b=bytearray(donor)
 # Template records preserve known-good manufacturer mode parameters.
 examples=[bytes(donor[CH_AT+i*32:CH_AT+(i+1)*32]) for i in range(CH_CAP)]
 patterns={mode:next((r for r in examples if r[8]==typ),None) for mode,typ in [('FM',0x17),('DMR',0x14)]}
 if any(v is None for v in patterns.values()):raise ValueError('Donor lacks observed analog or DMR channel records')
 contact_pattern=bytes(donor[CONTACT_AT:CONTACT_AT+CONTACT_BYTES]); rx_pattern=bytes(donor[0x45000:0x45000+44]);scan_pattern=bytes(donor[SCAN_AT:SCAN_AT+SCAN_BYTES]);roam_pattern=bytes(donor[ROAM_AT:ROAM_AT+ROAM_BYTES])
 if not scan_pattern[:2].strip(b'\0') or not roam_pattern[:2].strip(b'\0'):raise ValueError('Donor has no scan or roam record template; provide a different RDB')
 # clear only identified table ranges; retain donor analog 2-tone and device fields.
 b[CH_ALIAS:CH_ALIAS+CH_CAP*32]=bytes(CH_CAP*32)
 b[CH_AT:CH_AT+CH_CAP*CH_BYTES]=bytes(CH_CAP*CH_BYTES)
 b[CONTACT_AT:CONTACT_AT+CONTACT_CAP*CONTACT_BYTES]=bytes(CONTACT_CAP*CONTACT_BYTES)
 b[SCAN_AT:SCAN_AT+SCAN_CAP*SCAN_BYTES]=bytes(SCAN_CAP*SCAN_BYTES)
 b[ROAM_AT:ROAM_AT+ROAM_CAP*ROAM_BYTES]=bytes(ROAM_CAP*ROAM_BYTES)
 b[ZONE_AT:ZONE_AT+ZONE_CAP*ZONE_BYTES]=bytes(ZONE_CAP*ZONE_BYTES)
 # Original Motorola channel order / CPS-visible channel index.
 struct.pack_into('<H',b,0x15082,len(channels))
 for i in range(1022):struct.pack_into('<H',b,0x15084+2*i,i+1 if i<len(channels) else 0)
 # Contact records and CPS-visible display order. Never assume existing donor count equals source count.
 cid={};used=set()
 for i,c in enumerate(contacts,1):
  at=CONTACT_AT+(i-1)*CONTACT_BYTES;b[at:at+CONTACT_BYTES]=contact_pattern
  wstr(b,at,32,label(c['name'],i,used));struct.pack_into('<I',b,at+32,int(c['id']))
  b[at+36]=1;b[at+37]=5 if c['type']=='Private' else 4
  cid[c['uuid']]=i
 donor_n=struct.unpack_from('<H',donor,0x3082)[0]
 donor_display=list(struct.unpack_from('<1000H',donor,0x3084))
 kept=[]
 if 0<=donor_n<=1000 and all(1<=v<=len(contacts) for v in donor_display[:donor_n]) and len(set(donor_display[:donor_n]))==donor_n:
  kept=donor_display[:donor_n]
 order=kept+[x for x in range(1,len(contacts)+1) if x not in kept]
 struct.pack_into('<H',b,0x3082,len(contacts))
 struct.pack_into('<1000H',b,0x3084,*(order+[0]*(1000-len(order))))
 # RX group: one verified table with up to 24 contacts.
 if groups:
  g=groups[0];members=g['contact_indices']
  if len(members)>24 or any(not 1<=int(x)<=len(contacts) for x in members):raise ValueError('RX group overflow or invalid contact member')
  b[0x45000:0x45000+128*44]=bytes(128*44)
  for j,co in enumerate(members,1):
   source=contacts[co-1];at=0x45000+(j-1)*44
   b[at:at+44]=rx_pattern;wstr(b,at,32,label(source['name'],j,set()))
   struct.pack_into('<I',b,at+32,int(source['id']));b[at+36]=1;b[at+37]=5 if source['type']=='Private' else 4
  at=58784;b[at:at+84]=bytes(84)
  struct.pack_into('<I',b,at,len(members));wstr(b,at+4,32,g['name'][:16])
  struct.pack_into('<24H',b,at+36,*(list(range(1,len(members)+1))+[0]*(24-len(members))))
 # Scan/roam CPS inventories, with the REAL CPS-saved scan index at 0x33500.
 scan_map={};roam_map={};seen=set()
 for i,li in enumerate(scan,1):
  members=[int(x['channel_index']) for x in li['members']];at=SCAN_AT+(i-1)*SCAN_BYTES
  b[at:at+SCAN_BYTES]=scan_pattern;wstr(b,at,32,label(li['name'],i,seen))
  b[at+38]=len(members);struct.pack_into('<32H',b,at+64,*(members+[0]*(32-len(members))))
  scan_map[li['uuid']]=i
 struct.pack_into('<H',b,SCAN_INDEX,len(scan))
 b[SCAN_INDEX+2:SCAN_INDEX+2+SCAN_CAP]=bytes(list(range(1,len(scan)+1))+[0]*(SCAN_CAP-len(scan)))
 seen=set()
 for i,li in enumerate(roam,1):
  members=[int(x['channel_index']) for x in li['members']]
  if any(channels[v-1]['mode']!='DMR' for v in members):raise ValueError('Analog channel in DMR roaming list')
  at=ROAM_AT+(i-1)*ROAM_BYTES;b[at:at+ROAM_BYTES]=roam_pattern
  wstr(b,at,32,label(li['name'],i,seen));b[at+32]=len(members)
  struct.pack_into('<32H',b,at+44,*(members+[0]*(32-len(members))))
  roam_map[li['uuid']]=i
 struct.pack_into('<I',b,ROAM_INDEX,len(roam))
 b[ROAM_INDEX+4:ROAM_INDEX+4+ROAM_INDEX_CAP]=bytes(list(range(1,len(roam)+1))+[0]*(ROAM_INDEX_CAP-len(roam)))
 # Channel records. Known offset +27 is analog squelch type, NOT a tone value.
 for i,ch in enumerate(channels,1):
  wstr(b,CH_ALIAS+(i-1)*32,32,ch['name'])
  rec=bytearray(patterns[ch['mode']]);struct.pack_into('<II',rec,0,round(ch['tx_mhz']*1e6),round(ch['rx_mhz']*1e6))
  rec[8]=0x17 if ch['mode']=='FM' else 0x14
  rec[9]=(rec[9]&~3)|(2 if ch['rx_only'] else 0)|(1 if ch['auto_scan'] else 0)
  uid=ch['scan_roam_uuid']
  if uid in scan_map:struct.pack_into('<H',rec,12,scan_map[uid])
  elif uid in roam_map:
   if ch['mode']!='DMR':raise ValueError('FM channel with DMR roaming list')
   struct.pack_into('<H',rec,12,roam_map[uid]);rec[17]=0x2c
  elif uid in (None,'NONE',''):struct.pack_into('<H',rec,12,0xffff)
  else:raise ValueError('Unresolved scan/roam UUID on channel '+ch['name'])
  if ch['mode']=='FM':
   struct.pack_into('<HH',rec,16,tone(ch['rx_tone_type'],ch['rx_tone_value'],ch['rx_invert']),tone(ch['tx_tone_type'],ch['tx_tone_value'],ch['tx_invert']))
   rec[22]=0;rec[24]=0;rec[27]=analog_flags(ch)
  else:
   rec[16]=(rec[16]&0xe0)|(ch['color_code']&0xf)|(0x10 if ch['timeslot']==2 else 0)
   rec[20]=1 if ch['rx_group'] else 0;rec[22]=1 if ch['rx_group'] else 0
   rec[24]=cid.get(ch['contact_uuid'],0)
   if uid not in roam_map:rec[17]&=~0x20
  b[CH_AT+(i-1)*32:CH_AT+i*32]=rec
 # Zones: CS711 16-member named banks; CS811 16-member fixed physical continuation
 # records with SAME logical zone number, blank continuation names and total count.
 pages=[];seen=set()
 for zone_no,z in enumerate(zones,1):
  members=[int(x['channel_index']) for x in z['members']]
  if not members:continue
  for j,start in enumerate(range(0,len(members),16),1):
   part=members[start:start+16]
   if model_name=='CS711':
    n=len(pages)+1
    zn=label(z['name'] if j==1 else z['name'][:13]+'-'+str(j),n,seen)
    logical_n=n;total=len(part);physical_name=zn
   else:
    zn=label(z['name'],zone_no,seen) if j==1 else ''
    logical_n=zone_no;total=len(members);physical_name=zn
   pages.append((logical_n,physical_name,part,total))
 if len(pages)>ZONE_CAP:raise ValueError(f'Exceeded {ZONE_CAP} physical zone records')
 for i,(zone_no,name,members,total) in enumerate(pages):
  at=ZONE_AT+i*ZONE_BYTES
  wstr(b,at,32,name);b[at+36]=len(members);b[at+37]=1 if i==0 else 0
  struct.pack_into('<H',b,at+38,zone_no);struct.pack_into('<H',b,at+40,total)
  struct.pack_into('<16H',b,at+48,*(members+[0]*(16-len(members))))
 # Clear the observed password/lock region (not hardware identity). Unknown donor keys must be checked manually.
 b[0x2300:0x2314]=bytes(0x14)
 struct.pack_into('<I',b,0x2220,int(src['subscriber_id']))
 wstr(b,0x2200,32,alias[:16])
 out=bytes(b)
 # Independently read back stored count, channel aliases, tones, scan inventory,
 # contact display inventory, zone members and contact refs from the generated bytes.
 if struct.unpack_from('<H',out,SCAN_INDEX)[0]!=len(scan):raise AssertionError('Scan index count wrong')
 if list(out[SCAN_INDEX+2:SCAN_INDEX+2+len(scan)])!=list(range(1,len(scan)+1)):raise AssertionError('Scan index wrong')
 if struct.unpack_from('<H',out,0x3082)[0]!=len(contacts):raise AssertionError('Contact index wrong')
 if struct.unpack_from('<I',out,ROAM_INDEX)[0]!=len(roam):raise AssertionError('Roam inventory wrong')
 if struct.unpack_from('<H',out,0x15082)[0]!=len(channels):raise AssertionError('Channel index wrong')
 for i,ch in enumerate(channels):
  actual=out[CH_ALIAS+i*32:CH_ALIAS+(i+1)*32].decode('utf-16le').split('\0')[0]
  rec=out[CH_AT+i*32:CH_AT+(i+1)*32]
  assert actual==ch['name'] and struct.unpack_from('<II',rec)==(round(ch['tx_mhz']*1e6),round(ch['rx_mhz']*1e6))
  if ch['mode']=='FM':assert rec[27]==analog_flags(ch)
  else:assert rec[24]==cid.get(ch['contact_uuid'],0)
 for i,(zn,name,members,total) in enumerate(pages):
  rec=out[ZONE_AT+i*80:ZONE_AT+(i+1)*80]
  assert struct.unpack_from('<H',rec,38)[0]==zn and struct.unpack_from('<H',rec,40)[0]==total
  assert list(struct.unpack_from('<16H',rec,48))[:len(members)]==members
 return out,{'source_format':src['source_format'],'source_model':src['source_datamodel'],'destination_model':model_name,'channels':len(channels),'contacts':len(contacts),'source_zones':len(zones),'physical_zone_records':len(pages),'scan_lists':len(scan),'roam_lists':len(roam),'rx_groups':len(groups),'two_tone':'Donor definitions preserved; Motorola two-tone NOT migrated','source_sha256':src['source_sha256'],'output_sha256':hashlib.sha256(out).hexdigest(),'status':'BINARY READBACK PASSED; CPS OPEN/SAVE/REOPEN REQUIRED','note':'Donor model/serial and unknown proprietary fields retained; verify RF model/band/privacy keys before programming'}

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('source_xctb',type=Path)
 p.add_argument('--donor',required=True,type=Path,help='Unmodified genuine same-model CPS-exported RDB')
 p.add_argument('--model',required=True,choices=('CS711','CS811','CS801'))
 p.add_argument('--alias',default='Imported XCTB',help='Neutral power-on display alias (up to 16 chars)')
 p.add_argument('--output',required=True,type=Path)
 a=p.parse_args()
 if a.output.exists():p.error('Refusing to overwrite existing output')
 if a.output.resolve() in (a.source_xctb.resolve(),a.donor.resolve()):p.error('Output must differ from source/donor')
 model=normalize(a.source_xctb)
 out,report=patch(model,a.donor.read_bytes(),a.model,a.alias)
 a.output.parent.mkdir(parents=True,exist_ok=True)
 with a.output.open('xb') as fh:fh.write(out)
 report_path=a.output.with_suffix('.audit.json');report_path.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'output':str(a.output),'audit':str(report_path),**report},indent=2))
if __name__=='__main__':main()
