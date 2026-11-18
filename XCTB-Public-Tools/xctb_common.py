#!/usr/bin/env python3
"""Shared Motorola XCTB decoder and programming model normalization.
Uses externally supplied XCTB only; no user-specific codeplugs, keys, or profiles.
"""
from __future__ import annotations
import base64,csv,hashlib,io,json,os,re,struct,sys,zipfile,collections,copy
from pathlib import Path
from lxml import etree
from motorola_decoder import decode_xctb, extract_dbnode

def F(n):return {x.get('Name'):x.get('Value') for x in n if x.tag=='DBNode' and x.get('Name')}

def getgrp(r,name):
 v=r.xpath('.//DBNode[@Name="'+name+'"]');assert len(v)==1,(name,len(v));return [x for x in v[0] if x.tag=='DBNode']

def kids(n,key):
 e=n.xpath('./DBNode[@Name="'+key+'"]');return [x for x in e[0] if x.tag=='DBNode'] if e else []

def name16(s,idx,taken):
 s=' '.join(str(s or '').replace('|','/').replace('\r',' ').replace('\n',' ').split()).strip() or 'Unnamed'
 n=s[:16]
 if n.casefold() not in taken:
  taken.add(n.casefold());return n
 suffix='~'+str(idx)
 n=s[:16-len(suffix)]+suffix
 while n.casefold() in taken:
  suffix='~'+str(idx)+'x';n=s[:16-len(suffix)]+suffix
 taken.add(n.casefold());return n

def normalize(source_path):
 source_path=Path(source_path)
 raw=source_path.read_bytes()
 matrix_xml, matrix_root, meta=decode_xctb(raw)
 _packed, db_xml, _report=extract_dbnode(matrix_root,matrix_xml,source_path.name,hashlib.sha256(raw).hexdigest(),'XCTB',meta)
 r=etree.fromstring(db_xml)
 cr=getgrp(r,'ConventionalPersonality'); cg=getgrp(r,'PCRContacts');zg=getgrp(r,'Zone')
 contact_map={}; contacts=[]
 for node in cg:
  f=F(node); digital=kids(node,'DigitalCalls')
  if not digital:continue
  dc=F(digital[0]); typ={'GRPCALL':'Group','PRIVCALL':'Private','ALLCALL':'All'}.get(dc.get('DU_CALLTYPE'),None)
  if typ is None:typ='Group' if dc.get('DU_CALLTYPE')=='GROUPCALL' else 'Unknown'
  c={'index':len(contacts)+1,'name':f.get('ContactName') or 'Unnamed','id':int(dc.get('DU_CALLLSTID','0') or 0),'type':typ,'raw_type':dc.get('DU_CALLTYPE'),'uuid':node.get('UUID')}
  contacts.append(c);contact_map[c['uuid']]=c
 all_recs=[];used=set();uuid_ch={}
 for i,node in enumerate(cr,1):
  f=F(node);orig=f.get('CP_CNVPERSALIAS') or f'Channel {i}'
  ch={'index':i,'uuid':node.get('UUID'),'source_name':orig,'name':name16(orig,i,used), 'mode':'DMR' if f['CP_PERSTYPE'].startswith('DGTL') else 'FM',
      'rx_mhz':float(f['CP_RXFREQ']),'tx_mhz':float(f['CP_TXFREQ']),
      'rx_only':f.get('CP_RXONLYEN')=='True' or f.get('CP_RXONLY')=='True',
      'power':'Low' if f.get('CP_TXPWR')=='LOWPWR' else 'Max','timeout':int(f.get('CP_TOT') or 0),
      'bandwidth':25.0 if '25KHZ' in f.get('CP_CHNLBWDTH','') else 12.5,
      'color_code':int(f.get('CP_COLORCODE') or 0),'timeslot':2 if f.get('CP_SLTASSGMNT')=='SLOT2' else 1,
      'rx_tone_type':f.get('CP_XSQCHTY'),'tx_tone_type':f.get('CP_TXSQCHTY'),
      'rx_tone_value':f.get('CP_RXTPLFREQ') if f.get('CP_XSQCHTY')=='TPL' else f.get('CP_RXDPLCD') if f.get('CP_XSQCHTY')=='DPL' else '',
      'tx_tone_value':f.get('CP_TXTTPLFREQ') if f.get('CP_TXSQCHTY')=='TPL' else f.get('CP_TXTDPLCD') if f.get('CP_TXSQCHTY')=='DPL' else '',
      'rx_invert':f.get('CP_RXDPLINV')=='True','tx_invert':f.get('CP_TXDPLINV')=='True',
      'contact_uuid':f.get('CP_UKPPERS'),'rxgroup_uuid':f.get('CP_TGLISTIT'),
      'scan_roam_uuid':f.get('CP_SCNROAMLISTIT'),'auto_scan':f.get('CP_UTOSCANEN')=='True',
      'vox':f.get('CP_VOXSTATE')=='True', 'original_personality_type':f.get('CP_PERSTYPE')}
  ch['tx_contact']=contact_map.get(ch['contact_uuid'])
  all_recs.append(ch);uuid_ch[ch['uuid']]=ch
 # Map scan / roam and preserve membership by UUID.
 lsts={};lists=[]
 zoneitem_to_channel={}
 for zn in zg:
  for membernode in kids(zn,'ZoneItems'):
   u=F(membernode).get('ZP_PERSIT')
   if u in uuid_ch:zoneitem_to_channel[membernode.get('UUID')]=uuid_ch[u]
 for label,group,field,member,ref in [('scan','ScanItems','SP_SCANLISTALIAS','ScanListItems','SP_CNVPERCOMP'),('roam','RoamList','SSP_SCANLISTALIAS','RoamListItems','SSP_CNVPERCOMP')]:
  for i,node in enumerate(getgrp(r,group),1):
   f=F(node)
   members=[]
   for it in kids(node,member):
    u=F(it).get(ref);ch=uuid_ch.get(u) or zoneitem_to_channel.get(u)
    members.append({'source_uuid':u,'channel_index':ch['index'] if ch else None,'channel_name':ch['name'] if ch else None})
   ll={'type':label,'index':i,'uuid':node.get('UUID'),'name':f.get(field),'members':members}
   lists.append(ll);lsts[ll['uuid']]=ll
 for ch in all_recs:ch['scan_roam']=lsts.get(ch['scan_roam_uuid'])
 # Zones reflect references, not just names. A repeated alias is not the same personality.
 zones=[]
 for i,node in enumerate(zg,1):
  f=F(node);members=[]
  for it in kids(node,'ZoneItems'):
   u=F(it).get('ZP_PERSIT');ch=uuid_ch.get(u)
   members.append({'source_uuid':u,'channel_index':ch['index'] if ch else None, 'channel_name':ch['name'] if ch else None})
  zones.append({'index':i,'name':f.get('ZP_ZONEALIAS') or f'Zone {i}','members':members})
 grps=[]
 for node in getgrp(r,'DigitalRXGroupList'):
  f=F(node);members=[]
  for it in kids(node,'DigitalRXGroupListItems'):
   co=contact_map.get(F(it).get('RXTG_DGUCLCOMP'))
   if co:members.append(co['index'])
  grps.append({'uuid':node.get('UUID'),'name':f.get('RXTG_RXTGLISTALIAS'),'contact_indices':members})
 grpmap={x['uuid']:x for x in grps}
 for ch in all_recs:ch['rx_group']=grpmap.get(ch['rxgroup_uuid'])
 rids=r.xpath('.//DBNode[@Name="RC_SUBSCRIBERID_CPS"]')
 if len(rids)!=1 or not (1<=int(rids[0].get('Value'))<=16776415):raise ValueError('Missing or invalid source subscriber ID')
 subscriber_id=int(rids[0].get('Value'))
 model={'subscriber_id':subscriber_id,'source_file':source_path.name,'source_sha256':hashlib.sha256(raw).hexdigest(),
  'source_format':'Motorola CPS2 XCTB','source_datamodel':meta['DATA_MODEL'],
  'channels':all_recs,'zones':zones,'contacts':contacts,'rx_groups':grps,'scan_roam_lists':lists}
 return model

def fmt_tone(ch,direction):
 kind=ch[direction+'_tone_type'];value=ch[direction+'_tone_value']
 if kind=='TPL':
  try:return f'{float(value):.1f}'
  except:return ''
 if kind=='DPL':
  return 'D'+str(value or '023').zfill(3)+('I' if ch.get(direction+'_invert') else 'N')
 return ''

def read_csv(z,name):
 data=z.read(name).decode('utf-8-sig');return list(csv.DictReader(io.StringIO(data))),list(csv.DictReader(io.StringIO(data)).fieldnames)

def csvbytes(cols,rows):
 out=io.StringIO(newline='');w=csv.DictWriter(out,fieldnames=cols,lineterminator='\r\n',extrasaction='ignore');w.writeheader();w.writerows(rows);return ('\ufeff'+out.getvalue()).encode('utf-8')

def dm32(model, schema_zip, output_zip):
 out=Path(output_zip)
 with zipfile.ZipFile(schema_zip) as original:
  schemas={name:read_csv(original,name) for name in original.namelist() if name.endswith('.csv')}
  target_channels=[];zrows=[];crow=[];grows=[]
  used_contacts=set()
  name_by_id={co['index']:name16(co['name'],co['index'],used_contacts) for co in model['contacts']}
  contact_slot_by_uuid={co['uuid']:co['index'] for co in model['contacts']}
  for c in model['contacts']:
   crow.append({'Number':c['index'],'Name':name_by_id[c['index']],'ID':c['id'],'Call Type':c['type'],'Timeslot':''})
  for g in model['rx_groups']:
   grows.append({'Number':len(grows)+1,'Name':g['name'],'Contacts':'|'.join(name_by_id[i] for i in g['contact_indices'] if i in name_by_id)})
  for ch in model['channels']:
   row=dict.fromkeys(schemas['channels.csv'][1],'')
   row.update({'Number':ch['index'],'Name':ch['name'],'Mode':ch['mode'],
     'RX Frequency (MHz)':f"{ch['rx_mhz']:.6f}", 'TX Frequency (MHz)':f"{ch['tx_mhz']:.6f}",
     'Power':ch['power'],'Timeout (s)':ch['timeout'],'Bandwidth (kHz)':('25' if ch['bandwidth']==25 else '12.5') if ch['mode']=='FM' else '12.5',
     'RX Tone':fmt_tone(ch,'rx') if ch['mode']=='FM' else '',
     'TX Tone':fmt_tone(ch,'tx') if ch['mode']=='FM' else '',
     'Squelch':'0', 'Color Code':ch['color_code'] if ch['mode']=='DMR' else '1',
     'Timeslot':ch['timeslot'] if ch['mode']=='DMR' else '1',
     'TX Contact':name_by_id[contact_slot_by_uuid[ch['contact_uuid']]] if ch['mode']=='DMR' and ch['tx_contact'] else '',
     'RX Group List':ch['rx_group']['name'] if ch['mode']=='DMR' and ch['rx_group'] else '',
     'DMR ID':model['subscriber_id'] if ch['mode']=='DMR' else '', 'RX Only':'Yes' if ch['rx_only'] else 'No',
     'All Skip':'No','Zone Skip':'No','VOX':'Yes' if ch['vox'] else 'No',
     'No Beep':'No','No Eco':'No','DMO':'No',
     'Roaming':'Yes' if ch['scan_roam'] and ch['scan_roam']['type']=='roam' else 'No',
     'Talker Alias TS1':'0','Talker Alias TS2':'0','Use Location':'No',
     'Latitude':'','Longitude':'','SFR':'No','SFR A':'0','SFR B':'0'})
   target_channels.append(row)
  for z in model['zones']:
   zrows.append({'Name':z['name'],'Channels':'|'.join(m['channel_name'] for m in z['members'] if m['channel_name'])})
  replace={'channels.csv':target_channels,'contacts.csv':crow,'zones.csv':zrows,'rx-group-lists.csv':grows}
  with zipfile.ZipFile(out,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
   for name in original.namelist():
    if name in replace:z.writestr(name,csvbytes(schemas[name][1],replace[name]))
    else:z.writestr(name,original.read(name))
 # Verify import references and completeness with real written zip.
 with zipfile.ZipFile(out) as z:
  rows,cols=read_csv(z,'channels.csv');zone_rows,_=read_csv(z,'zones.csv');contacts,_=read_csv(z,'contacts.csv')
  assert len(rows)==len(model['channels'])
  assert len(zone_rows)==len(model['zones'])
  assert set(z.namelist())==set(schemas)
  names=[x['Name'].casefold() for x in rows];assert len(names)==len(set(names))
  known=set(x['Name'] for x in rows)
  for zone in zone_rows:
   for name in zone['Channels'].split('|'):
    if name:assert name in known,(zone['Name'],name)
  knowncontact=set(x['Name'] for x in contacts)
  for c in rows:
   if c['TX Contact']:assert c['TX Contact'] in knowncontact,(c['Name'],c['TX Contact'])
 return out
