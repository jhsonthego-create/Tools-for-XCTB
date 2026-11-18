#!/usr/bin/env python3
"""Experimental reverse export: Motorola XCTB normalized -> patched PD782 Hytera RCDX.
CPS import not certified. Always test in an isolated CPS environment; never directly program.
"""
from pathlib import Path
import copy,hashlib,json,struct,sys,argparse
from xctb_common import normalize
from motorola_decoder import decode_xctb, extract_dbnode
from lxml import etree
from hytera_codec import decrypt, decrypt_block, SBOX, RKEYS, SIG, HEADER_SIZE
from hytera_extract import scan_all_sections, parse_plaintext, active_section_entries

def gmul(a,b):
 res=0
 while b:
  if b&1:res^=a
  a=((a<<1) ^ (0x11b if a&0x80 else 0))&255
  b>>=1
 return res
mul2=[gmul(i,2) for i in range(256)];mul3=[gmul(i,3) for i in range(256)]
def shiftrows(s):
 for row in range(1,4):
  a=[s[row+4*j] for j in range(4)]
  for j in range(4):s[row+4*j]=a[(j+row)%4]
def mixcolumns(s):
 for start in range(0,16,4):
  a,b,c,d=s[start:start+4]
  s[start:start+4]=[mul2[a]^mul3[b]^c^d,a^mul2[b]^mul3[c]^d,a^b^mul2[c]^mul3[d],mul3[a]^b^c^mul2[d]]
def encrypt_block(b):
 if len(b)!=16:raise ValueError('block')
 s=[x^y for x,y in zip(b,RKEYS[0])]
 for roundnum in range(1,5):
  s=[SBOX[x] for x in s]
  shiftrows(s)
  if roundnum<4:mixcolumns(s)
  s=[x^y for x,y in zip(s,RKEYS[roundnum])]
 return bytes(s)
def encrypt_container(rawhead,plaintext):
 if len(rawhead)!=HEADER_SIZE or len(plaintext)<16:raise ValueError('header/payload')
 n=len(plaintext)//16*16
 result=rawhead+b''.join(encrypt_block(plaintext[i:i+16]) for i in range(0,n,16))+plaintext[n:]
 if len(result)!=struct.unpack_from('<I',rawhead,24)[0]:raise ValueError('len mismatch')
 return result

def utf16_into(p,at,maxlen,name):
 b=name.encode('utf-16le');assert len(b)<=maxlen,(at,maxlen,name)
 p[at:at+maxlen]=b+bytes(maxlen-len(b))
def sec_fill(p,sec,records):
 count=len(records)
 if count>sec['capacity']:raise ValueError('section capacity exceeded')
 stride=sec['stride'];struct.pack_into('<H',p,sec['offset']+4,count)
 for j,rec in enumerate(records):
  if len(rec)!=stride:raise ValueError(('size',sec['id'],len(rec),stride))
  p[sec['data_offset']+stride*j:sec['data_offset']+stride*(j+1)]=rec
  struct.pack_into('<HI',p,sec['mapping_offset']+6*j,j,stride*j)

def sec_template(p,sec):
 return bytearray(p[sec['data_offset']:sec['data_offset']+sec['stride']])
def analogtone(kind,value,invert=False):
 if kind not in ('TPL','DPL'):return 0
 if kind=='TPL':return 0x4000|int(round(float(value)*10))
 v=int(str(value),8)
 if v>4095:raise ValueError('DPL out of range')
 return (0xc000 if invert else 0x8000)|v

def set_rx_power(rec,ch):
 rec[33]=(rec[33] & ~5) | (1 if ch['rx_only'] else 0) | (4 if ch['power']=='Low' else 0)

def source_quickcall_ii(source_xctb):
 raw=Path(source_xctb).read_bytes()
 matrix_xml,matrix_root,detail=decode_xctb(raw)
 _,db_xml,_=extract_dbnode(matrix_root,matrix_xml,Path(source_xctb).name,hashlib.sha256(raw).hexdigest(),'XCTB',detail)
 root=etree.fromstring(db_xml)
 systems=root.xpath('.//DBNode[@Name="QCIISYS_QCIISYSALIAS"]')
 system_name=(systems[0].get('Value') if systems else 'QCII') or 'QCII'
 records=[]
 for el in root.xpath('.//DBNode[@Name="QuikCallIICalls"]/DBNode[@UUID]'):
  vals={child.get('Name'):child.get('Value') for child in el if child.tag=='DBNode' and child.get('Value') is not None}
  if not vals.get('QU_TONEATXFRE'):continue
  fmt=vals.get('QU_CALLFORMAT','TWO_TONE')
  if fmt not in ('TWO_TONE','LONG_TONE'):
   raise ValueError('Unknown Motorola Quick Call II format '+str(fmt))
  records.append({'alias':f'QCII-{len(records)+1:03d}', 'format':fmt,
                  'first_tone_hz':float(vals['QU_TONEATXFRE']),
                  'second_tone_hz':float(vals.get('QU_TONEBTXFRE') or 0.0)})
 return system_name,records

def build(source_xctb, donor_path, target_path):
 source_xctb=Path(source_xctb);donor_path=Path(donor_path);target_path=Path(target_path)
 if target_path.exists(): raise FileExistsError(target_path)
 original=donor_path.read_bytes();plaintext=bytearray(decrypt(original));secs=scan_all_sections(plaintext);model=normalize(source_xctb)
 if original[68:100].decode('utf-16le','replace').partition('\0')[0] not in ('PD782','PD782i'):
  raise ValueError('This converter is validated against a PD782 donor RCDX layout only')
 if any(m['channel_index'] is None for z in model['zones'] for m in z['members']):
  raise ValueError('Unresolved Motorola source zone channel')
 if any(m['channel_index'] is None for li in model['scan_roam_lists'] for m in li['members']):
  raise ValueError('Unresolved Motorola scan/roam channel')
 # Verify byte-identical re-encryption before altering any bits.
 assert encrypt_container(original[:HEADER_SIZE],plaintext)==original, 'encryption is not reversible'
 channels=model['channels'];digital=[x for x in channels if x['mode']=='DMR'];analog=[x for x in channels if x['mode']=='FM']
 dig_ids={x['index']:i for i,x in enumerate(digital,1)};ana_ids={x['index']:i for i,x in enumerate(analog,1)}
 if len(model['zones'])>secs[0x24]['capacity']:raise ValueError('zone capacity')
 contact_ids={x['uuid']:i for i,x in enumerate(model['contacts'],1)}
 # Contact section has a FOUR-BYTE per-record prefix; parser sees name at +4,
 # call type at physical +37 and DMR call ID at physical +40.
 records=[];base=sec_template(plaintext,secs[0x2a])
 for i,c in enumerate(model['contacts'],1):
  rec=bytearray(base);utf16_into(rec,4,32,c['name'][:16]);rec[37]={'Private':0,'Group':1,'All':2}.get(c['type'],1)
  struct.pack_into('<I',rec,40,c['id']);records.append(rec)
 sec_fill(plaintext,secs[0x2a],records)
 # Scan and roaming lists: physical source channel index rewritten to destination channel physical index.
 lists=model['scan_roam_lists'];scans=[x for x in lists if x['type']=='scan'];roams=[x for x in lists if x['type']=='roam']
 listids={x['uuid']:i for li in (scans,roams) for i,x in enumerate(li,1)}
 for num,nametype,membertype,group in [('scan',0x6d,0x4d,scans),('roam',0x7a,0x79,roams)]:
  names=[];members=[];namebase=sec_template(plaintext,secs[nametype]);memberbase=sec_template(plaintext,secs[membertype])
  for i,l in enumerate(group):
   name=bytearray(namebase);utf16_into(name,0,32,(l['name'] or f'{num}{i+1}')[:16]);names.append(name)
   m=bytearray(memberbase);marker,cap,_,datasize,mapoff=struct.unpack_from('<HHHII',m,0)
   width=4 if num=='scan' else 2
   assert cap*width==datasize and mapoff==14+datasize
   if len(l['members'])>cap:raise ValueError('Hytera scan/roam exceeds source donor list capacity')
   m[14:14+datasize]=bytes(datasize)
   struct.pack_into('<HHHII',m,0,i,cap,len(l['members']),datasize,mapoff)
   for j,member in enumerate(l['members']):
    x=member['channel_index'];ch=channels[x-1] if x else None
    if num=='scan':
     if ch is None:chnum,kind=65535,0
     elif ch['mode']=='DMR':chnum,kind=dig_ids[x],0
     else:chnum,kind=ana_ids[x],1
     struct.pack_into('<HBB',m,14+width*j,chnum,kind,0)
    else:
     if ch is None:chnum=65535
     elif ch['mode']=='DMR':chnum=dig_ids[x]
     else:raise ValueError('analog source referenced in Hytera roam list '+str(l['name']))
     struct.pack_into('<H',m,14+width*j,chnum)
    struct.pack_into('<HI',m,mapoff+6*j,j,width*j)
   members.append(m)
  sec_fill(plaintext,secs[nametype],names);sec_fill(plaintext,secs[membertype],members)
 # RX group names and membership; contact indexes in list records are 1-based.
 grouplist=model['rx_groups']
 if grouplist:
  gnamebase=sec_template(plaintext,secs[0x8d]);gmemberbase=sec_template(plaintext,secs[0x8c]);names=[];entries=[]
  for i,g in enumerate(grouplist):
   nr=bytearray(gnamebase);utf16_into(nr,0,32,g['name'][:16]);names.append(nr)
   rec=bytearray(gmemberbase);marker,cap,_,datasize,mapoff=struct.unpack_from('<HHHII',rec,0)
   if len(g['contact_indices'])>cap:raise ValueError('rx group > capacity')
   struct.pack_into('<HHHII',rec,0,i,cap,len(g['contact_indices']),datasize,mapoff)
   rec[14:14+datasize]=bytes(datasize)
   for j,co in enumerate(g['contact_indices']):
    struct.pack_into('<I',rec,14+j*4,co)
    struct.pack_into('<HI',rec,mapoff+j*6,j,j*4)
   entries.append(rec)
  sec_fill(plaintext,secs[0x8d],names);sec_fill(plaintext,secs[0x8c],entries)
 # Digital channels: known fields, all other proprietary settings are retained from donor record template.
 base=sec_template(plaintext,secs[0x26]);records=[]
 for i,ch in enumerate(digital):
  rec=bytearray(base);utf16_into(rec,0,32,ch['name']);set_rx_power(rec,ch)
  struct.pack_into('<II',rec,36,round(ch['rx_mhz']*1e6),round(ch['tx_mhz']*1e6))
  rec[45]=min(255,round(ch['timeout']/5))
  rec[49]=(rec[49]&0xf0)|(ch['color_code']&0x0f)
  struct.pack_into('<H',rec,50,contact_ids.get(ch['contact_uuid'],0))
  struct.pack_into('<H',rec,52,1 if ch['rx_group'] else 0)
  struct.pack_into('<H',rec,54,0)
  ll=ch['scan_roam'];rec[56]=listids.get(ch['scan_roam_uuid'],0) if ll else 0
  rec[57]=(rec[57]&~0x21)|(1 if ch['auto_scan'] else 0)
  # CPS requires every roaming-list member to be eligible for IP Multi-site Connect.
  roaming_members={m['channel_index'] for li in roams for m in li['members']}
  if ch['index'] in roaming_members:rec[57]|=0x20
  rec[58]=(rec[58]&~0x77)|(1 if ch['timeslot']==2 else 0)|({'scan':0x10,'roam':0x20}.get(ll['type'],0) if ll else 0)|(0x40 if ch['vox'] else 0)
  if ll and ll['type']=='roam':rec[58]|=0x04 # Auto Roam Start for the roaming personality
  records.append(rec)
 sec_fill(plaintext,secs[0x26],records)
 # Analog channels.
 base=sec_template(plaintext,secs[0x27]);records=[]
 for i,ch in enumerate(analog):
  rec=bytearray(base);utf16_into(rec,0,32,ch['name']);set_rx_power(rec,ch)
  struct.pack_into('<II',rec,36,round(ch['rx_mhz']*1e6),round(ch['tx_mhz']*1e6))
  struct.pack_into('<HH',rec,44,analogtone(ch['rx_tone_type'],ch['rx_tone_value'],ch['rx_invert']),analogtone(ch['tx_tone_type'],ch['tx_tone_value'],ch['tx_invert']))
  rec[54]=min(255,round(ch['timeout']/5))
  ll=ch['scan_roam'];rec[69]=listids.get(ch['scan_roam_uuid'],0) if ll and ll['type']=='scan' else 0
  rec[70]=(rec[70]&~1)|(1 if ch['auto_scan'] else 0)
  rec[71]=(rec[71]&~0x80)|(0x80 if ch['vox'] else 0)
  records.append(rec)
 sec_fill(plaintext,secs[0x27],records)
 # Quick Call II. Preserve CPS donor timing parameters, but replace system/contacts.
 system_name,tone_calls=source_quickcall_ii(source_xctb)
 if tone_calls:
  if len(tone_calls)>secs[0x37]['capacity']:
   raise ValueError('Too many Motorola Quick Call II records for Hytera contact table')
  systmpl=bytearray(active_section_entries(bytes(plaintext),secs[0x36])[0][1])
  utf16_into(systmpl,0,32,system_name[:16])
  sec_fill(plaintext,secs[0x36],[systmpl])
  contacttmpl=bytearray(active_section_entries(bytes(plaintext),secs[0x37])[0][1])
  tone_recs=[]
  for call in tone_calls:
   r=bytearray(contacttmpl);utf16_into(r,0,32,call['alias'])
   r[32]=0 if call['format']=='TWO_TONE' else 1
   r[33]=1
   struct.pack_into('<HH',r,34,round(call['first_tone_hz']*10),round(call['second_tone_hz']*10))
   tone_recs.append(r)
  sec_fill(plaintext,secs[0x37],tone_recs)
 else:
  # Remove unrelated donor QCII entries from the ACTIVE listing; retain unknown storage.
  struct.pack_into('<H',plaintext,secs[0x36]['offset']+4,0)
  struct.pack_into('<H',plaintext,secs[0x37]['offset']+4,0)
 # Zone records and 256-member pointer sets.
 base=sec_template(plaintext,secs[0x24]);zrecords=[]
 for i,z in enumerate(model['zones']):
  if len(z['members'])>256:raise ValueError('Hytera zone capacity exceeded')
  rec=bytearray(base);utf16_into(rec,0,32,z['name'][:16]);struct.pack_into('<H',rec,32,len(z['members']));zrecords.append(rec)
  at=secs[0x23]['data_offset']+i*secs[0x23]['stride']
  old=plaintext[at:at+secs[0x23]['stride']];marker,cap,_,datasize,mapoff=struct.unpack_from('<HHHII',old,0)
  assert cap==256 and datasize==2048 and mapoff==2062
  new=bytearray(old);struct.pack_into('<HHHII',new,0,i,cap,len(z['members']),datasize,mapoff)
  new[14:14+datasize]=bytes(datasize)
  for j,member in enumerate(z['members']):
   ix=member['channel_index'];ch=channels[ix-1]
   if ch['mode']=='DMR':number,kind=dig_ids[ix],0
   else:number,kind=ana_ids[ix],1
   struct.pack_into('<HBB',new,14+j*8,number,kind,0)
   struct.pack_into('<HI',new,mapoff+j*6,j,j*8)
  plaintext[at:at+len(new)]=new
 sec_fill(plaintext,secs[0x24],zrecords)
 struct.pack_into('<H',plaintext,secs[0x23]['offset']+4,len(model['zones']))
 for i in range(len(model['zones'])):
  struct.pack_into('<HI',plaintext,secs[0x23]['mapping_offset']+6*i,i,i*secs[0x23]['stride'])
 # Clear verified password-field positions; no source or donor passwords are migrated.
 for at in (0x748,0x758,0x768):plaintext[at:at+16]=bytes(16)
 # Do not edit donor header radio model/serial identity -- model-specific payload remains donor PD782.
 encoded=encrypt_container(original[:HEADER_SIZE],bytes(plaintext))
 target_path.parent.mkdir(parents=True,exist_ok=True)
 target_path.write_bytes(encoded)
 assert decrypt(encoded)==bytes(plaintext),'RCDX encryption/decryption roundtrip mismatch'
 decoded=parse_plaintext(bytes(plaintext))
 stats=decoded['statistics']
 assert (stats['digital_channels'],stats['analog_channels'],stats['zones'],stats['dmr_contacts'])==(len(digital),len(analog),len(model['zones']),len(model['contacts']))
 assert stats['zone_memberships']==sum(len(z['members']) for z in model['zones'])
 if stats['two_tone_contacts']!=len(tone_calls):
  raise ValueError('Quick Call II contact count readback mismatch')
 if stats['unresolved_zone_members'] or stats['unresolved_scan_members'] or stats['unresolved_roam_members']:
  raise ValueError('Unresolved Hytera reference '+str(stats))
 for i,c in enumerate(model['contacts']):
  actual=decoded['dmr_contacts'][i]
  if actual['call_id']!=c['id'] or actual['name']!=c['name'][:16] or actual['call_type_raw']!={'Private':0,'Group':1,'All':2}.get(c['type'],1):
   raise ValueError('Hytera contact readback mismatch: '+str((i,c,actual)))
 audit={'source':model['source_file'],'output':target_path.name,'template':donor_path.name,
  'hytera_model_from_donor':'PD782','CPS_import_verified':False,'programming_safe':False,
  'quick_call_ii_contacts':len(tone_calls),'quick_call_ii_system':system_name if tone_calls else None,
  'known_fields_patched':['channel names','analog/digital rx/tx frequencies','color code','timeslot','TX contact','RX group','scan/roam lists','zones','receive/transmit tones','RX-only','power','timeout'],
  'retained_unmapped_proprietary_fields':'Donor-specific PD782 settings, privacy key slots, radio hardware identity; inspect for privacy keys before programming or sharing any generated RCDX',
  'source_radio_identity_migration':'Only programming/alias records changed; donor model/serial retained',
  'decoded_stats':stats,'sha256':hashlib.sha256(encoded).hexdigest(),'roundtrip':'Full ciphertext decrypts back to patched plaintext exactly; not a Hytera CPS validation'}
 target_path.with_suffix('.audit.json').write_text(json.dumps(audit,indent=2)+'\n')
 print('WROTE',target_path,'bytes',len(encoded),'SHA',audit['sha256'],'STATS',stats)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('source_xctb',type=Path)
 p.add_argument('--donor',required=True,type=Path,help='Genuine model-compatible Hytera PD782 RCDX')
 p.add_argument('--output',required=True,type=Path)
 args=p.parse_args()
 if args.output.resolve() in (args.source_xctb.resolve(),args.donor.resolve()):p.error('Output may not overwrite either source')
 build(args.source_xctb,args.donor,args.output)
