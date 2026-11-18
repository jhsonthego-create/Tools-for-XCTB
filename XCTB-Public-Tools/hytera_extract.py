#!/usr/bin/env python3
"""Extract authenticated Hytera RCDX RCDB sections, without Windows CPS.

Supported tables in supplied PD782/PD662i RCDX variants:
  0x23 Zone ChannelPointerSection (all zone memberships and ordering)
  0x24 Zone names
  0x26 DMR channels: names, frequencies, slot, contact, RX group, scan/roam refs
  0x27 Analog channels: names, frequencies and raw option bytes
  0x2A DMR contacts: names, call type and ID
  0x36/0x37 two-tone systems and contacts
  0x4D/0x6D scan membership/names; 0x79/0x7A roaming membership/names
  0x8C/0x8D DMR RX-group membership/names

Uses hytera_codec.py (fixed 4-round AES CPS container cipher), which is
part of this same distribution. Unrecognized settings are exposed as raw hex,
not silently guessed. Excludes HDC1200, 5-tone and phone list.
"""
import argparse
import csv
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path
from hytera_codec import decrypt, KEY

# Offsets refer to the *decoded RCDX PAYLOAD*, excluding the 211-byte header.
# These positions are verified against all three user-provided codeplugs.
TABLES={
    'zones':        (0x24,235706,40,22),
    'digital':      (0x26,240768,96,22),
    'analog':       (0x27,345136,100,22),
    'dmr_contacts': (0x2A,453792,48,26),
}
ZONE_POINTER_BASE=5050
ZONE_POINTER_STRIDE=3598
# Dynamically indexed tables support deleted records and arbitrary physical ordering.
EXTRA_SECTION_TYPES={
    'scan_members':0x4d, 'scan_names':0x6d, 'roam_members':0x79,
    'roam_names':0x7a, 'rx_group_members':0x8c, 'rx_group_names':0x8d,
}

def scan_all_sections(p):
    if len(p)<0x392:raise ValueError('RCDB payload too short for section index')
    end=u32(p,0x38e)
    if not 0x392 < end <= len(p):raise ValueError(f'Invalid section index end: {end}')
    pos=0x392;sections={}
    while pos<end:
        if pos+22>end:raise ValueError('Truncated section header')
        typ,capraw,count,constant,unk2,size,check=struct.unpack_from('<HHHIIII',p,pos)
        cap=capraw&0xfff
        if constant!=32 or check!=size+22 or not cap or count>cap or size%cap:
            raise ValueError(f'Invalid section at 0x{pos:x}: {typ,cap,count,size}')
        nextpos=pos+22+size+6*cap
        if nextpos>len(p):raise ValueError(f'Section 0x{typ:x} extends beyond payload')
        if typ in sections:raise ValueError(f'Duplicate section 0x{typ:x}')
        sections[typ]={'id':typ,'offset':pos,'capacity':cap,'count':count,
                       'stride':size//cap,'data_offset':pos+22,
                       'mapping_offset':pos+22+size,'total_bytes':nextpos-pos}
        pos=nextpos
    if pos<end:raise ValueError('Section index ended prematurely')
    return sections

def active_section_entries(p,section):
    vals=[];seen=set()
    for i in range(section['count']):
        phys,off=struct.unpack_from('<HI',p,section['mapping_offset']+i*6)
        if phys in seen or phys>=section['capacity'] or off != phys*section['stride']:
            raise ValueError(f"Bad active mapping in section 0x{section['id']:x} entry {i}")
        seen.add(phys)
        start=section['data_offset']+off
        vals.append((phys+1,p[start:start+section['stride']]))
    return vals

def named_pointer_list(p,sections,name_type,member_type,digital,analog,encoding):
    names=active_section_entries(p,sections[name_type])
    member_sections=active_section_entries(p,sections[member_type])
    members_by_id=dict(member_sections)
    if not set(k for k,_ in names).issubset(members_by_id):
        raise ValueError(f'Missing pointer-list sections for 0x{name_type:x}')
    dig_by_id={c['index']:c for c in digital}; ana_by_id={c['index']:c for c in analog}
    results=[]
    for logical_idx,(phys_id,name_record) in enumerate(names,1):
        rec=members_by_id[phys_id]
        hdr_id,capacity,count,data_size,map_off=struct.unpack_from('<HHHII',rec,0)
        expected_width=4 if encoding=='channel' else 2
        if hdr_id!=phys_id-1 or count>capacity or data_size!=capacity*expected_width or map_off!=14+data_size:
            raise ValueError(f'Invalid list header 0x{member_type:x} physical={phys_id}')
        if map_off+6*capacity>len(rec):raise ValueError('Truncated list mapping array')
        entries=[]
        for j in range(count):
            slot,offset=struct.unpack_from('<HI',rec,map_off+6*j)
            if slot>=capacity or offset>=data_size or offset%expected_width:
                raise ValueError('Invalid pointer-list membership mapping')
            if encoding=='channel':
                chidx,kind,flags=struct.unpack_from('<HBB',rec,14+offset)
                if chidx==65535:
                    entries.append({'position':j+1,'channel_name':'Selected','type':'selected','source_index':chidx,'flags':flags});continue
                ch=(dig_by_id if kind==0 else ana_by_id if kind==1 else {}).get(chidx)
                unresolved=ch is None
                entries.append({'position':j+1,'channel_name':ch['name'] if ch else '',
                                'type':'digital' if kind==0 else 'analog' if kind==1 else 'unknown',
                                'source_index':chidx,'flags':flags,'unresolved':unresolved,
                                'warning':f'Unresolved scan member #{chidx}, type {kind}' if unresolved else ''})
            else:
                chidx=u16(rec,14+offset)
                if chidx==65535:
                    entries.append({'position':j+1,'channel_name':'Selected','type':'selected','source_index':chidx});continue
                ch=dig_by_id.get(chidx)
                unresolved=ch is None
                entries.append({'position':j+1,'channel_name':ch['name'] if ch else '',
                                'type':'digital','source_index':chidx,'unresolved':unresolved,
                                'warning':f'Unresolved roam member #{chidx}' if unresolved else ''})
        results.append({'index':logical_idx,'physical_id':phys_id,'name':utf16(name_record[:32]),'channel_count':count,'members':entries,'raw_record_hex':name_record.hex()})
    return results

def parse_two_tone(p,sections):
    systems=[]
    for logical_idx,(physical_id,r) in enumerate(active_section_entries(p,sections[0x36]),1):
        systems.append({'index':logical_idx,'physical_id':physical_id,'name':utf16(r[:32]),'raw_record_hex':r.hex()})
    by_id={x['physical_id']:x for x in systems}
    contacts=[]
    for logical_idx,(physical_id,r) in enumerate(active_section_entries(p,sections[0x37]),1):
        system_physical_id=r[33]
        system=by_id.get(system_physical_id)
        contacts.append({'index':logical_idx,'physical_id':physical_id,
                         'name':utf16(r[:32]),
                         'encode_format':{0:'Two Tone',1:'Long Tone'}.get(r[32],f'Unknown {r[32]}'),
                         'two_tone_system_id':system_physical_id,
                         'two_tone_system_name':system['name'] if system else None,
                         'first_tone_hz':u16(r,34)/10,
                         'second_tone_hz':u16(r,36)/10,
                         'raw_record_hex':r.hex()})
    return systems,contacts

def parse_rx_groups(p,sections,contacts):
    names=active_section_entries(p,sections[0x8d])
    group_records=dict(active_section_entries(p,sections[0x8c]))
    contacts_by_id={c['index']:c for c in contacts}
    groups=[]
    for idx,(physical_id,name_record) in enumerate(names,1):
        r=group_records.get(physical_id)
        if r is None:raise ValueError('Missing RX group membership section')
        marker,capacity,count,data_size,map_offset=struct.unpack_from('<HHHII',r,0)
        if marker!=physical_id-1 or capacity*4!=data_size or map_offset!=14+data_size or count>capacity:
            raise ValueError('Unexpected RX group layout')
        entries=[]
        for j in range(count):
            _,off=struct.unpack_from('<HI',r,map_offset+6*j)
            if off>=data_size or off%4:raise ValueError('Invalid RX group mapping')
            ref=u16(r,14+off)
            c=contacts_by_id.get(ref)
            entries.append({'position':j+1,'contact_index':ref,'contact_name':c['name'] if c else None})
        groups.append({'index':idx,'physical_id':physical_id,'name':utf16(name_record[:32]),'contact_count':len(entries),'members':entries})
    return groups

def u16(data,pos):return struct.unpack_from('<H',data,pos)[0]
def u32(data,pos):return struct.unpack_from('<I',data,pos)[0]
def utf16(b):return b.decode('utf-16le',errors='replace').split('\0')[0].strip()
def inspect_table(p,tag):
    number,start,stride,delta=TABLES[tag]
    t,cap,count=struct.unpack_from('<HHH',p,start)
    if t!=number or count>cap:raise ValueError(f'Unexpected {tag} table: id=0x{t:x} count={count} cap={cap}')
    # RCDB tables use a live logical-to-physical mapping. Physical storage
    # contains old/deleted records that MUST NOT be treated as live entries.
    mapping_offset=u32(p,start+18)
    records=[]
    seen=set()
    for order in range(count):
        physical_id, offset=struct.unpack_from('<HI',p,start+mapping_offset+6*order)
        if offset%stride or offset//stride != physical_id or physical_id>=cap:
            raise ValueError(f'{tag} invalid mapping {order}: physical_id={physical_id}, offset={offset}')
        if physical_id in seen:raise ValueError(f'{tag} duplicate active physical slot {physical_id}')
        seen.add(physical_id)
        r=p[start+delta+offset:start+delta+offset+stride]
        if len(r)!=stride:raise ValueError(f'Truncated {tag} record at physical slot {physical_id}')
        records.append((physical_id+1,r)) # physical ID is zero-based in map
    return records

def common_channel_fields(r):
    return {'rx_only':bool(r[33]&1),
            'power_level':'Low' if r[33]&4 else 'High'}

def decode_analog_tone(data):
    raw=u16(data,0)
    kind=(raw>>14)&3
    val=raw&0xfff
    if kind==0:return {'type':'None','value':None,'raw':raw}
    if kind==1:return {'type':'CTCSS','value':round(val/10,1),'raw':raw}
    # DCS is represented as an integer that is displayed in octal (131 octal=89 decimal).
    if kind in (2,3):return {'type':'CDCSS' if kind==2 else 'CDCSS Inverted',
                             'value':format(val,'03o'),'raw':raw}
    raise ValueError(f'Invalid analog tone {raw}')

def parse_contact(r,i):
    # Name starts at +4 inside contact record; first 4 bytes are record metadata.
    name=utf16(r[:32])
    call_type_raw=r[33]
    return {'index':i,'name':name,'call_type':{0:'Private Call',1:'Group Call',2:'All Call'}.get(call_type_raw, f'Unknown {call_type_raw}'),
        'call_type_raw':call_type_raw,'call_id':u32(r,36),'raw_record_hex':r.hex()}

def parse_digital(r,i,contacts_by_physical):
    name=utf16(r[:32]);txidx=u16(r,50);cc=r[49]&0x0f
    mode=r[58]&3
    timeslot={0:'Slot 1',1:'Slot 2',3:'Pseudo Trunk'}.get(mode,'Unknown')
    list_type={0x00:'None',0x10:'Scan list',0x20:'Roam list'}.get(r[58]&0x30,'Unknown')
    c=contacts_by_physical.get(txidx)
    return {'index':i,'name':name,'rx_mhz':u32(r,36)/1e6,'tx_mhz':u32(r,40)/1e6,
            'colour_code':cc,'color_code':cc,'timeslot':timeslot,'timeslot_code':mode,
            'tx_contact_index':txidx,'tx_contact_name':c['name'] if c else None,
            'tx_contact_call_id':c['call_id'] if c else None,
            'tx_contact_call_type':c['call_type'] if c else None,
            'rx_group_index':u16(r,52),'emergency_system_index':u16(r,54),
            'scan_roam_type':list_type,'scan_roam_index':r[56],
            'auto_start_scan':bool(r[57]&1),'auto_start_roam':bool(r[58]&4),
            'ip_multi_site_connect':bool(r[57]&0x20),'vox':bool(r[58]&0x40),
            'tx_timeout_s':r[45]*5,**common_channel_fields(r),'raw_record_hex':r.hex()}

def parse_analog(r,i):
    rx_tone=decode_analog_tone(r[44:46]);tx_tone=decode_analog_tone(r[46:48])
    return {'index':i,'name':utf16(r[:32]),'rx_mhz':u32(r,36)/1e6,'tx_mhz':u32(r,40)/1e6,
            **common_channel_fields(r),
            'rx_tone_type':rx_tone['type'],'rx_tone_value':rx_tone['value'],
            'tx_tone_type':tx_tone['type'],'tx_tone_value':tx_tone['value'],
            'rx_tone_raw':rx_tone['raw'],'tx_tone_raw':tx_tone['raw'],
            'rx_squelch_mode_code':r[48], 'monitor_squelch_mode_code':r[49],
            'tx_timeout_s':r[54]*5,'scan_list_index':r[69],
            'auto_start_scan':bool(r[70]&1),'compandor':bool(r[70]&0x20),
            'scrambler':bool(r[70]&0x40),'vox':bool(r[71]&0x80),
            'raw_record_hex':r.hex()}

def parse_zones(p,records,digital,analog):
    results=[]
    digital_by_id={c['index']:c for c in digital}
    analog_by_id={c['index']:c for c in analog}
    for logical_i,(zone_physical_id,r) in enumerate(records,1):
        zi=zone_physical_id-1
        expected_count=u16(r,32)
        ptrpos=ZONE_POINTER_BASE+zi*ZONE_POINTER_STRIDE
        marker,capacity,count,data_size,map_offset=struct.unpack_from('<HHHII',p,ptrpos)
        if marker!=zi or capacity!=256 or count!=expected_count or data_size!=2048 or map_offset!=2062:
            raise ValueError(f'Zone {zi+1} pointer-section validation failed: {(marker,capacity,count,data_size,map_offset)}, name={utf16(r[:32])!r}')
        members=[]
        for mi in range(count):
            map_index,offset=struct.unpack_from('<HI',p,ptrpos+map_offset+6*mi)
            if map_index!=mi or offset>=data_size:
                raise ValueError(f'Zone {zi+1} mapping entry {mi+1} invalid')
            ch_idx,kind,flags=struct.unpack_from('<HBB',p,ptrpos+14+offset)
            kind_name={0:'digital',1:'analog'}.get(kind,'unknown')
            channel=(digital_by_id if kind==0 else analog_by_id if kind==1 else {}).get(ch_idx)
            unresolved = channel is None and ch_idx != 65535
            members.append({'position':mi+1,'type':kind_name,'source_index':ch_idx,
                            'channel_name':channel['name'] if channel else ('Selected' if ch_idx==65535 else ''),
                            'unresolved':unresolved,
                            'warning':f'Zone {zi+1} position {mi+1}: missing active {kind_name} channel slot #{ch_idx}' if unresolved else '',
                            'flags':flags})
        results.append({'index':logical_i,'physical_id':zone_physical_id,'name':utf16(r[:32]),'members':members,'channel_count':len(members),
                        'inconsistent_member_counts':False,
                        'unresolved_members':sum(m['unresolved'] for m in members)})
    return results

def decode_password_fields(p):
    """Password strings from decoded RCDX payload.

    Field roles confirmed by controlled file with distinct user-provided values:
    0x748 radio lock=123123, 0x758 CPS wire lock=456456,
    0x768 read lock=789789. 0x778 remains unidentified.
    Treat results as sensitive credentials.
    """
    fields = ((0x748, 'radio_lock'), (0x758, 'cps_wire_lock'),
              (0x768, 'read_lock'), (0x778, 'unknown_field_0x778'))
    return {label: p[off:off+16].decode('utf-16le', errors='replace').split('\0')[0]
            for off, label in fields}

def capitalization_collisions(names):
    """Report case-only duplicates without changing their spelling."""
    from collections import defaultdict
    groups=defaultdict(set)
    for name in names:
        if name: groups[name.casefold()].add(name)
    return [sorted(values) for values in groups.values() if len(values)>1]

def parse_plaintext(p):
    records={tag:inspect_table(p,tag) for tag in TABLES}
    contacts=[parse_contact(r,physical_id) for physical_id,r in records['dmr_contacts']]
    contacts_by_physical={c['index']:c for c in contacts}
    digital=[parse_digital(r,physical_id,contacts_by_physical) for physical_id,r in records['digital']]
    analog=[parse_analog(r,physical_id) for physical_id,r in records['analog']]
    # Two independent IDs: index is the physical slot ID for references;
    # source_order is the original row order visible in Hytera CPS.
    for tag,entries in [('digital',digital),('analog',analog),('dmr_contacts',contacts)]:
        for source_order,entry in enumerate(entries,1):entry['source_order']=source_order
    zones=parse_zones(p,records['zones'],digital,analog)
    sections=scan_all_sections(p)
    scans=named_pointer_list(p,sections,0x6d,0x4d,digital,analog,'channel')
    roams=named_pointer_list(p,sections,0x7a,0x79,digital,analog,'roam')
    rxgroups=parse_rx_groups(p,sections,contacts)
    tone_systems,tone_contacts=parse_two_tone(p,sections)
    scan_by_id={x['physical_id']:x for x in scans}
    roam_by_id={x['physical_id']:x for x in roams}
    groups_by_id={x['physical_id']:x for x in rxgroups}
    for c in digital:
        kind=c['scan_roam_type'];ref=c['scan_roam_index']
        target=scan_by_id if kind=='Scan list' else roam_by_id if kind=='Roam list' else {}
        c['scan_roam_name']=target[ref]['name'] if ref in target else None
        c['rx_group_name']=groups_by_id[c['rx_group_index']]['name'] if c['rx_group_index'] in groups_by_id else None
    for c in analog:
        ref=c['scan_list_index'];c['scan_list_name']=scan_by_id[ref]['name'] if ref in scan_by_id else None
    return {'password_fields':decode_password_fields(p), 'radio_model':p[242:272].decode('utf-16le',errors='replace').split('\0')[0],
        'capitalization_collisions':{'zones':capitalization_collisions(z['name'] for z in zones), 'channels':capitalization_collisions(c['name'] for c in digital+analog), 'contacts':capitalization_collisions(c['name'] for c in contacts)},'zones':zones,'scan_lists':scans,'roam_lists':roams,'rx_group_lists':rxgroups,
        'two_tone_systems':tone_systems,'two_tone_contacts':tone_contacts,
        'digital_channels':digital,'analog_channels':analog,'dmr_contacts':contacts,
        'section_inventory':[{'id_hex':f'0x{n:04X}',**{k:v for k,v in s.items() if k!='id'}} for n,s in sections.items()],
        'statistics':{'zones':len(zones),'zone_memberships':sum(z['channel_count'] for z in zones),
                      'digital_channels':len(digital),'analog_channels':len(analog),'dmr_contacts':len(contacts),
                      'scan_lists':len(scans),'roam_lists':len(roams),'rx_group_lists':len(rxgroups),
                      'two_tone_contacts':len(tone_contacts),
                      'timeslots':dict(Counter(c['timeslot'] for c in digital)),
                      'inconsistent_zone_count_records':0,
                      'unresolved_zone_members':sum(z['unresolved_members'] for z in zones),
                      'unresolved_scan_members':sum(m.get('unresolved',False) for g in scans for m in g['members']),
                      'unresolved_roam_members':sum(m.get('unresolved',False) for g in roams for m in g['members'])}}

def save_csv(path, rows):
    if not rows:return
    cols=list(rows[0].keys())
    with path.open('x',newline='',encoding='utf-8-sig') as fh:
        writer=csv.DictWriter(fh,fieldnames=cols,extrasaction='ignore');writer.writeheader();writer.writerows(rows)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('inputs',nargs='+',type=Path)
    ap.add_argument('--outdir',type=Path,required=True)
    ap.add_argument('--include-decoded-bin',action='store_true',help='write lossless decoded payload (private)')
    ap.add_argument('--dump-all-sections',action='store_true',help='dump each indexed section, including unused slots and unknown fields (private)')
    args=ap.parse_args()
    args.outdir.mkdir(parents=True,exist_ok=True)
    for f in args.inputs:
        raw=f.read_bytes();p=decrypt(raw);parsed=parse_plaintext(p)
        for group in parsed['zones']+parsed['scan_lists']+parsed['roam_lists']:
            for member in group['members']:
                if member.get('unresolved'):
                    print('WARNING: '+member['warning'],file=__import__('sys').stderr)
        parsed['source_filename']=f.name
        parsed['source_sha256']=hashlib.sha256(raw).hexdigest()
        parsed['payload_sha256']=hashlib.sha256(p).hexdigest()
        base=args.outdir/f.stem
        sectiondir=Path(str(base)+'.sections')
        if args.dump_all_sections and sectiondir.exists():
            raise FileExistsError(f'No overwrite: {sectiondir}')
        for suffix in ('.json','.digital.csv','.analog.csv','.dmr_contacts.csv','.zones.csv','.zone_members.csv','.scan_lists.csv','.scan_members.csv','.roam_lists.csv','.roam_members.csv','.rx_group_lists.csv','.rx_group_members.csv','.two_tone_contacts.csv','.two_tone_systems.csv','.decoded-payload.bin'):
            if suffix!='.decoded-payload.bin' or args.include_decoded_bin:
                if Path(str(base)+suffix).exists():raise FileExistsError(f'No overwrite: {base}{suffix}')
        Path(str(base)+'.json').write_text(json.dumps(parsed,indent=2,ensure_ascii=False)+'\n')
        for tag,rows in [('digital',parsed['digital_channels']),('analog',parsed['analog_channels']),('dmr_contacts',parsed['dmr_contacts'])]:
            save_csv(Path(str(base)+'.'+tag+'.csv'),rows)
        save_csv(Path(str(base)+'.zones.csv'),[{'index':z['index'],'physical_id':z['physical_id'],'name':z['name'],'channel_count':z['channel_count']} for z in parsed['zones']])
        save_csv(Path(str(base)+'.zone_members.csv'),[
            {'zone_index':z['index'],'zone_name':z['name'],**m} for z in parsed['zones'] for m in z['members']])
        save_csv(Path(str(base)+'.two_tone_contacts.csv'),parsed['two_tone_contacts'])
        save_csv(Path(str(base)+'.two_tone_systems.csv'),parsed['two_tone_systems'])
        for name in ['scan_lists','roam_lists','rx_group_lists']:
            save_csv(Path(str(base)+f'.{name}.csv'),[{'index':g['index'],'physical_id':g['physical_id'],'name':g['name'],'member_count':len(g['members'])} for g in parsed[name]])
            save_csv(Path(str(base)+'.'+name.replace('_lists','_members')+'.csv'),
                [{'list_index':g['index'],'list_name':g['name'],**m} for g in parsed[name] for m in g['members']])
        if args.dump_all_sections:
            sectiondir.mkdir()
            for row in parsed['section_inventory']:
                pos=row['offset'];size=row['total_bytes']
                (sectiondir/(row['id_hex']+'.bin')).write_bytes(p[pos:pos+size])
        if args.include_decoded_bin:Path(str(base)+'.decoded-payload.bin').write_bytes(p)
        print(f"{f.name}: {parsed['statistics']}")

if __name__=='__main__':main()
