#!/usr/bin/env python3
"""Build an offline, searchable Radio Management HTML explorer from a
Motorola Radio Management DBNode.decompressed.xml export.
Contacts, linked-channel popouts, Zone/Channel Assignment, and Security & Keys
from the USER INPUT XML. No separate HTML patcher or reference files needed.
No personal reference tables, hardcoded values, keys, or sample codeplugs.
Does not modify the source XML. Generated HTML contains LIVE private credentials;
never publish a generated HTML created from a real codeplug.
Usage: python3 build_rm_explorer_PUBLIC.py input.DBNode.decompressed.xml [-o PRIVATE-RadioManagement-Explorer.html]
Python standard library only.
"""
import argparse
import collections
import hashlib
import json
import html
import xml.etree.ElementTree as ET
from pathlib import Path

XN = '{http://www.w3.org/2001/XMLSchema-instance}type'

# Linked-channel popouts are built into the generated HTML (no second script).
# No hard-coded contacts, CAP codes, tones, location names, credentials, or
# filenames. All radio information displayed in the resulting HTML comes from
# the end user's input XML. An absent CAP code is NOT guessed from tone indexes.


def direct_fields(node):
    return {child.get('Name'): child.get('Value', '')
            for child in node.findall('DBNode')
            if child.get('Name') and child.get(XN) in ('DBField', 'DBRefField')}

def child_records(node):
    return [x for x in node.findall('DBNode') if x.get(XN) == 'Record']

def display_mhz(value):
    if value is None or not str(value).strip():
        return ''
    try:
        return f'{float(value):.5f}'
    except ValueError:
        return value


def display_tone(fields, side):
    # RX squelch is CP_XSQCHTY; TX squelch is CP_TXSQCHTY.
    # An inactive field can retain a default DPL/TPL value, so NEVER infer
    # a tone from the mere presence of its stored frequency/code.
    kind = fields.get('CP_XSQCHTY' if side == 'RX' else 'CP_TXSQCHTY', '').upper()
    if kind == 'CSQ':
        return 'CSQ'
    if kind == 'DPL':
        code = fields.get('CP_RXDPLCD' if side == 'RX' else 'CP_TXTDPLCD', '').strip()
        if not code or code.upper() == 'NONE':
            return '—'
        return 'D' + code.zfill(3) if code.isdigit() else 'D' + code
    if kind == 'TPL':
        val = fields.get('CP_RXTPLFREQ' if side == 'RX' else 'CP_TXTTPLFREQ', '').strip()
        if not val or val.upper() == 'NONE':
            return '—'
        try:
            return f'{float(val):.1f}'
        except ValueError:
            return val
    return '—'


def build(src):
    root = ET.parse(src).getroot()
    if root.tag != 'DBNode':
        raise ValueError('Expected a DBNode XML document')
    base = next((e for e in root.findall('DBNode') if e.get(XN) == 'Record'), None)
    if base is None:
        raise ValueError('No top-level Radio Management Record found')
    groups = {g.get('Name'): g for g in base.findall('DBNode') if g.get(XN) == 'RefSet'}
    for required in ('PCRContacts', 'Zone', 'ConventionalPersonality'):
        if required not in groups:
            raise ValueError('Missing expected Radio Management collection: '+required)

    contacts = []
    contact_collections = ('DigitalCalls', 'QuikCallIICalls', 'CapacityPlusCalls', 'PhoneCalls')
    for node in child_records(groups['PCRContacts']):
        fields = direct_fields(node)
        calls = []
        for collection in contact_collections:
            nested = node.find("DBNode[@Name='" + collection + "']")
            if nested is None:
                continue
            for call in child_records(nested):
                cfields = direct_fields(call)
                calls.append({
                    'id': cfields.get('DU_CALLLSTID') or cfields.get('CAPPLUSUCL_CALLLSTID') or cfields.get('PHNUCLELL_CALLID') or '',
                    'type': cfields.get('DU_CALLTYPE') or cfields.get('CAPPLUSUCL_CALLTYPE') or cfields.get('QU_CALLFORMAT') or collection,
                    'collection': collection,
                    'fields': cfields,
                    'set': call.get('SetName', '')
                })
        is_qcii = any(c['collection']=='QuikCallIICalls' for c in calls)
        is_group = any(c['type']=='GRPCALL' for c in calls)
        contacts.append({
            'name':fields.get('ContactName') or node.get('SetName', 'Unnamed'),
            'id': ', '.join(c['id'] for c in calls if c['id']),
            'type': ', '.join(c['type'] for c in calls if c['type']),
            'category': 'qcii' if is_qcii else 'group' if is_group else 'other',
            'calls':calls,
            'uuid':node.get('UUID',''),
            'set':node.get('SetName',''),
            'modified':node.get('LastModifiedDate',''),
            'fields':fields,
        })
    # QCII tones and format come only from the supplied XML.
    # The source typically stores transmit tone frequencies but may not expose
    # a decimal pager CAP code; leave it blank rather than infer it from a
    # Motorola STR_... tone lookup index. This avoids silently wrong codes.
    qcii = []
    qcii_systems = {}
    if 'QuikCallIISystems' in groups:
        for item in child_records(groups['QuikCallIISystems']):
            qcii_systems[item.get('UUID', '')] = direct_fields(item)
    for c in contacts:
        for call in c['calls']:
            if call['collection'] != 'QuikCallIICalls':
                continue
            f = call['fields']
            fmt = f.get('QU_CALLFORMAT', '')
            is_long = 'LONG' in fmt.upper()
            sysfields = qcii_systems.get(f.get('QU_QCIISYS', ''), {})
            duration = sysfields.get('QCIISYS_LTONEDURAT', '') if is_long else ''
            qcii.append({
                'name': c['name'],
                'cap': '',  # Not present as a decimal CAP code in verified XML.
                'a': f.get('QU_TONEATXFRE', ''),
                # A second frequency can be retained by the radio for a long-tone
                # call but is not an active second tone in that format.
                'b': '' if is_long else f.get('QU_TONEBTXFRE', ''),
                'duration': duration,
                'format': fmt,
                'source': c,
                'sourceAlias': c['name'],
                'sourceUuid': c['uuid'],
                'systemFields': sysfields,
                'provenance': 'Extracted from provided Radio Management XML',
            })

    # Security/key records are deliberately extracted as-is from each user's
    # own export. Do not hide or substitute real values. Generated HTML files
    # are PRIVATE: they may contain passwords, RAS keys, privacy keys, etc.
    security_items = []
    if 'Security' in groups:
        for record in child_records(groups['Security']):
            security_items.append({
                'collection': 'Security',
                'label': 'Security settings',
                'fields': direct_fields(record),
            })
            for group in record.findall('DBNode'):
                if group.get(XN) != 'RefSet':
                    continue
                for nested in child_records(group):
                    security_items.append({
                        'collection': group.get('Name') or 'Security',
                        'label': group.get('Name') or 'Key / Security record',
                        'fields': direct_fields(nested),
                    })
    # Some credentials live outside Security (e.g., codeplug password and
    # Wi-Fi/network credentials). Extract explicit password fields from other
    # records, not loosely matched text like "PTTKEYUP" or "PRIVATE CALL".
    import re
    credential_name = re.compile(r'(?:PASSWORD|PASSWD|PASSPHRASE|_PWD$|_PSK$|_SECRET$|_AUTHKEY$)', re.I)
    for node in root.iter('DBNode'):
        if node.get(XN) != 'Record':
            continue
        matches = {n.get('Name'): n.get('Value', '') for n in node.findall('DBNode')
                   if n.get('Name') and credential_name.search(n.get('Name'))
                   and n.get('Value') is not None}
        if matches:
            security_items.append({
                'collection': 'Other credentials',
                'label': 'Additional credential fields',
                'fields': matches,
            })

    channel_by_id = {}
    for node in child_records(groups['ConventionalPersonality']):
        fields = direct_fields(node)
        mode = 'Digital' if fields.get('CP_PERSTYPE','').startswith('DGTL') else 'Analog' if fields.get('CP_PERSTYPE','').startswith('ANLG') else fields.get('CP_PERSTYPE','Unknown')
        channel_by_id[node.get('UUID','')] = {
            'name':fields.get('CP_CNVPERSALIAS') or node.get('SetName','Unnamed'),
            'mode':mode,'rx':display_mhz(fields.get('CP_RXFREQ','')), 'tx':display_mhz(fields.get('CP_TXFREQ','')),
            'colorCode':fields.get('CP_COLORCODE',''),
            'slot':fields.get('CP_SLTASSGMNT','').replace('SLOT',''),
            'rxTone':display_tone(fields,'RX') if mode=='Analog' else '',
            'txTone':display_tone(fields,'TX') if mode=='Analog' else '',
            'power':fields.get('CP_TXPWR',''),
            'contactRef':fields.get('CP_UKPPERS',''),
            'uuid':node.get('UUID',''), 'set':node.get('SetName',''),
            'modified':node.get('LastModifiedDate',''),
            'fields':fields
        }
    contact_by_id = {c['uuid']: c for c in contacts}
    zones = []
    used = collections.Counter()
    bad = []
    for node in child_records(groups['Zone']):
        fields = direct_fields(node)
        zone_items = node.find("DBNode[@Name='ZoneItems']")
        channels = []
        for index, item in enumerate(child_records(zone_items) if zone_items is not None else [],1):
            f = direct_fields(item)
            cid = f.get('ZP_PERSIT','')
            channel = channel_by_id.get(cid)
            if channel is None:
                bad.append((node.get('SetName',''),cid))
                channels.append({'order':index,'name':'Unresolved reference','uuid':cid,'mode':'Unknown',
                                 'rx':'','tx':'','colorCode':'','slot':'','rxTone':'','txTone':'','power':'','contactName':'','contactId':'','fields':{}, 'zoneItem':f})
                continue
            used[cid] += 1
            contact = contact_by_id.get(channel['contactRef'])
            channels.append({'order':index,**channel,
                             'contactName':contact['name'] if contact else '',
                             'contactId':contact['id'] if contact else '',
                             'zoneItem':f})
        zones.append({'name':fields.get('ZP_ZONEALIAS') or node.get('SetName','Unnamed'),
                      'kind':fields.get('ZP_ZONETYPE',''),
                      'uuid':node.get('UUID',''), 'set':node.get('SetName',''),
                      'fields':fields, 'channels':channels})
    by_contact = collections.Counter()
    for c in channel_by_id.values():
        if c['contactRef'] in contact_by_id:
            by_contact[c['contactRef']] += 1
    for c in contacts:
        c['channelReferences'] = by_contact[c['uuid']]
    meta = {'title': 'Radio Management Explorer',
            'version': root.get('OriginalVersion', ''),
            'contacts': len(contacts),
            'groupContacts': sum(c['category'] == 'group' for c in contacts),
            'qciiSourceContacts': len(qcii),
            'zones': len(zones),
            'assignments': sum(len(z['channels']) for z in zones),
            'uniqueChannels': len(channel_by_id),
            'unresolvedReferences': len(bad),
            'analog': sum(ch['mode'] == 'Analog' for ch in channel_by_id.values()),
            'digital': sum(ch['mode'] == 'Digital' for ch in channel_by_id.values()),
            'securityRecords': len(security_items)}
    return {'meta': meta, 'contacts': contacts, 'qcii': qcii,
            'security': security_items, 'zones': zones}

HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="color-scheme" content="light"/>
<title>Radio Management • Configuration Explorer</title>
<style>
:root{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;--navy:#10213a;--nav2:#1b304d;--blue:#1467a6;--blue2:#dcefff;--ink:#142338;--muted:#69768a;--line:#e0e6ee;--page:#f4f7fb;--card:#fff;--green:#1e8968;--orange:#a86610;--shadow:0 5px 26px rgba(23,40,69,.06)}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);font-size:14px}button,input,select{font:inherit}button{cursor:pointer}a{color:var(--blue)}.shell{display:flex;min-height:100vh}.sidebar{width:250px;flex:none;background:linear-gradient(180deg,#12243f,#192a45);color:#dce8f6;position:sticky;top:0;height:100vh;display:flex;flex-direction:column;padding:25px 16px;overflow:auto}.brand{display:flex;gap:12px;align-items:center;padding:8px 9px 23px}.brand-icon{width:41px;height:41px;border:1px solid #57749b;border-radius:11px;display:grid;place-items:center;background:#2d4a6d;font-size:21px}.brand strong{display:block;font-size:15px;letter-spacing:.01em;color:white}.brand small{display:block;font-size:11px;color:#abbfd8;margin-top:2px}.side-label{text-transform:uppercase;letter-spacing:.13em;font-size:10px;font-weight:800;color:#849dbd;margin:12px 10px}.side-btn{display:flex;align-items:center;text-align:left;gap:10px;width:100%;background:none;color:#d0dceb;border:0;border-radius:9px;padding:12px 12px;margin:3px 0;font-weight:650}.side-btn:hover{background:#304967}.side-btn.active{background:#325b86;color:white}.side-btn .n{margin-left:auto;background:#263f5d;border-radius:9px;padding:2px 7px;font-size:11px}.side-btn.active .n{background:#4776a6}.side-note{margin-top:auto;padding:15px 10px 0;border-top:1px solid #36516e;color:#a7c1dc;font-size:11px;line-height:1.65}.side-note strong{color:#dbeafa}.main{min-width:0;flex:1;padding:38px clamp(18px,3.6vw,60px) 70px;max-width:1750px}.eyebrow{color:#3c749f;text-transform:uppercase;font-size:11px;font-weight:800;letter-spacing:.15em}.title{font-size:clamp(26px,3vw,37px);line-height:1.18;letter-spacing:-.03em;margin:8px 0 8px;font-weight:750}.sub{color:var(--muted);font-size:14px;line-height:1.55;max-width:920px}.topline{display:flex;justify-content:space-between;align-items:center;gap:18px}.offline{white-space:nowrap;display:flex;align-items:center;gap:6px;color:#267657;background:#e5f4ed;padding:8px 11px;border-radius:100px;font-size:11px;font-weight:750}.offline:before{content:"";width:7px;height:7px;background:#28a270;border-radius:50%}.cards{display:grid;grid-template-columns:repeat(4,minmax(125px,1fr));gap:14px;margin:25px 0}.stat{background:var(--card);padding:18px 20px;border:1px solid var(--line);border-radius:13px;box-shadow:var(--shadow)}.stat-label{font-size:11px;text-transform:uppercase;font-weight:750;letter-spacing:.08em;color:var(--muted)}.stat-value{margin-top:5px;font-size:28px;font-weight:790;letter-spacing:-.025em}.stat-sub{margin-top:3px;color:var(--muted);font-size:11px}.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;background:white;border:1px solid var(--line);border-radius:13px;padding:12px;margin:25px 0 18px;box-shadow:var(--shadow)}.search{position:relative;min-width:220px;flex:1}.search input{width:100%;height:43px;border:1px solid var(--line);border-radius:8px;padding:9px 12px 9px 36px;outline:none;color:var(--ink);background:#fff}.search input:focus{border-color:#3995d2;box-shadow:0 0 0 3px #cde7fa}.search:before{content:"⌕";position:absolute;left:11px;top:2px;font-size:27px;color:#7290a9}.filter{height:43px;padding:0 13px;max-width:210px;min-width:140px;background:white;border:1px solid var(--line);border-radius:8px;color:var(--ink)}.btn{border:1px solid var(--line);background:#fff;color:#294867;border-radius:8px;height:43px;padding:0 15px;font-size:12px;font-weight:750}.btn:hover{background:#f2f7fc}.btn.primary{background:var(--navy);color:white;border-color:var(--navy)}.btn.primary:hover{background:#2c527b}.section{background:white;border:1px solid var(--line);border-radius:13px;overflow:hidden;box-shadow:var(--shadow);margin-bottom:16px}.section-heading{padding:16px 21px;display:flex;align-items:center;justify-content:space-between;gap:15px;border-bottom:1px solid var(--line)}.section-heading h2{font-size:16px;letter-spacing:-.01em;margin:0;font-weight:760}.section-heading p{font-size:12px;color:var(--muted);margin:5px 0 0}.count{background:#eaf3fd;color:#275b8f;padding:5px 9px;border-radius:99px;font-size:11px;font-weight:750}.tablewrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:660px}thead{background:#f7f9fc}th{text-align:left;text-transform:uppercase;letter-spacing:.08em;font-size:10px;color:#718298;font-weight:850;padding:14px 19px;border-bottom:1px solid var(--line)}td{padding:13px 19px;border-bottom:1px solid #ecf0f4;font-size:13px}tr:last-child td{border-bottom:none}tbody tr{cursor:pointer}tbody tr:hover{background:#f2f8fe}.name{color:#1c496e;font-weight:760}.mono{font-family:ui-monospace,"Cascadia Code",Consolas,monospace;font-size:12px;font-variant-numeric:tabular-nums}.muted{color:var(--muted)}.pill{font-weight:750;display:inline-flex;align-items:center;border-radius:5px;padding:4px 8px;font-size:11px;white-space:nowrap}.pill.digital{background:#e2f4f1;color:#147c69}.pill.analog{background:#fff2df;color:#996116}.pill.group{background:#f0edff;color:#6651b5}.pill.private{background:#e6effd;color:#27649b}.zone-head{list-style:none;padding:20px 21px;cursor:pointer;display:flex;gap:13px;align-items:center}.zone-head::-webkit-details-marker{display:none}.zone-head::before{content:'▸';color:#7191b3;font-size:15px;transition:transform .15s}.section[open]>.zone-head::before{transform:rotate(90deg)}.zone-head .zone-title{font-size:16px;font-weight:770;flex:1}.zone-head .zone-kind{font-size:11px;color:var(--muted);font-weight:550;margin-left:6px}.mode-heading{display:flex;justify-content:space-between;align-items:center;padding:11px 20px;background:#f0f5fa;border-top:1px solid var(--line);font-size:12px;font-weight:800;color:#335a80}.mode-heading .count{font-size:10px}.zone-wrap .section:not([open]) .zone-head{border:0}.zone-wrap .section[open] .zone-head{border-bottom:1px solid var(--line)}.no-results{background:#fff;border:1px dashed #b9cad9;padding:30px;border-radius:11px;color:var(--muted);text-align:center}.hint{color:#7b8b9a;font-size:12px;margin:8px 0 22px}.footer{color:#8494a6;font-size:11px;margin:30px 0;line-height:1.7}.drawer-shade{position:fixed;inset:0;background:rgba(13,29,49,.45);z-index:20;display:none}.drawer{position:fixed;right:0;top:0;bottom:0;background:#fff;z-index:21;width:min(680px,95vw);box-shadow:-10px 0 40px #10243c32;display:none;flex-direction:column}.drawer.open{display:flex}.drawer-shade.open{display:block}.drawer-header{padding:22px 25px;border-bottom:1px solid var(--line);display:flex;align-items:start;gap:12px}.drawer-header>div{flex:1;min-width:0}.drawer-header h2{font-size:21px;letter-spacing:-.02em;margin:4px 0}.drawer-header small{font-size:11px;color:var(--muted)}.close{background:#f0f4f8;color:#29445e;width:35px;height:35px;border:0;border-radius:9px;font-size:20px}.drawer-body{overflow-y:auto;padding:22px 26px 55px}.detail-head{font-size:13px;font-weight:790;margin:22px 0 10px;color:#2e4f73}.facts{display:grid;grid-template-columns:1fr 1fr;gap:10px}.fact{border:1px solid #e6edf4;border-radius:8px;padding:12px;overflow-wrap:anywhere}.fact b{display:block;font-size:10px;color:#72869b;text-transform:uppercase;letter-spacing:.04em;margin-bottom:5px}.fact span{font-size:13px;font-weight:650}.field-list{border:1px solid var(--line);border-radius:9px;overflow:hidden}.field-row{display:flex;align-items:start;border-bottom:1px solid #ecf0f5;padding:9px 11px;gap:14px;line-height:1.45}.field-row:last-child{border:0}.field-row .key{flex:0 0 48%;color:#546a7f;font-family:ui-monospace,Consolas,monospace;font-size:11px;overflow-wrap:anywhere}.field-row .val{flex:1;font-family:ui-monospace,Consolas,monospace;font-size:11px;overflow-wrap:anywhere}.disclosure{margin-top:19px;border:1px solid var(--line);border-radius:9px;overflow:hidden}.disclosure>summary{font-weight:750;padding:14px;cursor:pointer;background:#f6f9fc}.disclosure .field-list{border:0;border-radius:0}.hidden{display:none!important}.nav-open{display:none}.jump{font-size:11px;border:0;padding:6px 10px;border-radius:8px;color:#175b96;background:#e8f2fb;font-weight:750}.warn{font-size:12px;line-height:1.5;color:#876210;background:#fff6dc;padding:10px;border-radius:9px;margin-top:12px}
@media(max-width:870px){.sidebar{width:205px}.main{padding:26px 20px}.cards{grid-template-columns:repeat(2,1fr)}.topline{align-items:flex-start}.offline{font-size:10px}}@media(max-width:640px){.shell{display:block}.sidebar{height:auto;width:auto;position:relative;flex-direction:row;flex-wrap:wrap;gap:7px;align-items:center;padding:10px 12px}.brand{padding:2px 5px;flex:1}.brand-icon{width:35px;height:35px}.side-label,.side-note{display:none}.side-btn{width:auto;font-size:12px;padding:10px;margin:0}.side-btn .n{display:none}.main{padding:25px 14px}.cards{gap:8px}.stat{padding:13px}.stat-value{font-size:23px}.offline{display:none}.toolbar{padding:9px}.filter{flex:1;min-width:120px}.facts{grid-template-columns:1fr}}
/* Source-derived QCII, security views and print layout. */
.qcii-long{display:inline-block;background:#fff1d6;color:#955300;padding:5px 9px;border-radius:7px;font-weight:800;white-space:nowrap}
.qcii-note{font-size:12px;color:#61738a;line-height:1.55;padding:11px 20px;background:#f9fbff;border-bottom:1px solid var(--line)}
.extra-section{margin-top:17px}.extra-section summary{padding:15px 20px;font-weight:750;cursor:pointer;background:#fbfcfe}
.extra-section[open] summary{border-bottom:1px solid var(--line)}.summary-meta{font-size:12px;color:var(--muted);font-weight:400;margin-left:12px}
.provenance{display:inline-block;border-radius:6px;background:#eef5ff;color:#275b8f;padding:5px 8px;font-size:11px;font-weight:800}
.credential-warning{padding:14px 17px;border-bottom:1px solid #eddfbb;background:#fff9e8;color:#684c10;line-height:1.6;font-size:12px}
@media print{body{background:#fff;color:#111}.sidebar,.toolbar,.offline,.footer,.drawer-shade,.close,#printDetails,.btn,.jump{display:none!important}.main{padding:6px;width:100%;max-width:none}.shell{display:block}.section{break-inside:avoid;box-shadow:none}.drawer:not(.open){display:none!important}.drawer.open{display:block!important;position:static;width:100%;box-shadow:none;overflow:visible}.drawer.open .drawer-body{overflow:visible}.drawer.open .field-row{break-inside:avoid}.drawer.open~.main{display:none}.detail-head{break-after:avoid}body:has(.drawer.open) .main{display:none!important}body:has(.drawer.open) .sidebar{display:none!important}.cards{display:none!important}}
.link-count{background:#e8f2fc;color:#165e9b;border:1px solid #bad8f3;border-radius:8px;padding:6px 13px;font-weight:800;font-variant-numeric:tabular-nums;cursor:pointer}.link-count:hover{background:#cde6ff}.link-count:disabled{background:#f4f5f7;color:#9ba6b3;cursor:default}.drawer .tablewrap table{min-width:570px}
</style>
</head>
<body>
<div class="shell">
  <aside class="sidebar">
   <div class="brand"><div class="brand-icon">◉</div><div><strong>Radio Management</strong><small>Configuration Explorer</small></div></div>
   <div class="side-label">Browse configuration</div>
   <button class="side-btn active" data-view="contacts"><span>▤</span><span>Contacts</span><span class="n" id="navContacts">0</span></button>
    <button class="side-btn" data-view="zones"><span>▦</span><span>Zone / Channel Assignment</span><span class="n" id="navZones">0</span></button>
   <button class="side-btn" data-view="security"><span>🔐</span><span>Security &amp; Keys</span><span class="n" id="navSecurity">0</span></button>
   <div class="side-note"><strong>Private local export.</strong><p>Passwords, encryption keys and other credentials come from the file you load. Never upload a populated HTML explorer to a public website.</p>Offline; no remote requests, scripts or analytics.</div>
  </aside>
  <main class="main">
   <div class="topline"><div><div class="eyebrow" id="sectionLabel">CONTACT DIRECTORY</div><h1 class="title" id="pageTitle">Contacts</h1><div class="sub" id="pageSub">Search by name, call ID, and call type. Select a row to inspect its fields.</div></div><div class="offline">Offline · private</div></div>
   <div class="cards" id="stats"></div>
   <div class="toolbar"><label class="search"><input id="search" type="search" aria-label="Search records" placeholder="Search names, IDs, frequencies…" autocomplete="off" autofocus></label><select class="filter hidden" id="zoneFilter" aria-label="Filter by zone"><option value="all">All zones</option></select><select class="filter hidden" id="modeFilter" aria-label="Filter by mode"><option value="all">Analog + Digital</option><option value="Analog">Analog only</option><option value="Digital">Digital only</option></select><button class="btn" id="reset">Clear filters</button><button class="btn primary" id="export">Export visible CSV ↓</button><button class="btn" id="printView">Print view</button></div>
   <div class="hint" id="countText" role="status" aria-live="polite"></div>
   <div id="result"></div>
   <div class="footer" id="footer"></div>
  </main>
</div>
<div class="drawer-shade" id="shade"></div><aside class="drawer" id="drawer" role="dialog" aria-modal="true" aria-labelledby="drawerTitle"><div class="drawer-header"><div><small id="drawerKicker">DETAILS</small><h2 id="drawerTitle">Record</h2><small id="drawerMeta"></small></div><button class="btn" id="printDetails">Print details</button><button class="close" id="drawerClose" aria-label="Close details">×</button></div><div class="drawer-body" id="drawerBody"></div></aside>
<script id="data" type="application/json">__DATA__</script>
<script>
(()=>{'use strict';
const D=JSON.parse(document.getElementById('data').textContent);
const $=id=>document.getElementById(id);
const meta=D.meta;
let view='contacts',q='',zone='all',mode='all';
const contactByUuid=Object.fromEntries(D.contacts.map(c=>[c.uuid,c]));
const allChannels=D.zones.flatMap(z=>z.channels.map(c=>({z:z.name,zid:z.uuid,kind:z.kind,...c})));
function node(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined&&text!==null)n.textContent=String(text);return n;}
function add(parent,child){parent.appendChild(child);return child;}
function normal(s){return String(s??'').toLowerCase();}
function matches(a){return !q||normal(a).includes(q);}
function labelCall(s){return s==='GRPCALL'?'Group Call':s==='PRIVCALL'?'Private Call':s==='ALLCALL'?'All Call':s||'Unknown';}
function modePill(text){return node('span','pill '+(text==='Digital'?'digital':text==='Analog'?'analog':'group'),text||'Unknown');}
function badgeCall(type){return node('span','pill '+(type==='PRIVCALL'?'private':'group'),labelCall(type));}
function cell(row,content,klass){const td=add(row,node('td',klass||''));if(content&&typeof content==='object')add(td,content);else td.textContent=String(content??'—');return td;}
function renderStats(){const items=[['GROUP CALLS',meta.groupContacts,'digital group contacts'],['QCII',meta.qciiSourceContacts,'from imported XML'],['ZONES',meta.zones,'zone assignments'],['CHANNEL ENTRIES',meta.assignments,'ordered by zone']];const dst=$('stats');dst.replaceChildren();items.forEach(([k,v,sub])=>{const n=add(dst,node('div','stat'));add(n,node('div','stat-label',k));add(n,node('div','stat-value',v));add(n,node('div','stat-sub',sub));});}
function sortedZoneIndex(){return D.zones.map((z,i)=>({...z,i}));}
function changeView(v){
 view=v;q='';mode='all';zone='all';$('search').value='';$('modeFilter').value='all';$('zoneFilter').value='all';
 document.querySelectorAll('.side-btn').forEach(b=>b.classList.toggle('active',b.dataset.view===view));
 $('zoneFilter').classList.toggle('hidden',view!=='zones');$('modeFilter').classList.toggle('hidden',view!=='zones');
 const descriptions={
 contacts:['CONTACT DIRECTORY','Contacts','Group calls and QCII contacts read from the uploaded XML. Search names, IDs, tones, and formats.'],
 zones:['ZONE / CHANNEL ASSIGNMENT','Zone / Channel Assignment','Search names, MHz, DPL/CTCSS tones, color codes, slots, contacts, or radio fields. Click for details.'],
 security:['SENSITIVE RADIO SETTINGS','Security & Keys','Actual security settings, passwords, RAS keys, and privacy key values from the user-selected XML. Keep this HTML PRIVATE.']
 };
 const x=descriptions[view];$('sectionLabel').textContent=x[0];$('pageTitle').textContent=x[1];$('pageSub').textContent=x[2];
 draw();
}
function contactMatches(c){const full=[c.name,c.id,c.type,c.set,c.uuid,...c.calls.flatMap(call=>[call.id,call.type,...Object.entries(call.fields).flat()]),...Object.entries(c.fields).flat()];return matches(full.join(' '));}
function qciiMatches(c){return matches([c.name,c.a,c.b,c.duration,c.format,c.source?.set||'',c.source?.uuid||'',...Object.entries(c.systemFields||{}).flat()].join(' '));}
function channelMatches(c){if(zone!=='all'&&c.zid!==zone)return false;if(mode!=='all'&&c.mode!==mode)return false;const data=[c.z,c.name,c.rx,c.tx,c.rxTone,c.txTone,c.slot,c.mode,c.colorCode,c.power,c.contactName,c.contactId,c.set,c.uuid,...Object.entries(c.fields).flat()];return matches(data.join(' '));}
function makeTable(headers){const wrap=node('div','tablewrap');const table=add(wrap,node('table'));const thead=add(table,node('thead'));const thr=add(thead,node('tr'));headers.forEach(h=>add(thr,node('th','',h)));const tbody=add(table,node('tbody'));return {wrap,tbody};}
function makeContactSection(title,description,count){const box=add($('result'),node('section','section'));const header=add(box,node('div','section-heading'));const group=add(header,node('div'));add(group,node('h2','',title));add(group,node('p','',description));add(header,node('span','count',count+' shown'));return box;}
function clickableRow(row,callback){row.tabIndex=0;row.addEventListener('click',callback);row.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();callback();}});}
function renderContacts(){
 const groups=D.contacts.filter(c=>c.category==='group'&&contactMatches(c));
 const qc=D.qcii.filter(qciiMatches);
 const other=D.contacts.filter(c=>c.category==='other'&&contactMatches(c));
 const count=groups.length+qc.length+other.length;
 $('countText').textContent=`Showing ${count} entries · ${groups.length} group calls · ${qc.length} QCII · ${other.length} other contacts`;
 if(groups.length){const box=makeContactSection('Digital group calls','Group-call contacts from this Radio Management XML',groups.length);const {wrap,tbody}=makeTable(['CONTACT','TALKGROUP ID','TYPE','LINKED CHANNELS','']);add(box,wrap);
 for(const c of groups){const row=add(tbody,node('tr'));cell(row,c.name,'name');cell(row,c.id||'—','mono');cell(row,badgeCall('GRPCALL'));cell(row,linkedCountButton(c));cell(row,'Details →','muted');clickableRow(row,()=>openContact(c));}}
 if(qc.length){const box=makeContactSection('QCII / Quik-Call II','Tone values and call formats read directly from the uploaded XML',qc.length);add(box,node('div','qcii-note','No CAP-code table or user-supplied tone map is bundled. Source tone indices are available in Details. Long-tone calls have only one active transmitted tone.'));const {wrap,tbody}=makeTable(['CONTACT','A TONE (Hz)','B TONE (Hz)','FORMAT','LONG TONE (sec)','']);add(box,wrap);
 for(const c of qc){const row=add(tbody,node('tr'));cell(row,c.name,'name');cell(row,c.a||'—','mono');cell(row,c.b||'—','mono');cell(row,c.format||'—','mono');cell(row,c.duration||'—','mono');cell(row,'Details →','muted');clickableRow(row,()=>openQCII(c));}}
 if(other.length){const box=add($('result'),node('details','section extra-section'));box.open=!!q;const summary=add(box,node('summary'));summary.textContent='Other contacts';add(summary,node('span','summary-meta',other.length+' other contact entries'));const {wrap,tbody}=makeTable(['CONTACT','ID','TYPE','LINKED CHANNELS','']);add(box,wrap);
 for(const c of other){const row=add(tbody,node('tr'));cell(row,c.name,'name');cell(row,c.id||'—','mono');cell(row,c.type||'—');cell(row,linkedCountButton(c));cell(row,'Details →','muted');clickableRow(row,()=>openContact(c));}}
 if(!count){add($('result'),node('div','no-results','No contacts matched your search.'));}
}
function renderZones(){let total=0;const area=add($('result'),node('div','zone-wrap'));
 for(const z of D.zones){if(zone!=='all'&&z.uuid!==zone)continue;
 const found=z.channels.map(c=>({z:z.name,zid:z.uuid,kind:z.kind,...c})).filter(channelMatches);if(!found.length)continue;total+=found.length;
 const sec=add(area,node('details','section'));sec.open=true;const summary=add(sec,node('summary','zone-head'));add(summary,node('span','zone-title',z.name));if(z.kind)add(summary,node('span','zone-kind',z.kind==='CHANNELPOOL'?'Channel Pool':'Normal Zone'));add(summary,node('span','count',found.length+' channels'));
 // Separate mode tables so analog and digital have their own requested headers.
 for(const wanted of ['Digital','Analog','Unknown']){
 const subset=found.filter(c=>c.mode===wanted||(wanted==='Unknown'&&!['Digital','Analog'].includes(c.mode)));
 if(!subset.length)continue;
 const modeTitle=add(sec,node('div','mode-heading'));add(modeTitle,node('span','',wanted+' channels'));add(modeTitle,node('span','count',subset.length+' shown'));
 const heads=wanted==='Digital' ? ['#','CHANNEL NAME','MODE','RX MHZ','TX MHZ','COLOR CODE','SLOT','CONTACT / ID',''] : wanted==='Analog' ? ['#','CHANNEL NAME','MODE','RX MHZ','RX TONE','TX MHZ','TX TONE',''] : ['#','CHANNEL NAME','MODE','RX MHZ','TX MHZ',''];
 const {wrap,tbody}=makeTable(heads);add(sec,wrap);
 for(const c of subset){const row=add(tbody,node('tr'));row.tabIndex=0;
 cell(row,c.order,'mono muted');cell(row,c.name,'name');cell(row,modePill(c.mode));cell(row,c.rx||'—','mono');
 if(wanted==='Analog'){cell(row,c.rxTone||'—','mono');cell(row,c.tx||'—','mono');cell(row,c.txTone||'—','mono');}
 else {cell(row,c.tx||'—','mono');if(wanted==='Digital'){cell(row,c.colorCode||'—','mono');cell(row,c.slot||'—','mono');cell(row,(c.contactName||'—')+(c.contactId?' · '+c.contactId:''),'');}}
 cell(row,'Details →','muted');row.addEventListener('click',()=>openChannel(c));row.addEventListener('keydown',e=>{if(e.key==='Enter')openChannel(c);});
 }
 }
 }
 $('countText').textContent=`Showing ${total} of ${meta.assignments} channel assignments · ${area.children.length} zone${area.children.length!==1?'s':''} matched`;
 if(!total){area.remove();add($('result'),node('div','no-results','No channels matched these filters.'));}
}
function renderSecurity(){
 const matched=D.security.filter(c=>matches([c.collection,c.label,...Object.entries(c.fields).flat()].join(' ')));
 $('countText').textContent=`Showing ${matched.length} security / credential records from the imported XML`;
 const banner=add($('result'),node('div','credential-warning'));
 banner.textContent='PRIVATE CONTENT — This local HTML may include codeplug passwords, RAS/Enhanced Privacy encryption keys, Wi-Fi credentials, and other secrets. Do not publish or share the generated HTML. Only the Python generator contains no embedded radio data.';
 if(!matched.length){add($('result'),node('div','no-results','No matching security records in this XML.'));return;}
 const area=add($('result'),node('div','zone-wrap'));
 for(const c of matched){const sec=add(area,node('section','section'));
 const h=add(sec,node('div','section-heading'));const col=add(h,node('div'));
 add(col,node('h2','',c.label));add(col,node('p','',c.collection));
 add(h,node('span','count',Object.keys(c.fields).length+' fields'));
 add(sec,fieldTable(c.fields));}
}
function draw(){const r=$('result');r.replaceChildren();if(view==='contacts')renderContacts();else if(view==='zones')renderZones();else renderSecurity();}
function fact(parent,title,val){const d=add(parent,node('div','fact'));add(d,node('b','',title));add(d,node('span','',val===''?'—':(val??'—')));}
function fieldTable(obj){const list=node('div','field-list');for(const [k,v] of Object.entries(obj||{})){const row=add(list,node('div','field-row'));add(row,node('div','key',k));add(row,node('div','val',v===''?'(empty)':v));}return list;}
function detailSection(parent,label,obj){add(parent,node('h3','detail-head',label));add(parent,fieldTable(obj));}
function openDrawer(title,kicker,info,body){$('drawerTitle').textContent=title;$('drawerKicker').textContent=kicker;$('drawerMeta').textContent=info;$('drawerBody').replaceChildren();body($('drawerBody'));$('shade').classList.add('open');$('drawer').classList.add('open');document.body.style.overflow='hidden';$('drawerClose').focus();}
function closeDrawer(){$('shade').classList.remove('open');$('drawer').classList.remove('open');document.body.style.overflow='';}

function linkedChannels(c){
 // UUID is the authoritative link. Do not infer relationships by name alone.
 return allChannels.filter(ch=>ch.contactRef && c.uuid && ch.contactRef===c.uuid);
}
function openLinkedChannels(c){
 const channels=linkedChannels(c);
 openDrawer(c.name,'LINKED CHANNELS',channels.length+' channel assignments',(d)=>{
   if(!channels.length){add(d,node('div','no-results','No linked channels found for this contact.'));return;}
   const {wrap,tbody}=makeTable(['ZONE','CHANNEL','MODE','RX MHZ','TX MHZ','']);add(d,wrap);
   for(const ch of channels){
     const row=add(tbody,node('tr'));
     cell(row,ch.z);cell(row,ch.name,'name');cell(row,ch.mode);cell(row,ch.rx||'—','mono');cell(row,ch.tx||'—','mono');cell(row,'Details →','muted');
     clickableRow(row,()=>openChannel(ch));
   }
 });
}
function linkedCountButton(c){
 const channels=linkedChannels(c);
 const b=node('button','link-count',String(channels.length));b.type='button';b.disabled=!channels.length;
 b.title=channels.length?'Show linked channels':'No linked channels';
 b.addEventListener('click',e=>{e.stopPropagation();openLinkedChannels(c);});
 return b;
}

function openContact(c){openDrawer(c.name,'CONTACT DETAILS',c.set,(d)=>{const f=add(d,node('div','facts'));fact(f,'Contact ID',c.id||'—');fact(f,'Call type',c.type||'—');fact(f,'Referenced by channels',linkedChannels(c).length);const linkBtn=add(d,linkedCountButton(c));linkBtn.textContent='View linked channels ('+linkedChannels(c).length+')';fact(f,'Last modified',c.modified||'—');detailSection(d,'Contact fields from XML',c.fields);c.calls.forEach((call,i)=>detailSection(d,call.collection+' '+(i+1)+' · '+labelCall(call.type),call.fields));const det=add(d,node('details','disclosure'));add(det,node('summary','', 'Identifiers'));add(det,fieldTable({'Record UUID':c.uuid,'SetName':c.set}));});}
function openQCII(c){openDrawer(c.name,'QUICK-CALL II · '+(c.format||'Unknown format'),c.source?.set||'XML source record',(d)=>{
 const f=add(d,node('div','facts'));
 fact(f,'A tone',c.a||'—');fact(f,'B tone',c.b||'Not transmitted');fact(f,'Tone format',c.format||'—');if(c.duration)fact(f,'Long tone duration',c.duration+' seconds');
 if(c.source){detailSection(d,'Original contact fields',c.source.fields);
 c.source.calls.filter(call=>call.collection==='QuikCallIICalls').forEach(call=>detailSection(d,'Original QCII programming',call.fields));
 if(Object.keys(c.systemFields||{}).length)detailSection(d,'QCII system settings',c.systemFields);
 const id=add(d,node('details','disclosure'));add(id,node('summary','','Source identifiers'));add(id,fieldTable({'Contact UUID':c.source.uuid,'SetName':c.source.set,'LastModified':c.source.modified}));}
 });}
function openChannel(c){openDrawer(c.name,'CHANNEL · '+c.z+' · #'+c.order,c.set,(d)=>{const f=add(d,node('div','facts'));fact(f,'Zone',c.z);fact(f,'Mode',c.mode);fact(f,'Receive frequency',c.rx?c.rx+' MHz':'—');fact(f,'Transmit frequency',c.tx?c.tx+' MHz':'—');if(c.mode==='Analog'){fact(f,'RX tone',c.rxTone||'—');fact(f,'TX tone',c.txTone||'—');}if(c.mode==='Digital'){fact(f,'Color code',c.colorCode||'—');fact(f,'Time slot',c.slot||'—');}fact(f,'TX power',c.power||'—');if(c.contactName){const h=add(d,node('h3','detail-head','Linked contact'));const p=add(d,node('div','fact'));add(p,node('span','',c.contactName+(c.contactId?' · '+c.contactId:'')));const contact=contactByUuid[c.contactRef];if(contact){const b=add(p,node('button','jump','Inspect contact →'));b.style.marginLeft='10px';b.onclick=()=>openContact(contact);}}
 const select={'CP_XSQCHTY':'RX squelch type','CP_SLTASSGMNT':'DMR time slot','CP_CNVPERSALIAS':'Channel alias','CP_PERSTYPE':'Personality type','CP_RXFREQ':'RX frequency (MHz)','CP_TXFREQ':'TX frequency (MHz)','CP_TXPWR':'Transmit power','CP_COLORCODE':'DMR color code','CP_RXONLYEN':'RX only enabled','CP_TXSQCHTY':'TX squelch type','CP_RXSQL':'RX squelch','CP_TXTTPLFREQ':'TX CTCSS tone','CP_RXTPLFREQ':'RX CTCSS tone','CP_TXTDPLCD':'TX DPL','CP_RXDPLCD':'RX DPL','CP_UKPPERS':'Contact reference UUID'};
 const main={};for(const [k,v] of Object.entries(select)){if(k in c.fields)main[v+'  ['+k+']']=c.fields[k];}
 detailSection(d,'Programming essentials',main);
 const more=add(d,node('details','disclosure'));add(more,node('summary','',`Advanced · ${Object.keys(c.fields).length} channel fields (verbatim)`));add(more,fieldTable(c.fields));
 const zf=add(d,node('details','disclosure'));add(zf,node('summary','', 'Zone item linkage'));add(zf,fieldTable(c.zoneItem));const ids=add(d,node('details','disclosure'));add(ids,node('summary','', 'Record identifiers'));add(ids,fieldTable({'Personality UUID':c.uuid,'SetName':c.set,'LastModified':c.modified}));});}
function csvSafe(s){let v=String(s??'');if(/^[=+\-@\t\r]/.test(v))v="'"+v;return '"'+v.replaceAll('"','""')+'"';}
function downloadCsv(){
 const contactRows=[['CATEGORY','CONTACT','TONE A (Hz)','TONE B (Hz)','DURATION (s)','CALL ID','TYPE','LINKED CHANNELS'],
 ...D.contacts.filter(c=>c.category==='group'&&contactMatches(c)).map(c=>['Digital group call',c.name,'','','',c.id,c.type,c.channelReferences]),
 ...D.qcii.filter(qciiMatches).map(c=>['QCII',c.name,c.a,c.b,c.duration,'',c.format,'']),
 ...D.contacts.filter(c=>c.category==='other'&&contactMatches(c)).map(c=>['Other contact',c.name,'','','',c.id,c.type,c.channelReferences])];
 const channelRows=[['Zone','Order','Channel','Mode','RX MHz','RX Tone','TX MHz','TX Tone','Color Code','Slot','Contact','Contact ID','TX Power'],...allChannels.filter(channelMatches).map(c=>[c.z,c.order,c.name,c.mode,c.rx,c.mode==='Analog'?c.rxTone:'',c.tx,c.mode==='Analog'?c.txTone:'',c.mode==='Digital'?c.colorCode:'',c.mode==='Digital'?c.slot:'',c.mode==='Digital'?c.contactName:'',c.mode==='Digital'?c.contactId:'',c.power])];
 const securityRows=[['COLLECTION','LABEL','FIELD NAME','VALUE'],...D.security.filter(c=>matches([c.collection,c.label,...Object.entries(c.fields).flat()].join(' '))).flatMap(c=>Object.entries(c.fields).map(([key,val])=>[c.collection,c.label,key,val]))];
 const rows=view==='contacts'?contactRows:view==='zones'?channelRows:securityRows;
 const csv='\ufeff'+rows.map(r=>r.map(csvSafe).join(',')).join('\r\n');const blob=new Blob([csv],{type:'text/csv;charset=utf-8'});const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;
 link.download='PRIVATE-RadioManagement-'+view+'.csv';document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function init(){
 renderStats();$('navContacts').textContent=meta.contacts;$('navZones').textContent=meta.zones;$('navSecurity').textContent=meta.securityRecords;
 D.zones.forEach(z=>{const o=node('option','',z.name);o.value=z.uuid;$('zoneFilter').append(o);});
 document.querySelectorAll('.side-btn').forEach(b=>b.onclick=()=>changeView(b.dataset.view));
 $('search').oninput=e=>{q=normal(e.target.value.trim());draw();};
 $('zoneFilter').onchange=e=>{zone=e.target.value;draw();};$('modeFilter').onchange=e=>{mode=e.target.value;draw();};
 $('reset').onclick=()=>{q='';zone='all';mode='all';$('search').value='';$('zoneFilter').value='all';$('modeFilter').value='all';draw();};
 $('export').onclick=downloadCsv;$('printView').onclick=()=>window.print();$('printDetails').onclick=()=>window.print();
 $('shade').onclick=closeDrawer;$('drawerClose').onclick=closeDrawer;window.addEventListener('keydown',e=>{if(e.key==='Escape')closeDrawer();});
 $('footer').textContent='Offline, read-only Radio Management explorer. Contacts, QCII tones, channel settings, passwords and keys are read only from the end user’s XML file. No bundled codeplug, contact list, CAP-code table or radio data. Generated HTML and CSVs may contain secrets: do not publish them.';
 changeView('contacts');
}
init();
})();
</script>
</body>
</html>'''

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source',type=Path)
    ap.add_argument('-o','--output',type=Path)
    ap.add_argument('--force',action='store_true',
                    help='Replace an existing HTML output (never the input XML)')
    args=ap.parse_args()
    out=args.output or args.source.with_name('PRIVATE-RadioManagement-Explorer.html')
    if out.resolve()==args.source.resolve():
        ap.error('Refusing to overwrite input XML')
    if out.exists() and not args.force:
        ap.error('Output already exists: '+str(out))
    data=build(args.source)
    payload=json.dumps(data,ensure_ascii=False,separators=(',',':')).replace('</', '<' + '\\' + '/').replace('\u2028','\\u2028').replace('\u2029','\\u2029')
    content=HTML.replace('__DATA__',payload)
    out.write_text(content,encoding='utf-8')
    print('OUTPUT:',out)
    print('BYTES:',out.stat().st_size)
    print('CONTACTS_FROM_XML:',data['meta']['contacts'])
    print('GROUP_CALLS:',data['meta']['groupContacts'])
    print('QCII_RECORDS:',len(data['qcii']))
    print('ZONES:',data['meta']['zones'])
    print('CHANNEL_ASSIGNMENTS:',data['meta']['assignments'])
    print('UNRESOLVED_REFERENCES:',data['meta']['unresolvedReferences'])
    print('SECURITY_RECORDS:', data['meta']['securityRecords'])
    print('WARNING: Generated HTML contains raw credentials and MUST NOT be published.')
    print('SHA256:',hashlib.sha256(out.read_bytes()).hexdigest())

if __name__=='__main__':
    main()
