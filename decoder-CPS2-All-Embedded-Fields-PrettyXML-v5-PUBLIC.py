#!/usr/bin/env python3
"""One-shot Motorola MOTOTRBO CPS2 XCTB/CTB2 -> MatrixRadio + DBNode + extra XML fields.

Supports:
  - .xctb: default protection (protect=d) and archive-password protection
    (protect=u). protect=u only with supplied password,
    data models 2.151.206, 2.153.50, 2.159.125,
    using AES-256-CBC and embedded XML SHA-256 verification.
  - .ctb2: legacy CPS2 archive, DES-CBC + GZIP with a Ver:...\0 XML wrapper.
    GZIP CRC32, PKCS#7 padding, and MatrixRadio XML are validated.

CTB2 support was verified on an original 'Ver:02.16' archive. More CTB2
wrapper versions may exist; unknown wrappers are refused without guessing.

Also accepts already-decoded MatrixRadio .xml files for DBNode and additional field extraction.
This does NOT support .ctb (CPS1), unknown XCTB protection modes,
password-protected key-view material inside an already-decoded codeplug,
or writing codeplugs. No Motorola binaries are required at runtime.

The source file is NEVER modified. All results are grouped by default under
<input folder>/<codeplug stem>/{xml,pretty,binary}/, plus metadata and CSV.
The -o/--output flag still allows an explicit decoded-XML path override.
DBNodeCmpBytes, DeviceInfoFields, and ExtendedFields are Base64-encoded raw
DEFLATE. XML is validated; additional fields are exported unredacted.
DBNode metadata includes direct channel/zone counts and additional field stats.
Also decodes CFS (compressed feature/option XML) and SyncDataSource
(compressed .NET Binary XML / MC-NBFX). Embedded binary data is preserved.
Optional --pretty writes readable indented XML for MatrixRadio and all five
embedded XML sections; Base64 payloads are replaced with references in the
pretty MatrixRadio copy, including recognized opaque binary fields. The original decoded XML is preserved verbatim; pretty output
is for reading/inspection, NOT for re-importing into CPS.
decoded XML may contain passwords,
RAS/EP encryption keys, and confidential radio configuration.

Requires: Python 3.9+ and Python 'cryptography'.

Usage:
    ./decoder-CPS2-All-Embedded-Fields-PrettyXML-v5-PUBLIC.py input.ctb2
    ./decoder-CPS2-All-Embedded-Fields-PrettyXML-v5-PUBLIC.py input.xctb
    ./decoder-CPS2-All-Embedded-Fields-PrettyXML-v5-PUBLIC.py input.ctb2 --inspect
    ./decoder-CPS2-All-Embedded-Fields-PrettyXML-v5-PUBLIC.py input.ctb2 -o other.xml
    ./decoder-CPS2-All-Embedded-Fields-PrettyXML-v5-PUBLIC.py input.ctb2 --overwrite
    ./decoder-CPS2-All-Embedded-Fields-PrettyXML-v5-PUBLIC.py input.xctb --verify-only
    ./decoder-CPS2-All-Embedded-Fields-PrettyXML-v5-PUBLIC.py protected.xctb --password-file ./archive-password.txt
    ./decoder-CPS2-All-Embedded-Fields-PrettyXML-v5-PUBLIC.py protected.xctb --password-env MOTOROLA_XCTB_PASSWORD
    ./decoder-CPS2-All-Embedded-Fields-PrettyXML-v5-PUBLIC.py protected.xctb --prompt-password
    ./decoder-CPS2-All-Embedded-Fields-PrettyXML-v5-PUBLIC.py already.decoded.xml
    ./decoder-CPS2-All-Embedded-Fields-PrettyXML-v5-PUBLIC.py already.decoded.xml --pretty
    ./decoder-CPS2-All-Embedded-Fields-PrettyXML-v5-PUBLIC.py protected.xctb --prompt-password --pretty
    ./decoder-CPS2-All-Embedded-Fields-PrettyXML-v5-PUBLIC.py already.decoded.xml --outdir ./results --pretty
"""

import argparse
import getpass
import os
import tempfile
import uuid
from xml.sax.saxutils import escape as xml_escape, quoteattr as xml_quoteattr
import base64
import csv
import io
import gzip
import hashlib
import json
import re
import struct
import sys
import zlib
import xml.etree.ElementTree as ET
from pathlib import Path

TESTED_MODELS = frozenset({'2.151.206', '2.153.50', '2.159.125'})
DEFAULT_AES_SEED = b'627842'
# Motorola's legacy CPS2 CTB2 BinaryFileDecodingStrategy uses DES-CBC.
# The original 8-byte DES key/IV below were recovered from Motorola CPS2 DLL
# static FileCryptographyConstants; TripleDES K1=K2=K3 is equivalent to DES.
LEGACY_DES_KEY = b'NOWISTHE'
LEGACY_DES_IV = b'WINTEROF'
CTB2_PREFIX = re.compile(rb'^Copyright \(c\) ([0-9]{4}) Motorola Solutions, Inc\. All Rights Reserved ')
INNER_VERSION = re.compile(rb'^(Ver:[0-9]+\.[0-9]+)\x00')
MAX_XML_BYTES = 128 * 1024 * 1024
MAX_DB_NODE_XML = 256 * 1024 * 1024
MAX_EXTRA_FIELD_XML = 32 * 1024 * 1024
MAX_EMBEDDED_XML = 32 * 1024 * 1024
XSI_TYPE = '{http://www.w3.org/2001/XMLSchema-instance}type'


def sha256(data):
    return hashlib.sha256(data).digest()


def byte_xor(a, b):
    if len(a) != len(b):
        raise ValueError('XOR operand length mismatch')
    return bytes(x ^ y for x, y in zip(a, b))


def parse_xctb(raw):
    header_start = raw.find(b'{\r\n  "version"')
    if header_start < 4:
        raise ValueError('Motorola XCTB JSON header signature not found')
    header_length = struct.unpack_from('<I', raw, header_start - 4)[0]
    header_end = header_start + header_length
    if header_length < 16 or header_end > len(raw):
        raise ValueError('Invalid/truncated XCTB header length')
    header = json.loads(raw[header_start:header_end].decode('utf-8'))
    if header.get('type') != 'xctb' or header.get('protect') not in ('d', 'u'):
        raise ValueError('Unsupported XCTB type or protection mode {!r} (supported: d, u)'.format(
            header.get('protect')))
    model = header.get('dataModelVersion', {}).get('Version')
    if model not in TESTED_MODELS:
        raise ValueError('Untested XCTB data model {!r}; tested: {}'.format(
            model, ', '.join(sorted(TESTED_MODELS))))
    iv = base64.b64decode(header['stamp'], validate=True)
    if len(iv) != 16:
        raise ValueError('Invalid XCTB AES IV length')
    ciphertext = raw[header_end:]
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError('Missing/unaligned XCTB AES ciphertext')
    return header, iv, ciphertext


def decode_xctb(raw, password=None):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    header, iv, ciphertext = parse_xctb(raw)
    protection = header['protect']
    if protection == 'u':
        if password is None or not password:
            raise ValueError('Password required for user-protected XCTB (protect=u). '
                             'Use --password-file, --password-env, or --prompt-password.')
        # Verified against a protect=u CPS2.159 archive: the UTF-8 archive
        # password replaces Motorola's fixed default-protection seed.
        secret = password.encode('utf-8')
    else:
        secret = DEFAULT_AES_SEED
    hs = sha256(secret)
    mixed_seed = byte_xor(hs[:16], hs[16:])
    key = sha256(byte_xor(iv, mixed_seed))
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad = padded[-1]
    if not (1 <= pad <= 16) or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError('XCTB decoding failed (incorrect archive password or corrupted ciphertext)')
    zipped = padded[:-pad]
    if not zipped.startswith(b'\x1f\x8b\x08'):
        raise ValueError('XCTB plaintext is not GZIP (wrong password or damaged file)')
    decoded = gzip.decompress(zipped)
    if len(decoded) < 4:
        raise ValueError('Truncated XCTB metadata')
    inner_len = struct.unpack_from('<I', decoded, 0)[0]
    inner_end = 4 + inner_len
    if inner_len < 2 or inner_end > len(decoded):
        raise ValueError('Invalid XCTB inner metadata length')
    inner_header = json.loads(decoded[4:inner_end].decode('utf-8'))
    xml = decoded[inner_end:]
    actual_checksum = base64.b64encode(sha256(xml)).decode('ascii')
    if actual_checksum != inner_header.get('checksum'):
        raise ValueError('XCTB embedded XML SHA-256 mismatch')
    root = verify_matrixradio(xml)
    return xml, root, {
        'FORMAT': 'XCTB',
        'DATA_MODEL': header['dataModelVersion']['Version'],
        'RM_VERSION': header.get('rmVersion', '(not present)'),
        'PROTECTION': header['protect'],
        'INTERNAL_SHA256_VERIFIED': 'YES',
    }


def parse_ctb2(raw):
    m = CTB2_PREFIX.match(raw)
    if not m:
        raise ValueError('Motorola CTB2 copyright prefix not found')
    ciphertext = raw[m.end():]
    if not ciphertext or len(ciphertext) % 8:
        raise ValueError('CTB2 DES ciphertext is missing or not 8-byte aligned')
    return m.group(1).decode('ascii'), ciphertext


def decode_ctb2(raw):
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

    copyright_year, ciphertext = parse_ctb2(raw)
    des_equivalent = TripleDES(LEGACY_DES_KEY * 3)
    dec = Cipher(des_equivalent, modes.CBC(LEGACY_DES_IV)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    pad = padded[-1]
    if not (1 <= pad <= 8) or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError('Invalid CTB2 DES PKCS#7 padding')
    zipped = padded[:-pad]
    if not zipped.startswith(b'\x1f\x8b\x08'):
        raise ValueError('CTB2 plaintext is not GZIP')
    # Validate the GZIP CRC32 and size without allowing unbounded output.
    z = zlib.decompressobj(16 + zlib.MAX_WBITS)
    body = z.decompress(zipped, MAX_XML_BYTES + 1025)
    if len(body) > MAX_XML_BYTES + 1024:
        raise ValueError('CTB2 decompressed payload exceeds safety limit')
    body += z.flush()
    if not z.eof or z.unused_data:
        raise ValueError('CTB2 GZIP member incomplete or has trailing bytes')
    m = INNER_VERSION.match(body)
    if not m:
        raise ValueError('CTB2 decoded payload lacks a recognized Ver:...\\0 wrapper')
    xml = body[m.end():]
    root = verify_matrixradio(xml)
    return xml, root, {
        'FORMAT': 'CTB2',
        'COPYRIGHT_YEAR': copyright_year,
        'CTB2_WRAPPER': m.group(1).decode('ascii'),
        'DES_PADDING_VERIFIED': 'YES',
        'GZIP_CRC32_VERIFIED': 'YES',
        'EMBEDDED_XML_SHA256': 'NOT PRESENT IN VERIFIED CTB2 WRAPPER',
    }


def verify_matrixradio(xml):
    if not xml or len(xml) > MAX_XML_BYTES:
        raise ValueError('Invalid/oversized XML payload')
    root = ET.fromstring(xml)
    if root.tag.rsplit('}', 1)[-1] != 'MatrixRadio':
        raise ValueError('Expected a MatrixRadio XML root')
    return root


def first_nonempty(root, name):
    # Use a flat scan to maintain parity with v2 XCTB decoder's output.
    return next((e.text for e in root.iter()
                 if e.tag.rsplit('}', 1)[-1] == name and e.text), '(not found)')


def detect_format(source, raw):
    ext = source.suffix.lower()
    if ext == '.ctb2':
        parse_ctb2(raw)
        return 'CTB2'
    if ext == '.xctb':
        parse_xctb(raw)
        return 'XCTB'
    raise ValueError('Unsupported extension {!r}. Expected .ctb2 or .xctb; .ctb is different.'.format(ext))


def write_output(source, output, xml, overwrite):
    if output.resolve() == source.resolve():
        raise ValueError('Refusing to overwrite original radio archive')
    if overwrite:
        # Atomic replacement of XML only, with a temp file in the same folder.
        import os
        import tempfile
        fd, temp = tempfile.mkstemp(prefix='.motorola-decoder-', suffix='.tmp', dir=str(output.parent))
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(xml)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, output)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    else:
        with output.open('xb') as f:
            f.write(xml)




def local(element):
    return element.tag.rsplit('}', 1)[-1]


def first_child(parent, name):
    return next((e for e in parent if local(e) == name), None) if parent is not None else None


def child_text(parent, name):
    e = first_child(parent, name)
    return e.text.strip() if e is not None and e.text and e.text.strip() else None


def inflate_dbnode(packed):
    """Strict raw DEFLATE decoder, with a 256 MiB safety bound."""
    dec = zlib.decompressobj(-15)
    try:
        xml = dec.decompress(packed, MAX_DB_NODE_XML + 1)
        if len(xml) > MAX_DB_NODE_XML or dec.unconsumed_tail:
            raise ValueError('DBNode exceeds 256 MiB expansion limit')
        xml += dec.flush(MAX_DB_NODE_XML + 1 - len(xml))
    except zlib.error as exc:
        raise ValueError('DBNode raw DEFLATE decompression failed: ' + str(exc)) from exc
    if not dec.eof or dec.unused_data or len(xml) > MAX_DB_NODE_XML:
        raise ValueError('Incomplete/oversized DBNode DEFLATE stream or trailing bytes')
    return xml


def dbnode_summary(db_root):
    """Count concrete record entries, not arbitrary text occurrences."""
    top_record = next((e for e in db_root if local(e) == 'DBNode' and e.get(XSI_TYPE) == 'Record'), None)
    result = {}
    for name, key in [('ConventionalPersonality', 'channel_personality_records'),
                      ('Zone', 'zone_records'),
                      ('PCRContacts', 'contact_records'),
                      ('ScanItems', 'scan_item_records')]:
        group = next((e for e in top_record if local(e) == 'DBNode' and e.get('Name') == name), None) if top_record is not None else None
        result[key] = sum(1 for e in group if local(e) == 'DBNode' and e.get(XSI_TYPE) == 'Record') if group is not None else None
    result['dbnode_xml_root_name'] = db_root.get('Name')
    result['dbnode_xml_original_version'] = db_root.get('OriginalVersion')
    return result


def extract_dbnode(xml_root, radio_xml_bytes, source_label, source_hash, archive_format, details):
    working = first_child(xml_root, 'WorkingCodeplug')
    config = first_child(working, 'Configuration')
    field = first_child(config, 'DBNodeCmpBytes')
    if field is None or not field.text:
        raise ValueError('Missing MatrixRadio/WorkingCodeplug/Configuration/DBNodeCmpBytes; nothing to extract')
    try:
        packed = base64.b64decode(''.join(field.text.split()), validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError('DBNodeCmpBytes is not valid Base64: ' + str(exc)) from exc
    db_xml = inflate_dbnode(packed)
    db_root = ET.fromstring(db_xml)
    if local(db_root) != 'DBNode':
        raise ValueError('Expected decompressed <DBNode>, found <{}>'.format(local(db_root)))
    summary = {
        'input': source_label,
        'input_sha256': source_hash,
        'input_format': archive_format,
        'source_matrixradio_xml_sha256': hashlib.sha256(radio_xml_bytes).hexdigest(),
        'field_path': 'MatrixRadio/WorkingCodeplug/Configuration/DBNodeCmpBytes',
        'radio_model': child_text(xml_root, 'ModelNumber'),
        'serial_number': first_nonempty(xml_root, 'SerialNumber'),
        'radio_alias': child_text(working, 'RadioAlias'),
        'radio_id': child_text(working, 'RadioId'),
        'codeplug_version': child_text(working, 'CodeplugVersion'),
        'firmware_version': child_text(working, 'FirmwareVersion'),
        'configuration_name': child_text(config, 'Name'),
        'original_radio_serial': child_text(config, 'Original_RadioSN'),
        'dbnode_compression': 'raw DEFLATE (wbits=-15)',
        'dbnode_compressed_bytes': len(packed),
        'dbnode_compressed_sha256': hashlib.sha256(packed).hexdigest(),
        'dbnode_xml_bytes': len(db_xml),
        'dbnode_xml_sha256': hashlib.sha256(db_xml).hexdigest(),
        'dbnode_compressed_hex_prefix': packed[:32].hex(' ').upper(),
        'dbnode_xml_hex_prefix': db_xml[:24].hex(' ').upper(),
        'archive_verification': details,
    }
    summary.update(dbnode_summary(db_root))
    return packed, db_xml, summary


def inflate_extra_xml(packed, tag):
    """Strict, bounded raw DEFLATE for optional Motorola MultipleFieldsXML."""
    dec = zlib.decompressobj(-15)
    try:
        xml = dec.decompress(packed, MAX_EXTRA_FIELD_XML + 1)
        if len(xml) > MAX_EXTRA_FIELD_XML or dec.unconsumed_tail:
            raise ValueError('{} exceeds 32 MiB expansion limit'.format(tag))
        xml += dec.flush(MAX_EXTRA_FIELD_XML + 1 - len(xml))
    except zlib.error as exc:
        raise ValueError('{} raw DEFLATE decompression failed: {}'.format(tag, exc)) from exc
    if not dec.eof or dec.unused_data or len(xml) > MAX_EXTRA_FIELD_XML:
        raise ValueError('{} DEFLATE stream is incomplete, oversized, or has trailing bytes'.format(tag))
    return xml


def extract_additional_fields(xml_root):
    """Decode the two *independent* compressed XML fields under WorkingCodeplug.

    Missing fields are normal on other Motorola radios/versions; malformed
    fields which are present cause a clear failure rather than silent data loss.
    Preserves the exact original expanded XML byte strings.
    Returns (dict of tag -> decompressed XML bytes, CSV bytes or None, stats).
    """
    working = first_child(xml_root, 'WorkingCodeplug')
    if working is None:
        raise ValueError('MatrixRadio is missing WorkingCodeplug')

    expanded_xml = {}
    stats = {}
    csv_rows = []
    for tag in ('DeviceInfoFields', 'ExtendedFields'):
        field_node = first_child(working, tag)
        if field_node is None or not field_node.text or not field_node.text.strip():
            stats[tag] = {'present': False, 'field_count': 0}
            continue
        try:
            packed = base64.b64decode(''.join(field_node.text.split()), validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError('{} is not valid Base64: {}'.format(tag, exc)) from exc
        decoded_xml = inflate_extra_xml(packed, tag)
        extra_root = ET.fromstring(decoded_xml)
        if local(extra_root) != 'MultipleFieldsXML':
            raise ValueError('{}: expected <MultipleFieldsXML>, found <{}>'.format(tag, local(extra_root)))
        if any(local(e) != 'Field' for e in extra_root):
            raise ValueError('{} contains unexpected child element(s)'.format(tag))

        fields = list(extra_root)
        for index, field in enumerate(fields, 1):
            name = field.get('Name')
            if not name:
                raise ValueError('{} field #{} has no Name'.format(tag, index))
            value_node = first_child(field, 'Value')
            if value_node is None:
                raise ValueError('{} field #{} ({}) has no Value node'.format(tag, index, name))
            # Preserve the full original XML separately. The CSV is a flat view;
            # never silently stringify nested/complex values as ordinary scalars.
            if len(value_node):
                raise ValueError('{} field #{} ({}) has complex Value; XML retained but flat CSV unsupported'.format(
                    tag, index, name))
            value = value_node.text
            csv_rows.append((
                tag, index, name, value_node.get(XSI_TYPE) or '',
                'NULL' if value is None else 'VALUE',
                '' if value is None else value,
                field.get('ValueShallLocalize', ''),
            ))

        expanded_xml[tag] = decoded_xml
        stats[tag] = {
            'present': True,
            'field_path': 'MatrixRadio/WorkingCodeplug/' + tag,
            'compression': 'Base64 + raw DEFLATE (wbits=-15)',
            'compressed_bytes': len(packed),
            'compressed_sha256': hashlib.sha256(packed).hexdigest(),
            'xml_bytes': len(decoded_xml),
            'xml_sha256': hashlib.sha256(decoded_xml).hexdigest(),
            'field_count': len(fields),
        }

    if not expanded_xml:
        return expanded_xml, None, stats

    # Preserve same column structure as the earlier 462-field manual extraction.
    output = io.StringIO(newline='')
    writer = csv.writer(output, lineterminator='\r\n')
    writer.writerow(('SourceXMLTag', 'Index', 'MotorolaFieldName', 'XMLType',
                     'ValueStatus', 'Value', 'ValueShallLocalize'))
    writer.writerows(csv_rows)
    # Excel recognizes the UTF-8 BOM; it also preserves non-ASCII field values.
    csv_bytes = ('\ufeff' + output.getvalue()).encode('utf-8')
    return expanded_xml, csv_bytes, stats



# Pretty MatrixRadio only: preserve data verbatim in the normal XML and
# extracted files, and replace large Base64 blobs with traceable comments.
PRETTY_B64_DESCRIPTIONS = {
    'DBNodeCmpBytes': 'xml/<stem>.DBNode.xml; binary/<stem>.DBNodeCmpBytes.bin',
    'DeviceInfoFields': 'xml/<stem>.DeviceInfoFields.xml',
    'ExtendedFields': 'xml/<stem>.ExtendedFields.xml',
    'CFS': 'xml/<stem>.CFS.xml',
    'SyncDataSource': 'xml/<stem>.SyncDataSource.xml; binary/<stem>.SyncDataSource.uncompressed.nbfx',
}


class NbfxDecodeError(ValueError):
    """Known MC-NBFX record not supported; preserve original binary instead."""


class NbfxReader:
    """Read the .NET Binary XML subset present in Motorola SyncDataSource.

    Uses explicit record parsing; no Motorola binaries or .NET runtime needed.
    Fails closed on unsupported record types or dictionary lookups rather than
    returning invented XML. Source: Microsoft MC-NBFX public format spec.
    """
    def __init__(self, data):
        if len(data) > MAX_EMBEDDED_XML:
            raise NbfxDecodeError('NBFX input exceeds expansion safety bound')
        self.data, self.pos, self.stack, self.parts = data, 0, [], []
        self.element_count = 0

    def read(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise NbfxDecodeError('Truncated NBFX at offset {}'.format(self.pos))
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self):
        return self.read(1)[0]

    def u31(self):
        result, shift = 0, 0
        for _ in range(5):
            part = self.u8()
            result |= (part & 127) << shift
            if not part & 128:
                if result > 0x7fffffff:
                    raise NbfxDecodeError('Invalid multibyte integer')
                return result
            shift += 7
        raise NbfxDecodeError('Invalid multibyte integer at {}'.format(self.pos))

    def string(self):
        return self.read(self.u31()).decode('utf-8')

    def text_value(self, code):
        typ = code & 0xfe
        if typ == 0x80: return '0'
        if typ == 0x82: return '1'
        if typ == 0x84: return 'false'
        if typ == 0x86: return 'true'
        if typ == 0x88: return str(struct.unpack('<b', self.read(1))[0])
        if typ == 0x8a: return str(struct.unpack('<h', self.read(2))[0])
        if typ == 0x8c: return str(struct.unpack('<i', self.read(4))[0])
        if typ == 0x8e: return str(struct.unpack('<q', self.read(8))[0])
        if typ == 0x90: return str(struct.unpack('<f', self.read(4))[0])
        if typ == 0x92: return str(struct.unpack('<d', self.read(8))[0])
        if typ == 0x98: return self.read(self.u8()).decode('utf-8')
        if typ == 0x9a: return self.read(struct.unpack('<H', self.read(2))[0]).decode('utf-8')
        if typ == 0x9c: return self.read(struct.unpack('<I', self.read(4))[0]).decode('utf-8')
        if typ == 0x9e: return base64.b64encode(self.read(self.u8())).decode('ascii')
        if typ == 0xa0: return base64.b64encode(self.read(struct.unpack('<H', self.read(2))[0])).decode('ascii')
        if typ == 0xa2: return base64.b64encode(self.read(struct.unpack('<I', self.read(4))[0])).decode('ascii')
        if typ == 0xa8: return ''
        if typ == 0xae: return str(struct.unpack('<q', self.read(8))[0])
        if typ == 0xb0: return str(uuid.UUID(bytes_le=self.read(16)))
        if typ == 0xb2: return str(struct.unpack('<Q', self.read(8))[0])
        if typ == 0xb4: return 'true' if self.u8() else 'false'
        if typ in (0xb6, 0xb8, 0xba):
            length = (self.u8() if typ == 0xb6 else
                      struct.unpack('<H', self.read(2))[0] if typ == 0xb8 else
                      struct.unpack('<I', self.read(4))[0])
            return self.read(length).decode('utf-16-le')
        raise NbfxDecodeError('Unsupported NBFX text type 0x{:02X} at offset {}'.format(code, self.pos))

    def element_name(self, code):
        if code == 0x40: return self.string()
        if code == 0x41: return self.string() + ':' + self.string()
        if 0x5e <= code <= 0x77:
            return chr(ord('a') + code - 0x5e) + ':' + self.string()
        raise NbfxDecodeError('Unsupported NBFX element type 0x{:02X}'.format(code))

    def attribute(self, code):
        if code == 0x08: return 'xmlns', self.string()
        if code == 0x09: return 'xmlns:' + self.string(), self.string()
        if code == 0x04: name = self.string()
        elif code == 0x05: name = self.string() + ':' + self.string()
        elif 0x26 <= code <= 0x3f:
            name = chr(ord('a') + code - 0x26) + ':' + self.string()
        else:
            raise NbfxDecodeError('Unsupported NBFX attribute type 0x{:02X}'.format(code))
        text_type = self.u8()
        if not 0x80 <= text_type <= 0xbd:
            raise NbfxDecodeError('Invalid NBFX attribute value type 0x{:02X}'.format(text_type))
        return name, self.text_value(text_type)

    def close_pending(self):
        if self.stack and not self.stack[-1][1]:
            self.parts.append('>')
            self.stack[-1][1] = True

    def end_element(self):
        if not self.stack:
            raise NbfxDecodeError('Extra NBFX EndElement')
        name, opened = self.stack.pop()
        self.parts.append('</{}>'.format(name) if opened else '/>')

    def parse(self):
        while self.pos < len(self.data):
            at = self.pos
            code = self.u8()
            if code == 0x01:
                self.end_element()
            elif 0x40 <= code <= 0x77:
                self.close_pending()
                name = self.element_name(code)
                self.parts.append('<' + name)
                self.stack.append([name, False])
                self.element_count += 1
            elif 0x04 <= code <= 0x3f:
                if not self.stack or self.stack[-1][1]:
                    raise NbfxDecodeError('NBFX attribute not inside start tag at {}'.format(at))
                name, value = self.attribute(code)
                self.parts.append(' ' + name + '=' + xml_quoteattr(value))
            elif 0x80 <= code <= 0xbd:
                value = self.text_value(code)
                self.close_pending()
                self.parts.append(xml_escape(value))
                if code & 1:
                    self.end_element()
            elif code == 0x02:
                self.close_pending()
                comment = self.string().replace('--', '- -')
                self.parts.append('<!--' + comment + '-->')
            else:
                raise NbfxDecodeError('Unsupported NBFX record 0x{:02X} at offset {}'.format(code, at))
            if len(self.parts) > 1000000:
                raise NbfxDecodeError('NBFX has excessive number of records')
        if self.stack:
            raise NbfxDecodeError('NBFX has unclosed elements')
        xml = ''.join(self.parts).encode('utf-8')
        if len(xml) > MAX_EMBEDDED_XML:
            raise NbfxDecodeError('NBFX XML exceeds safety limit')
        root = ET.fromstring(xml)
        if local(root) != 'SyncDataSourceOfConfiguration':
            raise NbfxDecodeError('Unexpected NBFX root {}'.format(local(root)))
        return xml, self.element_count


def extract_embedded_sections(xml_root):
    """Decode CFS + SyncDataSource, keeping compressed/uncompressed raw data.

    The NBFX parser either succeeds as valid XML or emits a clear unparsed
    status while retaining the original bytes. No speculative best-effort XML.
    """
    working = first_child(xml_root, 'WorkingCodeplug')
    config = first_child(working, 'Configuration')
    records = {}
    stats = {}
    for tag, parent, expected_root in (
        ('CFS', working, 'Os'),
        ('SyncDataSource', first_child(config, 'ConfigurationExt'), 'SyncDataSourceOfConfiguration'),
    ):
        # SyncDataSource lives under ConfigurationExt, with a namespace-qualified tag.
        node = first_child(parent, tag)
        if node is None or not node.text or not node.text.strip():
            stats[tag] = {'present': False}
            continue
        packed = base64.b64decode(''.join(node.text.split()), validate=True)
        expanded = inflate_extra_xml(packed, tag)
        record = {'packed': packed, 'expanded': expanded}
        stat = {
            'present': True, 'compressed_bytes': len(packed),
            'compressed_sha256': hashlib.sha256(packed).hexdigest(),
            'expanded_bytes': len(expanded),
            'expanded_sha256': hashlib.sha256(expanded).hexdigest(),
        }
        if tag == 'CFS':
            root = ET.fromstring(expanded)
            if local(root) != expected_root:
                raise ValueError('CFS expected <Os>, found <{}>'.format(local(root)))
            record['xml'] = expanded
            stat['status'] = 'xml_decoded'
            stat['feature_records'] = sum(local(child) == 'O' for child in root)
        else:
            try:
                xml, element_count = NbfxReader(expanded).parse()
                record['xml'] = xml
                stat['status'] = 'binary_xml_decoded'
                stat['nbfx_xml_elements'] = element_count
                stat['xml_sha256'] = hashlib.sha256(xml).hexdigest()
            except (NbfxDecodeError, ET.ParseError, UnicodeError) as exc:
                stat['status'] = 'NBFX_NOT_FULLY_DECODED'
                stat['error'] = str(exc)
        records[tag] = record
        stats[tag] = stat
    return records, stats


def extract_opaque_base64(xml_root, ignored):
    """Preserve high-confidence Base64 fields whose semantics are not known.

    Only recognizes sufficiently long, canonical Base64 values. Does not
    pretend to decode password hashes or encrypted serial numbers.
    """
    found, stats = {}, []
    for element in xml_root.iter():
        name = local(element)
        if name in ignored or not element.text:
            continue
        text = ''.join(element.text.split())
        if len(text) < 64 or len(text) % 4 or not re.fullmatch('[A-Za-z0-9+/]+={0,2}', text):
            continue
        try:
            binary = base64.b64decode(text, validate=True)
        except (ValueError, TypeError):
            continue
        # Re-encoding excludes Base64-like strings with noncanonical padding.
        if base64.b64encode(binary).decode('ascii') != text:
            continue
        if len(binary) < 32:
            continue
        safe = re.sub(r'[^A-Za-z0-9_-]', '_', name)
        index = len(found) + 1
        key = '{:02d}.{}'.format(index, safe)
        found[key] = binary
        stats.append({'tag': name, 'key': key, 'bytes': len(binary),
                      'sha256': hashlib.sha256(binary).hexdigest(),
                      'status': 'base64_decoded_binary_opaque_not_decoded'})
    return found, stats


def register_pretty_namespaces(document):
    """Use stable, readable prefixes instead of auto-generated ns0/ns1 names.

    Motorola reuses the a/d aliases in nested scopes for distinct URIs; these
    are mapped to distinct prefixes in the *read-only* pretty view.
    """
    if document == 'matrix':
        mapping = (
            ('', 'http://schemas.datacontract.org/2004/07/Motorola.CommonCPS.Server.EntityModel'),
            ('i', 'http://www.w3.org/2001/XMLSchema-instance'),
            ('z', 'http://schemas.microsoft.com/2003/10/Serialization/'),
            ('a', 'http://schemas.datacontract.org/2004/07/Motorola.CommonCPS.Server.EntityModel.EntityModel'),
            ('db', 'http://schemas.datacontract.org/2004/07/Motorola.CommonCPS.Server.EntityModel.DBNodeDataModels'),
            ('b', 'http://schemas.microsoft.com/2003/10/Serialization/Arrays'),
            ('c', 'http://schemas.datacontract.org/2004/07/Motorola.CommonCPS.Server.EntityModel.GenericModel.DBNodeDataModels'),
            ('d', 'http://www.w3.org/2001/XMLSchema'),
            ('gm', 'http://schemas.datacontract.org/2004/07/Motorola.CommonCPS.Server.EntityModel.GenericModel'),
        )
    else:
        mapping = (
            ('xsi', 'http://www.w3.org/2001/XMLSchema-instance'),
            ('xsd', 'http://www.w3.org/2001/XMLSchema'),
        )
    for prefix, uri in mapping:
        ET.register_namespace(prefix, uri)


def render_pretty_xml(original_xml, document='other', strip_base64=False, omitted_files=None):
    """Return valid UTF-8 indented XML; original bytes are never modified.

    Only the MatrixRadio presentation copy has Base64 removed. The full
    extraction paths operate on the unmodified original XML independently.
    """
    root = ET.fromstring(original_xml)
    omitted = []
    if strip_base64:
        if local(root) != 'MatrixRadio':
            raise ValueError('Only MatrixRadio may have Base64 sections removed')
        # Build parent map before replacement; enumerate over a stable list.
        parent_map = {child: parent for parent in root.iter() for child in parent}
        omitted_files = omitted_files or {}
        for node in list(root.iter()):
            tag = local(node)
            if tag not in omitted_files or not node.text or not node.text.strip():
                continue
            parent = parent_map.get(node)
            if parent is None:
                continue
            # Only strip Base64 content, not a similarly named structural node.
            try:
                base64.b64decode(''.join(node.text.split()), validate=True)
            except (ValueError, TypeError):
                continue
            count = len(node.text.strip())
            idx = list(parent).index(node)
            parent.remove(node)
            comment = ' {}: omitted {} Base64 characters. {}. '.format(
                tag, count, omitted_files[tag])
            parent.insert(idx, ET.Comment(comment))
            omitted.append({'tag': tag, 'base64_characters': count})
    else:
        expected = {'dbnode': 'DBNode', 'cfs': 'Os',
                    'sync': 'SyncDataSourceOfConfiguration'}.get(document, 'MultipleFieldsXML')
        if local(root) != expected:
            raise ValueError('Pretty XML root is not {}: {}'.format(expected, local(root)))
    # Motorola embeds a *second* Base64 layer in CFS n attributes and
    # MatrixRadio FeatureNotice elements. Decode readable UTF-8 notices
    # for the presentation copy only; original XML remains untouched.
    def readable_notice(value):
        raw = ''.join(value.split()) if value else ''
        if len(raw) < 12 or len(raw) % 4 or not re.fullmatch('[A-Za-z0-9+/]+={0,2}', raw):
            return None
        try:
            binary = base64.b64decode(raw, validate=True)
            decoded = binary.decode('utf-8')
            if base64.b64encode(binary).decode('ascii') == raw and decoded.startswith('{') and decoded.endswith('}') and all(c.isprintable() for c in decoded):
                return decoded
        except (ValueError, UnicodeError):
            pass
        return None

    if document == 'matrix':
        for element in root.iter():
            if isinstance(element.tag, str) and local(element) == 'FeatureNotice' and element.text:
                value = readable_notice(element.text)
                if value is not None:
                    element.text = value
    if document == 'cfs':
        for element in root.iter():
            if 'n' in element.attrib:
                value = readable_notice(element.attrib['n'])
                if value is not None:
                    del element.attrib['n']
                    element.set('n_decoded', value)

    register_pretty_namespaces(document)
    ET.indent(root, space='  ')
    encoded = ET.tostring(root, encoding='utf-8', xml_declaration=True, short_empty_elements=True) + b'\n'
    # Validate the generated document, not just the original source.
    ET.fromstring(encoded)
    return encoded, omitted

def publish_outputs(payloads, inputs, overwrite):
    """Preflight every destination; stage all content before any final publication."""
    files = list(payloads)
    if len(set(p.resolve() for p in files)) != len(files):
        raise ValueError('Output paths collide with one another')
    for path in files:
        if path.resolve() in inputs:
            raise ValueError('Output path would overwrite source: ' + str(path))
        if path.is_dir():
            raise ValueError('Output path is a directory: ' + str(path))
        if path.exists() and not overwrite:
            raise FileExistsError('Output exists: {} (use --overwrite explicitly)'.format(path))
    staging = []
    published = []
    try:
        for path, data in payloads.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temp = tempfile.mkstemp(prefix='.motorola-staging-', suffix='.tmp', dir=str(path.parent))
            staging.append(Path(temp))
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            if hashlib.sha256(Path(temp).read_bytes()).digest() != hashlib.sha256(data).digest():
                raise ValueError('Staged output SHA-256 mismatch: ' + str(path))
        for (path, _), temp in zip(payloads.items(), staging):
            if overwrite:
                os.replace(temp, path)
            else:
                # No-clobber publish (works on WSL and Linux filesystems).
                os.link(temp, path)
                temp.unlink()
            published.append(path)
    except Exception:
        # With no-clobber publication, delete only files WE created on this attempt.
        # In overwrite mode, do not delete targets that might be older user files.
        if not overwrite:
            for path in published:
                try:
                    path.unlink()
                except OSError:
                    pass
        raise
    finally:
        for temp in staging:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('source', type=Path, help='Motorola .xctb, .ctb2, or already-decoded MatrixRadio .xml')
    ap.add_argument('-o', '--output', type=Path, help='Radio XML output name (for archives only)')
    ap.add_argument('--outdir', type=Path, help='Root output directory; codeplug-name subfolder is created inside it')
    ap.add_argument('--overwrite', action='store_true', help='Explicitly replace existing outputs (never source)')
    ap.add_argument('--inspect', action='store_true', help='Show archive header information only; no decoding or writes')
    ap.add_argument('--verify-only', action='store_true', help='Decode/expand/validate everything without writing files')
    ap.add_argument('--pretty', action='store_true', help='Write indented XML for MatrixRadio and all decoded embedded XML; strip Base64 blobs from MatrixRadio pretty view only')
    pw_group = ap.add_mutually_exclusive_group()
    pw_group.add_argument('--password-file', type=Path,
                          help='UTF-8 file containing archive password; one trailing CR/LF is ignored')
    pw_group.add_argument('--password-env', metavar='VARIABLE',
                          help='Read archive password from the named environment variable')
    pw_group.add_argument('--prompt-password', action='store_true',
                          help='Securely prompt for archive password (explicit opt-in only)')
    pw_group.add_argument('--password',
                          help='Archive password (INSECURE: visible in shell history/process list)')
    args = ap.parse_args()
    if args.output and args.outdir:
        raise ValueError('Use either -o/--output or --outdir, not both')
    raw = args.source.read_bytes()
    suffix = args.source.suffix.lower()
    fmt = 'XML' if suffix == '.xml' else detect_format(args.source, raw)
    source_sha = hashlib.sha256(raw).hexdigest()
    base = args.source.stem
    if base.endswith('.decoded'):
        base = base[:-len('.decoded')]
    # Every codeplug has its own output tree by default.
    # --outdir changes the parent, not the per-codeplug subfolder convention.
    destdir = (args.outdir or args.source.parent) / base
    pretty_dir, binary_dir, xml_dir = destdir / 'pretty', destdir / 'binary', destdir / 'xml'
    radio_out = args.output or (xml_dir / (base + '.decoded.xml'))
    dbxml_out = xml_dir / (base + '.DBNode.xml')
    dbbin_out = binary_dir / (base + '.DBNodeCmpBytes.bin')
    metadata_out = destdir / (base + '.DBNode.metadata.json')
    extra_xml_out = {tag: xml_dir / (base + '.' + tag + '.xml')
                     for tag in ('DeviceInfoFields', 'ExtendedFields')}
    extra_csv_out = destdir / (base + '.AdditionalFields.csv')
    embedded_xml_out = {tag: xml_dir / (base + '.' + tag + '.xml')
                        for tag in ('CFS', 'SyncDataSource')}
    embedded_bin_out = {tag: binary_dir / (base + '.' + tag + '.compressed.bin')
                        for tag in ('CFS', 'SyncDataSource')}
    pretty_radio_out = pretty_dir / (base + '.decoded.pretty.xml')
    pretty_dbnode_out = pretty_dir / (base + '.DBNode.pretty.xml')
    pretty_extra_out = {tag: pretty_dir / (base + '.' + tag + '.pretty.xml')
                        for tag in ('DeviceInfoFields', 'ExtendedFields', 'CFS', 'SyncDataSource')}
    print('[1/5] SOURCE:', args.source, flush=True)
    print('FORMAT:', fmt, 'SOURCE_BYTES:', len(raw), 'SHA256:', source_sha, flush=True)
    if fmt == 'CTB2':
        print('COPYRIGHT_YEAR:', parse_ctb2(raw)[0], flush=True)
    elif fmt == 'XCTB':
        header, _, _ = parse_xctb(raw)
        print('DATA_MODEL:', header['dataModelVersion']['Version'],
              'RM_VERSION:', header.get('rmVersion', '(none)'),
              'PROTECTION:', header['protect'], flush=True)
    if args.inspect:
        print('INSPECTION_ONLY: YES (no decoding/DBNode extraction)', flush=True)
        return
    if fmt == 'XML':
        if args.output:
            raise ValueError('-o/--output is only for radio archives, not already decoded XML')
        xml = raw
        xml_root = verify_matrixradio(xml)
        details = {'FORMAT': 'Already-decoded MatrixRadio XML', 'INTERNAL_SHA256_VERIFIED': 'N/A'}
    else:
        print('[2/5] Decoding archive and verifying MatrixRadio XML...', flush=True)
        if fmt == 'CTB2':
            if any((args.password_file, args.password_env, args.prompt_password, args.password is not None)):
                raise ValueError('Password options apply only to user-protected XCTB archives')
            xml, xml_root, details = decode_ctb2(raw)
        else:
            if header['protect'] == 'd':
                if any((args.password_file, args.password_env, args.prompt_password, args.password is not None)):
                    raise ValueError('Password options supplied for default-protected XCTB; remove them')
                password = None
            elif args.password_file:
                password = args.password_file.read_text(encoding='utf-8-sig').rstrip('\r\n')
            elif args.password_env:
                password = os.environ.get(args.password_env)
                if password is None:
                    raise ValueError('Password environment variable {!r} is not set'.format(args.password_env))
            elif args.prompt_password:
                password = getpass.getpass('XCTB archive password: ')
            else:
                password = args.password
            xml, xml_root, details = decode_xctb(raw, password=password)
            password = None  # Never copy the password into output metadata.
    print('RADIO_ALIAS:', child_text(first_child(xml_root, 'WorkingCodeplug'), 'RadioAlias') or '(not present)', flush=True)
    print('SERIAL_NUMBER:', first_nonempty(xml_root, 'SerialNumber'), flush=True)
    print('MATRIXRADIO_XML_BYTES:', len(xml), flush=True)
    print('[3/5] Base64 decoding + inflating DBNodeCmpBytes...', flush=True)
    packed, db_xml, metadata = extract_dbnode(xml_root, xml, str(args.source), source_sha, fmt, details)
    print('[4/5] Validated <DBNode> XML:', len(db_xml), 'bytes', flush=True)
    expanded_extra, extra_csv, extra_stats = extract_additional_fields(xml_root)
    metadata['embedded_fields'] = extra_stats
    for tag in ('DeviceInfoFields', 'ExtendedFields'):
        stat = extra_stats[tag]
        print('{}: {} ({} fields)'.format(tag,
              'DECODED' if stat['present'] else 'NOT PRESENT', stat['field_count']), flush=True)
    print('ADDITIONAL_FIELDS_TOTAL:', sum(v['field_count'] for v in extra_stats.values()), flush=True)
    print('CHANNEL_PERSONALITY_RECORDS:', metadata['channel_personality_records'], flush=True)
    print('ZONES:', metadata['zone_records'], flush=True)
    print('DBNODE_SHA256:', metadata['dbnode_xml_sha256'], flush=True)
    print('[EMBEDDED] Decoding CFS and .NET NBFX SyncDataSource...', flush=True)
    embedded, embedded_stats = extract_embedded_sections(xml_root)
    metadata['other_embedded_sections'] = embedded_stats
    opaque, opaque_stats = extract_opaque_base64(xml_root,
        set(PRETTY_B64_DESCRIPTIONS))
    metadata['other_base64_fields'] = opaque_stats
    for tag, status in embedded_stats.items():
        print('{}: {}'.format(tag, status.get('status', 'NOT PRESENT')), flush=True)
    for entry in opaque_stats:
        print('UNINTERPRETED_BASE64: {} ({} binary bytes; preserved)'.format(
              entry['tag'], entry['bytes']), flush=True)
    pretty_payloads = {}
    if args.pretty:
        print('[PRETTY] Creating readable XML for all decoded sections...', flush=True)
        omitted_paths = {}
        if 'DBNodeCmpBytes' in PRETTY_B64_DESCRIPTIONS:
            omitted_paths['DBNodeCmpBytes'] = str(dbxml_out.relative_to(destdir))
        for tag in expanded_extra:
            omitted_paths[tag] = str(extra_xml_out[tag].relative_to(destdir))
        for tag in embedded:
            if 'xml' in embedded[tag]:
                omitted_paths[tag] = str(embedded_xml_out[tag].relative_to(destdir))
            else:
                omitted_paths[tag] = str((binary_dir / (base + '.' + tag + '.uncompressed.nbfx')).relative_to(destdir))
        for entry in opaque_stats:
            omitted_paths[entry['tag']] = str((binary_dir / (base + '.' + entry['key'] + '.opaque.bin')).relative_to(destdir))
        pretty_radio_xml, omitted = render_pretty_xml(
            xml, document='matrix', strip_base64=True, omitted_files=omitted_paths)
        pretty_payloads[pretty_radio_out] = pretty_radio_xml
        pretty_payloads[pretty_dbnode_out] = render_pretty_xml(db_xml, document='dbnode')[0]
        for tag, expanded in expanded_extra.items():
            pretty_payloads[pretty_extra_out[tag]] = render_pretty_xml(expanded, document='extra')[0]
        for tag, entry in embedded.items():
            if 'xml' in entry:
                pretty_payloads[pretty_extra_out[tag]] = render_pretty_xml(
                    entry['xml'], document='cfs' if tag == 'CFS' else 'sync')[0]
        print('PRETTY_BASE64_SECTIONS_OMITTED:',
              ', '.join(row['tag'] for row in omitted) or '(none)', flush=True)
        print('PRETTY_XML_FILES:', len(pretty_payloads), flush=True)
    if args.verify_only:
        print('[5/5] VERIFY_ONLY: All checks passed; no files written.', flush=True)
        return
    payloads = {}
    # Include an exact original XML copy even when source itself was decoded XML.
    payloads[radio_out] = xml
    payloads[dbxml_out] = db_xml
    payloads[dbbin_out] = packed
    for tag, data in expanded_extra.items():
        payloads[extra_xml_out[tag]] = data
        source_node = first_child(first_child(xml_root, 'WorkingCodeplug'), tag)
        packed_extra = base64.b64decode(''.join(source_node.text.split()), validate=True)
        payloads[binary_dir / (base + '.' + tag + '.compressed.bin')] = packed_extra
    if extra_csv is not None:
        payloads[extra_csv_out] = extra_csv
    for tag, entry in embedded.items():
        payloads[embedded_bin_out[tag]] = entry['packed']
        if 'xml' in entry:
            payloads[embedded_xml_out[tag]] = entry['xml']
        if tag == 'SyncDataSource':
            payloads[binary_dir / (base + '.' + tag + '.uncompressed.nbfx')] = entry['expanded']
    for entry in opaque_stats:
        key = entry['key']
        payloads[binary_dir / (base + '.' + key + '.opaque.bin')] = opaque[key]
    payloads.update(pretty_payloads)
    metadata['output_layout'] = 'codeplug-named folder with xml/, pretty/ and binary/'
    metadata['output_file_count'] = len(payloads) + 2
    payloads[metadata_out] = (json.dumps(metadata, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
    readme = [
        'MOTOROLA CODEPLUG DECODED OUTPUT (PRIVATE DATA)\n',
        'Source: ' + str(args.source),
        'Source SHA256: ' + source_sha,
        'Format: ' + fmt,
        'All files are derived from the original input, which was NEVER changed.',
        'The xml/ folder contains the original decompressed/decoded XML sections.',
        'The pretty/ folder contains human-readable indented XML (only with --pretty).',
        'The binary/ folder preserves compressed DEFLATE bytes and the original',
        'decompressed WCF NBFX representation of SyncDataSource.',
        'AdditionalFields.csv lists DeviceInfoFields and ExtendedFields values.',
        'The .decoded.pretty.xml file omits Base64 blobs and points to extracted files.',
        'The .decoded.xml file preserves the exact XML bytes from the input/archive.',
        'Opaque .bin output means base64 was decoded, but the underlying bytes',
        'were NOT decoded or interpreted. No claim is made that it is plaintext.',
        'NONE of these outputs should be used as a writable Motorola codeplug.',
        'WARNING: These files can contain plaintext passwords, RAS keys, privacy',
        'keys, serials, and other confidential or operational radio settings.\n',
    ]
    payloads[destdir / 'READ_ME_FIRST.txt'] = ('\n'.join(readme)).encode('utf-8')
    inputs = {args.source.resolve()}
    print('[5/5] Writing all outputs (no overwrite unless --overwrite)...', flush=True)
    publish_outputs(payloads, inputs, args.overwrite)
    for path in payloads:
        print('OUTPUT:', path, flush=True)
    print('SUCCESS: MatrixRadio, DBNode, CFS, SyncDataSource, and additional fields processed; source untouched.', flush=True)
    print('OUTPUT_FOLDER:', destdir, flush=True)
    print('SECURITY: XML/CSV may contain RAS/EP keys, codeplug passwords and other private data.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except ImportError as exc:
        sys.exit('ERROR: Missing dependency: {}. Install: python3 -m pip install cryptography'.format(exc))
    except (OSError, ValueError, KeyError, IndexError, OverflowError, struct.error,
            zlib.error, gzip.BadGzipFile, json.JSONDecodeError, ET.ParseError) as exc:
        sys.exit('ERROR: {}'.format(exc))
