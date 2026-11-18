#!/usr/bin/env python3
"""One-shot Motorola MOTOTRBO CPS2 XCTB/CTB2 -> MatrixRadio XML + DBNode XML.

Supports:
  - .xctb: default protection (protect=d), data models 2.151.206,
    2.153.50, 2.159.125, using AES-CBC and embedded XML SHA-256 verification.
  - .ctb2: legacy CPS2 archive, DES-CBC + GZIP with a Ver:...\0 XML wrapper.
    GZIP CRC32, PKCS#7 padding, and MatrixRadio XML are validated.

CTB2 support was verified on an original 'Ver:02.16' archive. More CTB2
wrapper versions may exist; unknown wrappers are refused without guessing.

Also accepts already-decrypted MatrixRadio .xml files for DBNode extraction.
This does NOT support .ctb (CPS1), password-protected XCTB variants, or
writing codeplugs. No Motorola binaries are required at runtime.

The source file is NEVER modified. Output: <stem>.decrypted.xml (for archives),
<stem>.DBNode.xml, <stem>.DBNodeCmpBytes.bin, <stem>.DBNode.metadata.json.
The DBNode field is Base64-encoded raw DEFLATE; we validate the expanded DBNode
XML and report direct channel personality and zone counts.
Decrypted XML may contain passwords,
RAS/EP encryption keys, and confidential radio configuration.

Requires: Python 3.9+ and Python 'cryptography'.

Usage:
    ./decode_xctbcodeplug_multversions.py input.ctb2
    ./decode_xctbcodeplug_multversions.py input.xctb
    ./decode_xctbcodeplug_multversions.py input.ctb2 --inspect
    ./decode_xctbcodeplug_multversions.py input.ctb2 -o other.xml
    ./decode_xctbcodeplug_multversions.py input.ctb2 --overwrite
    ./decode_xctbcodeplug_multversions.py input.xctb --verify-only
    ./decode_xctbcodeplug_multversions.py already.decrypted.xml
"""

import argparse
import os
import tempfile
import base64
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
# Motorola's legacy CPS2 CTB2 BinaryFileDecryptionStrategy uses DES-CBC.
# The original 8-byte DES key/IV below were recovered from Motorola CPS2 DLL
# static FileCryptographyConstants; TripleDES K1=K2=K3 is equivalent to DES.
LEGACY_DES_KEY = b'NOWISTHE'
LEGACY_DES_IV = b'WINTEROF'
CTB2_PREFIX = re.compile(rb'^Copyright \(c\) ([0-9]{4}) Motorola Solutions, Inc\. All Rights Reserved ')
INNER_VERSION = re.compile(rb'^(Ver:[0-9]+\.[0-9]+)\x00')
MAX_XML_BYTES = 128 * 1024 * 1024
MAX_DB_NODE_XML = 256 * 1024 * 1024
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
    if header.get('type') != 'xctb' or header.get('protect') != 'd':
        raise ValueError('Only default-protected XCTB (protect=d) is supported')
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


def decode_xctb(raw):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    header, iv, ciphertext = parse_xctb(raw)
    hs = sha256(DEFAULT_AES_SEED)
    mixed_seed = byte_xor(hs[:16], hs[16:])
    key = sha256(byte_xor(iv, mixed_seed))
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad = padded[-1]
    if not (1 <= pad <= 16) or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError('Invalid XCTB AES padding')
    zipped = padded[:-pad]
    if not zipped.startswith(b'\x1f\x8b\x08'):
        raise ValueError('XCTB plaintext is not GZIP')
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
        raise ValueError('CTB2 decrypted payload lacks a recognized Ver:...\\0 wrapper')
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
    ap.add_argument('source', type=Path, help='Motorola .xctb, .ctb2, or already-decrypted MatrixRadio .xml')
    ap.add_argument('-o', '--output', type=Path, help='Radio XML output name (for archives only)')
    ap.add_argument('--outdir', type=Path, help='Output directory, defaults to source directory')
    ap.add_argument('--overwrite', action='store_true', help='Explicitly replace existing outputs (never source)')
    ap.add_argument('--inspect', action='store_true', help='Show archive header information only; no decryption or writes')
    ap.add_argument('--verify-only', action='store_true', help='Decode/expand/validate everything without writing files')
    args = ap.parse_args()
    if args.output and args.outdir:
        raise ValueError('Use either -o/--output or --outdir, not both')
    raw = args.source.read_bytes()
    suffix = args.source.suffix.lower()
    fmt = 'XML' if suffix == '.xml' else detect_format(args.source, raw)
    source_sha = hashlib.sha256(raw).hexdigest()
    base = args.source.stem
    if base.endswith('.decrypted'):
        base = base[:-len('.decrypted')]
    destdir = args.outdir or args.source.parent
    radio_out = args.output or (destdir / (base + '.decrypted.xml'))
    if args.output:
        destdir = args.output.parent
    dbxml_out = destdir / (base + '.DBNode.xml')
    dbbin_out = destdir / (base + '.DBNodeCmpBytes.bin')
    metadata_out = destdir / (base + '.DBNode.metadata.json')
    print('[1/5] SOURCE:', args.source, flush=True)
    print('FORMAT:', fmt, 'SOURCE_BYTES:', len(raw), 'SHA256:', source_sha, flush=True)
    if fmt == 'CTB2':
        print('COPYRIGHT_YEAR:', parse_ctb2(raw)[0], flush=True)
    elif fmt == 'XCTB':
        header, _, _ = parse_xctb(raw)
        print('DATA_MODEL:', header['dataModelVersion']['Version'], 'RM_VERSION:', header.get('rmVersion', '(none)'), flush=True)
    if args.inspect:
        print('INSPECTION_ONLY: YES (no decryption/DBNode extraction)', flush=True)
        return
    if fmt == 'XML':
        if args.output:
            raise ValueError('-o/--output is only for radio archives, not already decrypted XML')
        xml = raw
        xml_root = verify_matrixradio(xml)
        details = {'FORMAT': 'Already-decrypted MatrixRadio XML', 'INTERNAL_SHA256_VERIFIED': 'N/A'}
    else:
        print('[2/5] Decrypting archive and verifying MatrixRadio XML...', flush=True)
        xml, xml_root, details = decode_ctb2(raw) if fmt == 'CTB2' else decode_xctb(raw)
    print('RADIO_ALIAS:', child_text(first_child(xml_root, 'WorkingCodeplug'), 'RadioAlias') or '(not present)', flush=True)
    print('SERIAL_NUMBER:', first_nonempty(xml_root, 'SerialNumber'), flush=True)
    print('MATRIXRADIO_XML_BYTES:', len(xml), flush=True)
    print('[3/5] Base64 decoding + inflating DBNodeCmpBytes...', flush=True)
    packed, db_xml, metadata = extract_dbnode(xml_root, xml, str(args.source), source_sha, fmt, details)
    print('[4/5] Validated <DBNode> XML:', len(db_xml), 'bytes', flush=True)
    print('CHANNEL_PERSONALITY_RECORDS:', metadata['channel_personality_records'], flush=True)
    print('ZONES:', metadata['zone_records'], flush=True)
    print('DBNODE_SHA256:', metadata['dbnode_xml_sha256'], flush=True)
    if args.verify_only:
        print('[5/5] VERIFY_ONLY: All checks passed; no files written.', flush=True)
        return
    payloads = {}
    if fmt != 'XML':
        payloads[radio_out] = xml
    payloads[dbxml_out] = db_xml
    payloads[dbbin_out] = packed
    payloads[metadata_out] = (json.dumps(metadata, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
    inputs = {args.source.resolve()}
    print('[5/5] Writing all outputs (no overwrite unless --overwrite)...', flush=True)
    publish_outputs(payloads, inputs, args.overwrite)
    for path in payloads:
        print('OUTPUT:', path, flush=True)
    print('SUCCESS: MatrixRadio and DBNode extracted; input untouched.', flush=True)
    print('SECURITY: XML may contain RAS/EP keys and codeplug passwords.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except ImportError as exc:
        sys.exit('ERROR: Missing dependency: {}. Install: python3 -m pip install cryptography'.format(exc))
    except (OSError, ValueError, KeyError, IndexError, OverflowError, struct.error,
            zlib.error, gzip.BadGzipFile, json.JSONDecodeError, ET.ParseError) as exc:
        sys.exit('ERROR: {}'.format(exc))
