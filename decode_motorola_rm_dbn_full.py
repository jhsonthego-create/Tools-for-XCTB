#!/usr/bin/env python3
"""Decode Motorola Radio Management DBN and its nested compressed DBNode XML.

Verified with rm-export.dbn (Radio Management model 2.159.125):
  DBN  -> 64-byte copyright header, DES-CBC ciphertext, PKCS#7 padding
       -> 16-byte prefix, 4-byte little-endian JSON length, JSON, XML
       -> MatrixConfiguration XML / DBNodeCmpBytes (Base64 + raw DEFLATE)
       -> DBNode XML

The decoder is read-only with respect to the source. No network access.
Its outputs contain sensitive radio settings and potentially credentials.

Requires: Python 3.9+; pip install cryptography

Examples:
  python3 decode_motorola_rm_dbn_full.py rm-export.dbn
  python3 decode_motorola_rm_dbn_full.py rm-export.dbn --pretty
  python3 decode_motorola_rm_dbn_full.py rm-export.dbn --inspect
  python3 decode_motorola_rm_dbn_full.py rm-export.dbn --pretty --overwrite

Default outputs next to input:
  rm-export.decoded.xml            Exact outer MatrixConfiguration XML
  rm-export.DBNode.decompressed.xml  Exact inner DBNode XML

With --pretty, also writes:
  rm-export.pretty.xml
  rm-export.DBNode.pretty.xml

Existing outputs are never replaced unless --overwrite is explicitly supplied.
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path

BANNER = re.compile(rb'^Copyright \(c\) [0-9]{4} Motorola Solutions, Inc\. All Rights Reserved ')
LEGACY_DES_KEY = b'NOWISTHE'
LEGACY_DES_IV = b'WINTEROF'
MAX_DB_FILE = 128 * 1024 * 1024
MAX_INNER_BYTES = 128 * 1024 * 1024


def local_name(tag):
    return tag.rsplit('}', 1)[-1]


def first_element(root, name):
    return next((elem for elem in root.iter() if local_name(elem.tag) == name), None)


def first_value(root, name):
    element = first_element(root, name)
    return element.text if element is not None else None


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def decode_outer_dbn(data):
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

    banner = BANNER.match(data)
    if banner is None or banner.end() != 64:
        raise ValueError('Unrecognized DBN format: expected 64-byte Motorola banner')
    ciphertext = data[64:]
    if not ciphertext or len(ciphertext) % 8:
        raise ValueError('Invalid DBN ciphertext length (expected 8-byte alignment)')

    # 3DES with K1=K2=K3 is mathematically identical to single DES.
    # The key/IV were recovered from legacy Motorola CPS DLL static constants.
    decryptor = Cipher(TripleDES(LEGACY_DES_KEY * 3), modes.CBC(LEGACY_DES_IV)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad = padded[-1]
    if pad < 1 or pad > 8 or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError('Invalid DES PKCS#7 padding')
    plain = padded[:-pad]

    if len(plain) < 24:
        raise ValueError('Truncated DBN plaintext')
    metadata_length = struct.unpack_from('<I', plain, 16)[0]
    metadata_end = 20 + metadata_length
    if not 10 <= metadata_length <= 8192 or metadata_end >= len(plain):
        raise ValueError('Invalid DBN JSON header length')
    metadata = json.loads(plain[20:metadata_end].decode('utf-8'))
    if not isinstance(metadata, dict) or 'dataModelVersion' not in metadata:
        raise ValueError('Unrecognized DBN JSON metadata')

    xml = plain[metadata_end:]
    if len(xml) > MAX_DB_FILE:
        raise ValueError('Outer XML exceeds size limit')
    root = ET.fromstring(xml)
    if local_name(root.tag) != 'MatrixConfiguration':
        raise ValueError('Expected MatrixConfiguration XML in DBN')
    return metadata, xml, root


def extract_dbnode(outer_root):
    element = first_element(outer_root, 'DBNodeCmpBytes')
    if element is None or not element.text or not element.text.strip():
        raise ValueError('Missing or empty DBNodeCmpBytes; no nested payload to extract')
    base64_text = ''.join(element.text.split())
    if len(base64_text) > MAX_DB_FILE * 2:
        raise ValueError('DBNode Base64 field exceeds size limit')
    compressed = base64.b64decode(base64_text, validate=True)

    # This specific binary payload is raw DEFLATE (no zlib/gzip header).
    # Enforce an output bound to protect against accidental decompression bombs.
    inflater = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
    decoded = inflater.decompress(compressed, MAX_INNER_BYTES + 1)
    if len(decoded) > MAX_INNER_BYTES:
        raise ValueError('Decompressed DBNode exceeds 128 MiB safety limit')
    decoded += inflater.flush()
    if len(decoded) > MAX_INNER_BYTES:
        raise ValueError('Decompressed DBNode exceeds 128 MiB safety limit')
    if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
        raise ValueError('Incomplete raw DEFLATE data or trailing unrecognized data')

    dbnode_root = ET.fromstring(decoded)
    if local_name(dbnode_root.tag) != 'DBNode':
        raise ValueError('Expected DBNode XML after DEFLATE decompression')
    return compressed, decoded, dbnode_root


def make_pretty_xml(root):
    # Only use on parsed XML destined for display. Exact XML is saved separately.
    ET.indent(root, space='  ')
    pretty = ET.tostring(root, encoding='utf-8', xml_declaration=True)
    # Check the formatted XML is well-formed and still has all the elements.
    reparsed = ET.fromstring(pretty)
    if sum(1 for _ in reparsed.iter()) != sum(1 for _ in root.iter()):
        raise ValueError('XML formatting changed the element count')
    return pretty


def write_output(path, contents, overwrite):
    if not overwrite:
        with path.open('xb') as handle:
            handle.write(contents)
        return
    # When explicitly replacing an output, use an atomic rename.
    fd, temp_path = tempfile.mkstemp(prefix='.motorola-dbn-', suffix='.tmp', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('source', type=Path, help='Radio Management .dbn source archive')
    parser.add_argument('--pretty', action='store_true', help='Also generate human-readable indented copies of both XML files')
    parser.add_argument('--inspect', action='store_true', help='Decode and verify, but do not write any output files')
    parser.add_argument('--overwrite', action='store_true', help='Explicitly allow replacing XML outputs; never changes DBN source')
    parser.add_argument('--output-dir', type=Path, help='Directory for outputs; defaults to source directory (must exist)')
    args = parser.parse_args()

    source = args.source
    if not source.is_file() or source.suffix.lower() != '.dbn':
        raise ValueError('Source must be an existing .dbn file')
    if source.stat().st_size > MAX_DB_FILE:
        raise ValueError('DBN file exceeds 128 MiB safety limit')
    raw = source.read_bytes()
    metadata, outer_xml, outer_root = decode_outer_dbn(raw)
    compressed, dbnode_xml, dbnode_root = extract_dbnode(outer_root)

    print('SOURCE:', source)
    print('SOURCE_SHA256:', sha256_hex(raw))
    print('DATA_MODEL:', metadata.get('dataModelVersion', {}).get('Version', '?'))
    print('RADIO_SERIAL:', first_value(outer_root, 'Original_RadioSN') or '(not found)')
    print('CONFIG_NAME:', first_value(outer_root, 'Name') or '(not found)')
    print('OUTER_XML_BYTES:', len(outer_xml))
    print('OUTER_XML_SHA256:', sha256_hex(outer_xml))
    print('DBNODE_COMPRESSED_BYTES:', len(compressed))
    print('DBNODE_XML_BYTES:', len(dbnode_xml))
    print('DBNODE_XML_SHA256:', sha256_hex(dbnode_xml))
    print('DBNODE_XML_ELEMENTS:', sum(1 for _ in dbnode_root.iter()))
    print('VALIDATION: DES padding, Base64, raw DEFLATE stream, and both XML roots: PASS')
    if args.inspect:
        print('INSPECT_ONLY: no files written')
        return

    folder = args.output_dir if args.output_dir is not None else source.parent
    if not folder.is_dir():
        raise ValueError('Output directory does not exist: ' + str(folder))
    stem = source.stem
    outputs = {
        folder / (stem + '.decoded.xml'): outer_xml,
        folder / (stem + '.DBNode.decompressed.xml'): dbnode_xml,
    }
    if args.pretty:
        outputs[folder / (stem + '.pretty.xml')] = make_pretty_xml(outer_root)
        outputs[folder / (stem + '.DBNode.pretty.xml')] = make_pretty_xml(dbnode_root)

    for target in outputs:
        if target.resolve() == source.resolve():
            raise ValueError('Refusing to overwrite original DBN source: ' + str(source))
        if target.exists() and not args.overwrite:
            raise FileExistsError('Output already exists (use --overwrite): ' + str(target))
    for target, contents in outputs.items():
        write_output(target, contents, args.overwrite)
        print('SAVED:', target, '(' + str(len(contents)) + ' bytes)')
    print('DONE. Treat the output XML as sensitive radio configuration data.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, IndexError, ImportError, struct.error,
            binascii.Error, zlib.error, json.JSONDecodeError, ET.ParseError) as exc:
        sys.exit('ERROR: ' + str(exc))
