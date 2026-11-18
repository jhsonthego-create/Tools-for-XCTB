#!/usr/bin/env python3
"""Hytera CPS RCDX static decryption, reconstructed from CPS.exe code.

Decryption-only. Original files are never overwritten. The Hytera RCDX payload
is encrypted with a fixed 16-byte string key and a proprietary 4-round AES-like
configuration (standard AES-128 round functions, 4 rounds rather than 10).

Data layout: 211 bytes unencrypted header, N*16 bytes encrypted payload and
up to 15 trailing payload bytes copied without encryption by CPS's file codec.

Warning: this decodes the file container; hytera_extract.py interprets supported
programming tables. Unknown database fields remain unverified.
"""
import argparse
import collections
import hashlib
import json
import struct
from functools import lru_cache
from pathlib import Path

KEY = b'HYTERACPSENCRYPT'
HEADER_SIZE=211
ROUNDS=4
SIG='HYTERARCDB'.encode('utf-16le')

# Original, publicly standardized Rijndael S-box from the AES implementation.
SBOX = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16'
)
assert len(SBOX)==256, len(SBOX)
INV_SBOX=bytes(SBOX.index(x) for x in range(256))


def gmul(a,b):
    v=0
    for _ in range(8):
        if b&1: v^=a
        a=((a<<1)^ (0x11b if a&0x80 else 0))&0xff
        b>>=1
    return v

MULT={n: bytes(gmul(i,n) for i in range(256)) for n in (9,11,13,14)}

def key_schedule(key=KEY):
    if len(key)!=16:raise ValueError('Key must be exactly 16 bytes')
    w=[list(key[i:i+4]) for i in range(0,16,4)]
    for i in range(4,4*(ROUNDS+1)):
        t=w[-1][:]
        if i%4==0:
            t=t[1:]+t[:1]
            t=[SBOX[j] for j in t]
            t[0]^=[1,2,4,8][i//4-1]
        w.append([x^y for x,y in zip(w[-4],t)])
    return tuple(bytes(q for word in w[4*r:4*r+4] for q in word) for r in range(ROUNDS+1))

RKEYS=key_schedule()

def inverse_shift_rows(s):
    for r in range(1,4):
        a=[s[r+4*c] for c in range(4)]
        for c in range(4):s[r+4*c]=a[(c-r)%4]

@lru_cache(maxsize=None)
def decrypt_block(c):
    if len(c)!=16:raise ValueError('Block length must equal 16')
    s=[x^y for x,y in zip(c,RKEYS[-1])]
    for r in range(ROUNDS-1,-1,-1):
        inverse_shift_rows(s)
        s[:]=[INV_SBOX[x] for x in s]
        s[:]=[x^y for x,y in zip(s,RKEYS[r])]
        if r>0:
            z=s[:]
            for j in range(0,16,4):
                a,b,c,d=s[j:j+4]
                z[j]=MULT[14][a]^MULT[11][b]^MULT[13][c]^MULT[9][d]
                z[j+1]=MULT[9][a]^MULT[14][b]^MULT[11][c]^MULT[13][d]
                z[j+2]=MULT[13][a]^MULT[9][b]^MULT[14][c]^MULT[11][d]
                z[j+3]=MULT[11][a]^MULT[13][b]^MULT[9][c]^MULT[14][d]
            s=z
    return bytes(s)

def decrypt(raw):
    if not raw.startswith(SIG):raise ValueError('Missing Hytera RCDB file signature')
    if len(raw)<HEADER_SIZE: raise ValueError('RCDX file is too small')
    if struct.unpack_from('<I',raw,24)[0]!=len(raw):raise ValueError('Header file length mismatch')
    n=struct.unpack_from('<I',raw,207)[0]
    if n!=len(raw)-HEADER_SIZE:raise ValueError('Cipher length mismatch')
    if raw[183]!=1:raise ValueError('RCDX encryption flag does not equal 1')
    encrypted=raw[HEADER_SIZE:]
    enc_size=len(encrypted)//16*16
    payload=b''.join(decrypt_block(encrypted[i:i+16]) for i in range(0,enc_size,16)) + encrypted[enc_size:]
    return payload

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('inputs',type=Path,nargs='+')
    p.add_argument('--outdir',type=Path,required=True)
    args=p.parse_args()
    args.outdir.mkdir(parents=True,exist_ok=True)
    for src in args.inputs:
        raw=src.read_bytes()
        d=decrypt(raw)
        dst=args.outdir/(src.stem+'.decoded-payload.bin')
        if dst.exists():raise FileExistsError(f'Refusing to overwrite {dst}')
        dst.write_bytes(d)
        model=raw[68:100].decode('utf-16le','replace').partition('\x00')[0]
        block_hist=collections.Counter(d[i:i+16] for i in range(0,len(d)-len(d)%16,16))
        metadata={'input':src.name,'source_sha256':hashlib.sha256(raw).hexdigest(),'radio_model':model,
            'cps_version':raw[100:132].decode('utf-16le','replace').partition('\x00')[0],
            'header_bytes':HEADER_SIZE,'encryption':'4-round AES-128 ECB-compatible, fixed key',
            'full_payload_bytes':len(d),'encrypted_blocks':len(d)//16,'untransformed_suffix_bytes':len(d)%16,
            'output_sha256':hashlib.sha256(d).hexdigest(),'most_common_plaintext_block':block_hist.most_common(1)[0][0].hex(),
            'most_common_plaintext_block_count':block_hist.most_common(1)[0][1],
            'deciphered':True,'rcdb_fields_parsed':False}
        mpath=dst.with_suffix('.json')
        mpath.write_text(json.dumps(metadata,indent=2)+'\n')
        print(f'{src.name}: {len(d)} decrypted bytes, {decrypt_block.cache_info().currsize} unique blocks, repeated filler={block_hist.most_common(1)[0][0].hex()}, wrote {dst}')

if __name__=='__main__':main()
