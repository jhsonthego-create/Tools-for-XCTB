# XCTB Public Cross-Format Converters

Independent, experimental, command-line conversion tools for Motorola CPS2 `.xctb` archives.

**This is a public source-code distribution. It contains no personal radio codeplugs, CPS donor archives, encryption keys from radios, customer contacts, or site-specific profiles.** The small Radio Foundry example schema ZIP contains column headings only, with no data rows. Static protocol constants in the decoders are not user-specific radio encryption keys.

## Supported outputs

| Program | Output | Details | Status |
| --- | --- | --- | --- |
| `xctb_to_foundry_csv.py` | Radio Foundry DM32UV six-file CSV ZIP | Channel frequencies/modes, tone, TX contact, RX groups, zones | CSV/ZIP structural tests passed; application import still needs a test for each source |
| `xctb_to_cs_rdb.py` | CS711 RDB | TPL/CTCSS, DPL/DCS, DMR contact index, scan/roam indices, zones split at 16 | Known binary layout and comparison with a prior CPS-tested conversion passed |
| `xctb_to_cs_rdb.py` | CS811 RDB | Above plus CPS-observed extended zones (blank-name 80-byte continuation pages) | Known binary layout and comparison with a prior CPS-tested conversion passed |
| `xctb_to_hytera_rcdx.py` | PD782-format Hytera RCDX | Channels, contacts, scan, roam, all IP Multi-site Connect eligible members, auto-roam on roaming personalities, RX group, zones, Motorola Quick Call II two-tone contacts | Encrypted round-trip and independent table readback passed; new output requires CPS testing |

**Other format from our research:** Motorola **CTB v1** (CPS1). A genuine, CPS1-importable XCTB → CTB v1 converter has **NOT** been completed. A research envelope is not an importable `.ctb`. This package deliberately does not claim otherwise. The included `motorola_decoder.py` reads CPS2 XCTB and CTB2; CTB2 is different from CTB v1.

## Requirements

- Python 3.9 or newer
- `cryptography`
- `lxml`

Install dependencies in your preferred virtual environment:

```sh
python -m pip install -r requirements.txt
```

On Windows, use `py -3` in place of `python` if necessary.

## 1. XCTB → Radio Foundry DM32UV

```sh
python xctb_to_foundry_csv.py SOURCE.xctb \
  --schema radiofoundry_blank_schema.zip \
  --output foundry_channels.zip
```

The `radiofoundry_blank_schema.zip` is included and has exactly the six original CSV names, **with header rows only**. It is a schema, not a sample codeplug. The exporter emits bandwidth values as `12.5` or `25`, never `25.0`. If the target Radio Foundry application uses a newer CSV schema, supply your own empty header-only ZIP with the same six filenames.

Radio Foundry's six CSV tables do not represent every Motorola feature. In particular, the source scan/roam list configurations and Quick Call II two-tone systems are **not preserved as native destination features** by this exporter. Verify all options in the application before programming a radio.

## 2. XCTB → Connect Systems RDB

**A genuine CPS-exported donor RDB from the specific destination model is mandatory.** This contains the proprietary model-specific data and radio identity that the decoder cannot reconstruct from a Motorola file. Source XCTB, donor RDB, and output RDB should all be separate files.

CS711:

```sh
python xctb_to_cs_rdb.py SOURCE.xctb \
  --donor YOUR_GENUINE_CS711.rdb --model CS711 \
  --output converted_CS711.rdb
```

CS811 mobile:

```sh
python xctb_to_cs_rdb.py SOURCE.xctb \
  --donor YOUR_GENUINE_CS811.rdb --model CS811 \
  --output converted_CS811.rdb
```

**Key field fixes included:** CTCSS/TPL vs DPL squelch type; all indexed DMR contacts and their TX refs; scan list member table and the real CPS-visible scan inventory beginning at `0x33500`; separate roaming inventory and member table; auto scan; 16-channel CS711 zone banks; and CS811 80-byte extended-zone continuation records.

**Known omissions and caveats:** The source's Motorola Quick Call II two-tone definitions are not migrated to Connect Systems RDB. The donor's preexisting two-tone definitions and unrelated proprietary settings remain. Only one observed RX group table is supported; more than one RX group causes an error. Password-field positions that were identified are cleared, but unknown donor privacy settings/keys may remain. Inspect all key slots, power-on behavior, frequency bands and TX permissions after opening in CPS.

## 3. XCTB → Hytera PD782 RCDX

**A genuine model-compatible PD782 RCDX donor is mandatory.** This script targets the observed PD782 data layout, not every Hytera model.

```sh
python xctb_to_hytera_rcdx.py SOURCE.xctb \
  --donor YOUR_GENUINE_PD782.rcdx \
  --output converted_PD782.rcdx
```

The decoder/encoder performs a complete encrypted-container round-trip. It writes the source's channels, TX contacts, RX group, scan/roaming lists, zone membership, and Quick Call II two-tone transmit contacts. All channels used as roaming-list members receive the IP Multi-site Connect eligibility flag; personalities attached to a roaming list receive Auto Roam Start.

**Caveats:** Quick Call II contact aliases are deterministic placeholders (`QCII-001`, etc.) because the observed Motorola records did not contain individual aliases. The PD782 donor's tone-system timing values and other undocumented fields are retained. Motorola enhanced-privacy key material is **not** migrated. The donor's privacy/key slots may remain and MUST be inspected and cleared/updated as needed before sharing or programming a generated radio codeplug. Actual CPS acceptability and radio behavior must be tested.

## File list

- `xctb_to_foundry_csv.py` — public Radio Foundry exporter
- `xctb_to_cs_rdb.py` — public CS711/CS811 experimental RDB builder
- `xctb_to_hytera_rcdx.py` — public PD782 experimental RCDX builder
- `xctb_common.py` — Motorola XCTB → normalized programming extraction and CSV utilities
- `motorola_decoder.py` — Motorola CPS2 XCTB / CTB2 decoder and DBNode extractor
- `hytera_codec.py` — independently reconstructed Hytera RCDX container decoder
- `hytera_extract.py` — Hytera RCDX programming table decoder
- `radiofoundry_blank_schema.zip` — header-only six-file CSV schema
- `requirements.txt` — Python dependencies
- `LICENSE` — MIT license for original distribution code

## Safety / limits

- **Conversion is not certification.** All outputs are CPS import candidates only.
- Do not write these experimental binaries directly to hardware or operate on an authorized public-safety radio until frequency limits, emission bandwidth, duplex, channel type, scan/roam behavior, receive groups, channel TX contacts, signaling, encryption/privacy, and user permissions have been reviewed in the destination CPS.
- Source codeplugs contain information that may be sensitive. Do not publish input files, generated outputs or audit files containing those details. Only the supplied tool files are intended to be public.
- Input files are not modified; the scripts refuse to overwrite existing output files.
- The supported binary structures come from a limited set of observed CPS data models. Unknown versions are rejected or must be independently validated.
- No warranties; not affiliated with Motorola Solutions, Connect Systems, Hytera, Radio Foundry or Baofeng.
