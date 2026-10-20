# Dataset: CIC-IDS2017 (raw PCAPs)

## Source

- Dataset page (read for the attack schedule): <https://www.unb.ca/cic/datasets/ids-2017.html>
- Download location named on that page: <http://cicresearch.ca/CICDataset/CIC-IDS-2017/>
- The page states a capture from 9 a.m. Monday 2017-07-03 to 5 p.m. Friday 2017-07-07, and daily sizes of
  roughly 11 GB (Mon), 11 GB (Tue), 13 GB (Wed), 7.8 GB (Thu), 8.3 GB (Fri).
- The page does **not** list raw PCAP file names, per-file sizes or checksums, and it prints times with **no
  timezone**. The files table below is therefore generated from the files actually processed on the build machine.

Raw PCAPs are expected at `D:\datasets\cicids2017\` (outside the repository). They are never committed
(`*.pcap`, `flows*.csv.gz`, `models/` are git-ignored). The third-party labelled CSVs are not used.

## Attack schedule (machine-readable copy: `ml/schedules/cicids2017.json`)

Times are the local lab times printed on the page. Monday has no attacks.

| Date (local) | Class | Local time | Attackers | Victims |
| --- | --- | --- | --- | --- |
| 2017-07-04 | FTP-Patator | 09:20-10:20 | 205.174.165.73 | 205.174.165.68, 192.168.10.50 |
| 2017-07-04 | SSH-Patator | 14:00-15:00 | 205.174.165.73 | 205.174.165.68, 192.168.10.50 |
| 2017-07-05 | DoS-slowloris | 09:47-10:10 | 205.174.165.73 | 205.174.165.68, 192.168.10.50 |
| 2017-07-05 | DoS-Slowhttptest | 10:14-10:35 | 205.174.165.73 | 205.174.165.68, 192.168.10.50 |
| 2017-07-05 | DoS-Hulk | 10:43-11:00 | 205.174.165.73 | 205.174.165.68, 192.168.10.50 |
| 2017-07-05 | DoS-GoldenEye | 11:10-11:23 | 205.174.165.73 | 205.174.165.68, 192.168.10.50 |
| 2017-07-05 | Heartbleed | 15:12-15:32 | 205.174.165.73 | 205.174.165.66, 192.168.10.51 |
| 2017-07-06 | WebAttack-BruteForce | 09:20-10:00 | 205.174.165.73 | 205.174.165.68, 192.168.10.50 |
| 2017-07-06 | WebAttack-XSS | 10:15-10:35 | 205.174.165.73 | 205.174.165.68, 192.168.10.50 |
| 2017-07-06 | WebAttack-SQLi | 10:40-10:42 | 205.174.165.73 | 205.174.165.68, 192.168.10.50 |
| 2017-07-06 | Infiltration | 14:19-14:21 | 205.174.165.73 | 192.168.10.8 |
| 2017-07-06 | Infiltration | 14:33-14:35 | 205.174.165.73 | 192.168.10.8 |
| 2017-07-06 | Infiltration | 14:53-15:00 | 205.174.165.73 | 192.168.10.25 |
| 2017-07-06 | Infiltration | 15:04-15:45 | 205.174.165.73 | 192.168.10.8 |
| 2017-07-06 | Infiltration | 15:04-15:45 | 192.168.10.8 | 192.168.10.0/24 |
| 2017-07-07 | Botnet | 10:02-11:02 | 205.174.165.73 | 192.168.10.15, 192.168.10.9, 192.168.10.14, 192.168.10.5, 192.168.10.8 |
| 2017-07-07 | PortScan | 13:55-14:24 | 205.174.165.73 | 205.174.165.68, 192.168.10.50 |
| 2017-07-07 | PortScan | 14:33-14:34 | 205.174.165.73 | 205.174.165.68, 192.168.10.50 |
| 2017-07-07 | PortScan | 14:35-14:36 | 205.174.165.73 | 205.174.165.68, 192.168.10.50 |
| 2017-07-07 | PortScan | 14:51-15:29 | 205.174.165.73 | 205.174.165.68, 192.168.10.50 |
| 2017-07-07 | DDoS | 15:56-16:16 | 205.174.165.69, 205.174.165.70, 205.174.165.71 | 205.174.165.68, 192.168.10.50 |

Transcription notes:

- Page entries given as single minutes (Port Scan 14:33 and 14:35, "14:19 and 14:20-14:21") are encoded as the
  one-minute window starting at that minute (or 14:19-14:21). The Thursday "Dropbox download (first entry)" has
  no time and is not encoded.
- Infiltration step 2 (Portscan + Nmap from the compromised Vista host to "all other clients") is encoded as
  192.168.10.8 -> 192.168.10.0/24 during 15:04-15:45.
- Friday Port Scan sub-windows are encoded exactly as listed (firewall rules on and off).

## Assumptions (pick-the-safest-reading; verify on first run)

1. **Timezone.** Local lab time is taken as Atlantic Daylight Time, UTC-3 (Fredericton, July), and converted to
   the epoch times PCAP packets carry. If the assumption is wrong a window labels zero flows;
   `scripts/build_flows.py` prints a `[WARN] ... labelled 0 flows` line for any schedule window that lies inside a
   processed capture's time span but labelled nothing. Re-run with `--utc-offset-hours N` to correct it.
2. **NAT.** The page lists NAT mappings, and the PCAPs are captured inside the victim network, so external
   attackers (205.174.165.x) are expected to appear as the firewall address `172.16.0.1`. Both forms are accepted
   as attacker aliases. Consequence: benign traffic from `172.16.0.1` to a victim inside an attack window is
   labelled as attack (label noise of unknown size).
3. **Labels are time + address based.** A flow is attack if its start time lies in a window and its two endpoints
   are an attacker/victim pair (either direction). Everything else is BENIGN, including attacker traffic outside
   its window and attack traffic to hosts not listed. The labels are only as accurate as the published schedule.

## Processing

- `scripts/build_flows.py PCAP... --out flows.csv.gz` streams each PCAP with scapy `PcapReader` (never loads a
  capture into memory), runs `ml/flows.py` (see `ML_FEATURES.md`) and writes one labelled row per flow plus
  `flows.csv.gz.meta.json` (size, SHA-256, packet/flow/label counts, per-file seconds). Files that do not exist are
  recorded as `MISSING`, not invented.
- Splits, training, the held-out replay and the gate are described in `ML_REPORT.md` (generated).

Shell globs are expanded by your shell (cmd.exe does not expand them; list the files explicitly there).

```bash
python scripts/build_flows.py D:/datasets/cicids2017/*.pcap --out flows.csv.gz
export SENTINELX_MODEL_KEY=<at least 16 random bytes, never committed>   # PowerShell: $env:SENTINELX_MODEL_KEY=...
python main.py train --flows flows.csv.gz --out models
python main.py eval --pcap D:/datasets/cicids2017/*.pcap --labels models/test_labels.json --ml-model models --out eval_output
python scripts/gen_ml_report.py --train models/train_report.json --eval eval_output/ml_eval.json --meta flows.csv.gz.meta.json
```

## Files used

Generated by `scripts/gen_ml_report.py` from `flows.csv.gz.meta.json`; do not edit between the markers.
The file names in the last build attempt (`Monday-WorkingHours.pcap` ... `Friday-WorkingHours.pcap`) are the names these
captures are commonly distributed under; the dataset page does not list them, so they are unverified.

<!-- DATASET_FILES_BEGIN -->
| File | Status | Size (bytes) | SHA-256 | Packets | Flows |
| --- | --- | --- | --- | --- | --- |
| `Monday-WorkingHours.pcap` | MISSING | n/a | n/a | n/a | n/a |
| `Tuesday-WorkingHours.pcap` | MISSING | n/a | n/a | n/a | n/a |
| `Wednesday-workingHours.pcap` | MISSING | n/a | n/a | n/a | n/a |
| `Thursday-WorkingHours.pcap` | MISSING | n/a | n/a | n/a | n/a |
| `Friday-WorkingHours.pcap` | MISSING | n/a | n/a | n/a | n/a |

<!-- DATASET_FILES_END -->
