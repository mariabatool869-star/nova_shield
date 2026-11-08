#!/usr/bin/env python3
"""Isolated synthetic CICFlowMeter parity research. Does not edit NovaShield source."""
import argparse
import csv
import hashlib
import itertools
import json
import math
import subprocess
import sys
from pathlib import Path

from scapy.all import IP, TCP, UDP, Raw, wrpcap, rdpcap

ROOT = Path('/Users/a3mlab/Documents/nov@shield')
WORK = ROOT / 'research_fixtures' / 'automated_validation'
SCRIPTS = ROOT / 'scripts'
sys.path.insert(0, str(SCRIPTS))
from novashield_flow_assembler import FlowAssembler
from novashield_feature_exporter import export_partial_features

HOST = 'a3mlabe@192.168.64.2'
KEY = Path.home() / '.ssh' / 'novashield_testing_key'
REMOTE = 'CICFlowMeter'
SSH = ['ssh', '-i', str(KEY), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', HOST]
SCP = ['scp', '-i', str(KEY), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8']
ALIASES = dict(zip(
    'Destination Port|Avg Fwd Segment Size|Avg Bwd Segment Size|min_seg_size_forward|Fwd Header Length.1|CWE Flag Count|Init_Win_bytes_forward|Init_Win_bytes_backward|act_data_pkt_fwd|Min Packet Length|Max Packet Length|Fwd Avg Bytes/Bulk|Fwd Avg Packets/Bulk|Fwd Avg Bulk Rate|Bwd Avg Bytes/Bulk|Bwd Avg Packets/Bulk|Bwd Avg Bulk Rate|Total Fwd Packets|Total Backward Packets|Total Length of Fwd Packets|Total Length of Bwd Packets'.split('|'),
    'Dst Port|Fwd Segment Size Avg|Bwd Segment Size Avg|Fwd Seg Size Min|Fwd Header Length|CWR Flag Count|FWD Init Win Bytes|Bwd Init Win Bytes|Fwd Act Data Pkts|Packet Length Min|Packet Length Max|Fwd Bytes/Bulk Avg|Fwd Packet/Bulk Avg|Fwd Bulk Rate Avg|Bwd Bytes/Bulk Avg|Bwd Packet/Bulk Avg|Bwd Bulk Rate Avg|Total Fwd Packet|Total Bwd packets|Total Length of Fwd Packet|Total Length of Bwd Packet'.split('|')
))


def run(args):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=90)


def tcp(a, b, sport, dport, t, flag, forward=True, payload=b'', window=8192):
    p = IP(src=a if forward else b, dst=b if forward else a) / TCP(
        sport=sport if forward else dport, dport=dport if forward else sport,
        flags=flag, window=window)
    if payload:
        p /= Raw(load=payload)
    p.time = 1700001000 + t
    return p


def udp(a, b, sport, dport, t, forward=True, payload=b'hello'):
    p = IP(src=a if forward else b, dst=b if forward else a) / UDP(
        sport=sport if forward else dport, dport=dport if forward else sport) / Raw(load=payload)
    p.time = 1700001000 + t
    return p


def fixtures():
    # Each case is intentionally small and reproducible. Outcomes are observations, not assumptions.
    cases = {}
    a, b = '10.90.0.1', '10.90.0.2'
    # Test 4: FIN close followed by same five-tuple reuse.
    cases[4] = [tcp(a,b,44004,443,t,f,d) for t,f,d in [
        (0,'S',True),(.1,'SA',False),(.2,'A',True),(.3,'PA',True),
        (.4,'FA',True),(.5,'FA',False),(2,'S',True),(2.1,'SA',False),
        (2.2,'A',True),(2.3,'PA',False),(2.4,'FA',True),(2.5,'FA',False)]]
    # Test 5: reset and separate incomplete SYN-only connection.
    cases[5] = [tcp(a,b,44005,443,t,f,d) for t,f,d in [
        (0,'S',True),(.1,'SA',False),(.2,'A',True),(.3,'R',False)]] + [tcp(a,b,44006,443,1,'S')]
    # Test 6: bidirectional UDP datagrams.
    cases[6] = [udp(a,b,54006,53,t,d,bytes([65+i])*n) for i,(t,d,n) in enumerate([
        (0,True,12),(.1,False,20),(.2,True,8),(.3,False,32)])]
    # Test 7: varying TCP payload lengths.
    cases[7] = [tcp(a,b,44007,443,t,f,d,bytes([65+i])*n) for i,(t,f,d,n) in enumerate([
        (0,'S',True,0),(.1,'SA',False,0),(.2,'A',True,0),(.3,'PA',True,15),
        (.4,'PA',False,100),(.5,'PA',True,50),(.6,'FA',True,0),(.7,'FA',False,0)])]
    # Test 8: varied TCP flags and window sizes.
    cases[8] = [tcp(a,b,44008,8443,t,f,d,b'',w) for t,f,d,w in [
        (0,'S',True,1024),(.1,'SA',False,4096),(.2,'A',True,8192),
        (.3,'PA',True,2048),(.4,'A',False,16384),(.5,'FA',True,1024),(.6,'FA',False,4096)]]
    # Test 9: gap exceeding typical active/idle threshold (not necessarily flow timeout).
    cases[9] = [tcp(a,b,44009,443,t,f,d) for t,f,d in [
        (0,'S',True),(.1,'SA',False),(.2,'A',True),(.3,'PA',True),
        (20,'PA',False),(20.1,'A',True),(20.2,'FA',True),(20.3,'FA',False)]]
    # Test 10: two TCP flows and one UDP flow, interleaved.
    cases[10] = sorted([
        tcp('10.90.1.1','10.90.1.2',44110,443,t,f,d) for t,f,d in [
            (0,'S',True),(.3,'SA',False),(.6,'A',True),(.9,'FA',True),(1.2,'FA',False)]] + [
        tcp('10.90.2.1','10.90.2.2',44210,80,t,f,d) for t,f,d in [
            (.05,'S',True),(.35,'SA',False),(.65,'A',True),(.95,'FA',True),(1.25,'FA',False)]] + [
        udp('10.90.3.1','10.90.3.2',54310,53,t,d) for t,d in [
            (.1,True),(.4,False),(.7,True),(1,False)]], key=lambda p: float(p.time))
    return cases


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare_feature_pair(nova, ref):
    matched, differences, unmapped = 0, [], []
    for name, value in nova.items():
        col = ALIASES.get(name, name)
        if col not in ref:
            unmapped.append(name)
            continue
        try:
            same = math.isclose(float(value), float(ref[col]), rel_tol=1e-9, abs_tol=1e-6)
        except (ValueError, TypeError):
            same = False
        if same:
            matched += 1
        else:
            differences.append({'feature': name, 'nova': str(value), 'cic': ref[col]})
    return {'matches': matched, 'differences': differences, 'unmapped': unmapped}


def compare(novas, refs):
    if len(novas) != len(refs):
        return {'status': 'FLOW_COUNT_MISMATCH', 'nova_flows': len(novas), 'cic_flows': len(refs)}
    if len(novas) > 7:
        return {'status': 'TOO_MANY_FLOWS_FOR_SAFE_MATCHING'}
    # Search possible pairings, never silently assume that output row order agrees.
    # Destination port is a required hard constraint; among eligible assignments,
    # choose the one with the most numerical matches and disclose ambiguous ties.
    candidates = []
    for permutation in itertools.permutations(range(len(refs))):
        pairs = []
        for i, j in enumerate(permutation):
            nport = novas[i].get('Destination Port', novas[i].get('Dst Port'))
            rport = refs[j].get('Destination Port', refs[j].get('Dst Port'))
            if nport is not None and rport is not None and float(nport) != float(rport):
                break
            pairs.append(compare_feature_pair(novas[i], refs[j]))
        else:
            candidates.append((sum(p['matches'] for p in pairs), permutation, pairs))
    if not candidates:
        return {'status': 'NO_PORT_CONSISTENT_PAIRING', 'nova_flows': len(novas), 'cic_flows': len(refs)}
    candidates.sort(key=lambda x: x[0], reverse=True)
    best_score, permutation, pairs = candidates[0]
    tied = sum(score == best_score for score, _, _ in candidates)
    differences = [{'nova_flow': i+1, 'cic_flow': permutation[i]+1, **d}
                   for i,pair in enumerate(pairs) for d in pair['differences']]
    unmapped = [{'nova_flow': i+1, 'feature': name}
                for i,pair in enumerate(pairs) for name in pair['unmapped']]
    status = 'PASS' if not differences and not unmapped and tied == 1 and all(len(n)==78 for n in novas) else 'REVIEW'
    return {'status': status, 'nova_flows': len(novas), 'cic_flows': len(refs),
            'matches': best_score, 'differences': differences, 'unmapped': unmapped,
            'pairing': list(permutation), 'equally_scoring_pairings': tied}


def test(number, packets):
    folder = WORK / f'test_{number}'
    folder.mkdir(parents=True, exist_ok=True)
    pcap = folder / f'test_{number}.pcap'
    csvfile = folder / f'test_{number}.pcap_Flow.csv'
    # Avoid silently overwriting existing evidence.
    if pcap.exists() or csvfile.exists():
        raise RuntimeError(f'Existing test evidence at {folder}; refusing to overwrite')
    wrpcap(str(pcap), packets)
    assembler = FlowAssembler()
    for packet in rdpcap(str(pcap)):
        assembler.add_packet(packet)
    # Match CICFlowMeter's end-of-PCAP export rule:
    # retain completed flows, but omit unfinished single-packet flows.
    flows = (
        list(assembler.completed_flows)
        + [
            flow for flow in assembler.flows.values()
            if flow.forward_packets + flow.backward_packets > 1
        ]
    )
    novas = [export_partial_features(flow) for flow in flows]
    # Dedicated paths on Ubuntu, not its existing data/in or data/out files.
    remote_in = f'data/in/novashield_auto_{number}'
    remote_out = f'data/out/novashield_auto_{number}'
    run(SSH + [f'mkdir -p ~/{REMOTE}/{remote_in} ~/{REMOTE}/{remote_out}'])
    run(SCP + [str(pcap), f'{HOST}:~/{REMOTE}/{remote_in}/'])
    cmd = (f'cd ~/{REMOTE} && java '
           f'-Djava.library.path=jnetpcap/linux/jnetpcap-1.4.r1425 '
           f'-cp target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar '
           f'cic.cs.unb.ca.ifm.Cmd {remote_in}/{pcap.name} {remote_out}/')
    log = run(SSH + [cmd])
    (folder / 'cicflowmeter_log.txt').write_text(log.stdout + '\n' + log.stderr)
    run(SCP + [f'{HOST}:~/{REMOTE}/{remote_out}/{csvfile.name}', str(csvfile)])
    with csvfile.open(newline='') as f:
        refs = list(csv.DictReader(f))
    result = compare(novas, refs)
    result.update({'test': number, 'packets': len(packets),
                   'pcap_sha256': sha(pcap), 'csv_sha256': sha(csvfile)})
    (folder / 'comparison.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--test', type=int, choices=range(4,11), help='Run one test first')
    parser.add_argument('--all', action='store_true', help='Run all remaining tests')
    args = parser.parse_args()
    if not args.test and not args.all:
        parser.error('Choose --test 4 for verification, or --all for the batch')
    WORK.mkdir(parents=True, exist_ok=True)
    cases = fixtures()
    numbers = [args.test] if args.test else list(range(4,11))
    results = []
    for number in numbers:
        print(f'Running synthetic test {number}...', flush=True)
        try:
            result = test(number, cases[number])
            results.append(result)
            print(f"TEST {number}: {result['status']} | matches={result.get('matches', 0)} | "
                  f"differences={len(result.get('differences', []))} | "
                  f"Nova flows={result.get('nova_flows')} | CIC flows={result.get('cic_flows')}", flush=True)
        except Exception as exc:
            print(f'TEST {number}: ERROR: {exc}', flush=True)
            results.append({'test': number, 'status': 'ERROR', 'error': str(exc)})
            break
        if result['status'] != 'PASS':
            print('Stopping for investigation; no further fixtures will run.', flush=True)
            break
    (WORK / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
    print('Summary saved:', WORK / 'summary.json')
    return 0 if all(r['status'] == 'PASS' for r in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
