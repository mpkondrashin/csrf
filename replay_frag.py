#!/usr/bin/env python3
"""
Replay PCAP packet(s) with IP fragmentation / TCP segmentation and out-of-order delivery.
For IPS / sensor detection demos in a lab or authorized test environment.

Install:  pip3 install scapy
Run (root):
  sudo python3 replay_frag.py attack.pcap -i en0 --mode asis
  sudo python3 replay_frag.py attack.pcap -i en0 --mode frag --fragsize 8
  sudo python3 replay_frag.py attack.pcap -i en0 --mode frag-reverse --fragsize 8
  sudo python3 replay_frag.py attack.pcap -i en0 --mode frag-shuffle --fragsize 8 --seed 7
  sudo python3 replay_frag.py attack.pcap -i en0 --mode tcp-shuffle --segsize 8 --seed 7
  sudo python3 replay_frag.py attack.pcap -i en0 --mode frag-reverse --dst 10.0.0.50 --dstmac aa:bb:cc:dd:ee:ff
"""
import argparse
import random
from scapy.all import rdpcap, sendp, fragment, IP, TCP, Raw, Ether


def redirect(pkt, dst_ip, dst_mac):
    """Rewrite destination IP (and optionally MAC) and drop cached checksums."""
    p = pkt.copy()
    if dst_ip:
        p[IP].dst = dst_ip
        del p[IP].chksum
    if dst_mac and Ether in p:
        p[Ether].dst = dst_mac
    return p


def clear_df(pkt):
    """Clear Don't Fragment so the packet can be fragmented in transit."""
    p = pkt.copy()
    p[IP].flags = p[IP].flags & ~0x2  # DF bit
    del p[IP].chksum
    return p


def tcp_segments(pkt, segsize):
    """Split TCP payload into segments with correct sequence numbers."""
    data = bytes(pkt[TCP].payload)
    base_seq = pkt[TCP].seq
    segs = []
    for off in range(0, len(data), segsize):
        p = pkt.copy()
        p[TCP].remove_payload()
        p = p / Raw(load=data[off:off + segsize])
        p[TCP].seq = (base_seq + off) & 0xFFFFFFFF
        del p[IP].len, p[IP].chksum, p[TCP].chksum
        segs.append(p)
    return segs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("-i", "--iface", required=True)
    ap.add_argument("--mode", default="asis",
                    choices=["asis", "frag", "frag-reverse", "frag-shuffle", "tcp-shuffle"])
    ap.add_argument("--fragsize", type=int, default=8,
                    help="bytes of IP payload per fragment (multiple of 8)")
    ap.add_argument("--segsize", type=int, default=8, help="TCP payload bytes per segment")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--delay", type=float, default=0.05, help="seconds between packets")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--dst", default=None,
                    help="override destination IP (test host / sensor lab target)")
    ap.add_argument("--dstmac", default=None,
                    help="override destination MAC (e.g. gateway or test host)")
    ap.add_argument("--keep-df", action="store_true",
                    help="do not clear DF bit before fragmenting")
    a = ap.parse_args()

    random.seed(a.seed)
    for pkt in rdpcap(a.pcap):
        pkt = redirect(pkt, a.dst, a.dstmac)

        if a.mode == "asis":
            seq = [pkt]
        elif a.mode.startswith("frag"):
            if not a.keep_df:
                pkt = clear_df(pkt)
            seq = list(fragment(pkt, fragsize=a.fragsize))
            if a.mode == "frag-reverse":
                seq.reverse()
            elif a.mode == "frag-shuffle":
                random.shuffle(seq)
        else:  # tcp-shuffle
            seq = tcp_segments(pkt, a.segsize)
            random.shuffle(seq)

        print(f"[*] mode={a.mode} packets_on_wire={len(seq)} "
              f"dst={pkt[IP].dst} df={'set' if pkt[IP].flags & 0x2 else 'clear'}")
        for _ in range(a.repeat):
            sendp(seq, iface=a.iface, inter=a.delay, verbose=False)


if __name__ == "__main__":
    main()
