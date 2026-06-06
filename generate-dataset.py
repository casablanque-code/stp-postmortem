#!/usr/bin/env python3
"""
stp-postmortem dataset generator
Requires: scapy (pip install scapy)

Generates 6 pcap scenarios covering common STP/RSTP failure modes.
"""

from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.utils import PcapWriter
import struct, os, random

OUT = "dataset"
os.makedirs(OUT, exist_ok=True)

# ── BPDU builders ─────────────────────────────────────────────────────────────

STP_MCAST  = "01:80:c2:00:00:00"  # IEEE STP/RSTP
PVST_MCAST = "01:00:0c:cc:cc:cd"  # Cisco PVST+

def bridge_id(priority, mac_str):
    """Pack bridge ID: 2 bytes priority + 6 bytes MAC"""
    mac = bytes.fromhex(mac_str.replace(":", ""))
    return struct.pack("!H", priority) + mac

def config_bpdu(root_priority, root_mac, root_cost, bridge_priority, bridge_mac,
                port_id, flags=0, message_age=0, max_age=5120,
                hello_time=512, fwd_delay=3840):
    """Build STP Configuration BPDU (type 0x00)"""
    body = struct.pack("!HH", 0x0000, 0x0000)  # proto=0, ver=0, type=0
    body = struct.pack("!BBB", 0, 0, 0x00)      # proto(1) ver(1) type(1)
    body += struct.pack("!B", flags)
    body += bridge_id(root_priority, root_mac)
    body += struct.pack("!I", root_cost)
    body += bridge_id(bridge_priority, bridge_mac)
    body += struct.pack("!H", port_id)
    body += struct.pack("!HHHH", message_age, max_age, hello_time, fwd_delay)
    # Prepend proto+ver+type
    bpdu = b'\x00\x00' + b'\x00' + b'\x00' + struct.pack("!B", flags)
    bpdu += bridge_id(root_priority, root_mac)
    bpdu += struct.pack("!I", root_cost)
    bpdu += bridge_id(bridge_priority, bridge_mac)
    bpdu += struct.pack("!H", port_id)
    bpdu += struct.pack("!HHHH", message_age, max_age, hello_time, fwd_delay)
    return bpdu

def rst_bpdu(root_priority, root_mac, root_cost, bridge_priority, bridge_mac,
             port_id, flags=0x3c, message_age=0, max_age=5120,
             hello_time=512, fwd_delay=3840):
    """Build RST BPDU (version 2, type 0x02) — RSTP"""
    bpdu = b'\x00\x00'          # Protocol ID = 0
    bpdu += b'\x02'             # Version = 2 (RSTP)
    bpdu += b'\x02'             # BPDU Type = RST
    bpdu += struct.pack("!B", flags)
    bpdu += bridge_id(root_priority, root_mac)
    bpdu += struct.pack("!I", root_cost)
    bpdu += bridge_id(bridge_priority, bridge_mac)
    bpdu += struct.pack("!H", port_id)
    bpdu += struct.pack("!HHHH", message_age, max_age, hello_time, fwd_delay)
    bpdu += b'\x00'             # Version1 Length = 0
    return bpdu

def tcn_bpdu():
    """Build TCN BPDU (type 0x80)"""
    return b'\x00\x00\x00\x80'

def llc_wrap(bpdu_data):
    """Wrap BPDU in 802.3 LLC header: DSAP=0x42 SSAP=0x42 Control=0x03"""
    return b'\x42\x42\x03' + bpdu_data

def stp_frame(src_mac, bpdu_data, dst_mac=STP_MCAST):
    """Build complete 802.3 Ethernet frame with LLC"""
    llc_payload = llc_wrap(bpdu_data)
    length = len(llc_payload)
    src  = bytes.fromhex(src_mac.replace(":", ""))
    dst  = bytes.fromhex(dst_mac.replace(":", ""))
    frame = dst + src + struct.pack("!H", length) + llc_payload
    # Pad to minimum 64 bytes (minus FCS)
    if len(frame) < 60:
        frame += b'\x00' * (60 - len(frame))
    return frame

def pvst_frame(src_mac, bpdu_data, vlan_id):
    """Build 802.1Q-tagged PVST+ frame"""
    llc_payload = llc_wrap(bpdu_data)
    length = len(llc_payload)
    src = bytes.fromhex(src_mac.replace(":", ""))
    dst = bytes.fromhex(PVST_MCAST.replace(":", ""))
    # 802.1Q tag: ethertype 0x8100 + TCI (PCP=0, DEI=0, VID)
    dot1q = struct.pack("!HH", 0x8100, vlan_id & 0x0FFF)
    frame = dst + src + dot1q + struct.pack("!H", length) + llc_payload
    if len(frame) < 60:
        frame += b'\x00' * (60 - len(frame))
    return frame

def write_timed_pcap(path, timed_frames):
    """Write list of (timestamp_float, raw_bytes) to pcap"""
    with PcapWriter(path, sync=True, linktype=1) as pw:
        for ts, raw in timed_frames:
            pkt = Ether(raw)
            pkt.time = ts
            pw.write(pkt)

BASE = 1700000000.0

# ── Scenario 1: Clean RSTP convergence ───────────────────────────────────────
def scenario_01():
    """Normal RSTP: root elected, ports converge to Forwarding"""
    root_mac   = "00:11:22:33:44:01"
    bridge_mac = "00:11:22:33:44:02"
    frames = []
    t = BASE

    # Root sends RST BPDUs every 2s (hello time)
    # flags: 0x3c = Forwarding(0x20) | Learning(0x10) | Designated(0x0c)
    for i in range(10):
        bpdu = rst_bpdu(
            root_priority=4096, root_mac=root_mac,
            root_cost=0,
            bridge_priority=4096, bridge_mac=root_mac,
            port_id=0x8001, flags=0x3c
        )
        frames.append((t + i * 2.0, stp_frame(root_mac, bpdu)))

    # Non-root bridge sends RST BPDUs with root cost
    for i in range(10):
        # flags: 0x1c = Forwarding(0x20)? No: Root port = 0x28 = Root(0x08)|Learning(0x10)|Forwarding(0x20)
        flags = 0x1c  # Discarding → Learning → Forwarding transition
        if i >= 2:
            flags = 0x3c  # Forwarding
        bpdu = rst_bpdu(
            root_priority=4096, root_mac=root_mac,
            root_cost=4,
            bridge_priority=8192, bridge_mac=bridge_mac,
            port_id=0x8001, flags=flags
        )
        frames.append((t + i * 2.0 + 0.1, stp_frame(bridge_mac, bpdu)))

    frames.sort(key=lambda x: x[0])
    path = f"{OUT}/01-clean-rstp"
    os.makedirs(path, exist_ok=True)
    write_timed_pcap(f"{path}/capture.pcap", frames)
    print(f"[+] 01-clean-rstp: {len(frames)} frames")

# ── Scenario 2: Root Bridge Change ───────────────────────────────────────────
def scenario_02():
    """Planned/unplanned root change: new bridge with lower priority appears"""
    old_root = "00:11:22:33:44:01"
    new_root = "00:11:22:00:00:01"  # lower MAC → wins if same priority
    bridge2  = "00:11:22:33:44:02"
    frames = []
    t = BASE

    # Phase 1: old_root is root (0-10s)
    for i in range(5):
        bpdu = rst_bpdu(4096, old_root, 0, 4096, old_root, 0x8001, flags=0x3c)
        frames.append((t + i * 2.0, stp_frame(old_root, bpdu)))
        bpdu2 = rst_bpdu(4096, old_root, 4, 8192, bridge2, 0x8001, flags=0x3c)
        frames.append((t + i * 2.0 + 0.1, stp_frame(bridge2, bpdu2)))

    # Phase 2: new_root appears at t=10s with lower priority
    t2 = t + 10.0
    for i in range(8):
        bpdu = rst_bpdu(4096, new_root, 0, 4096, new_root, 0x8001, flags=0x3c)
        frames.append((t2 + i * 2.0, stp_frame(new_root, bpdu)))
        # bridge2 now uses new_root
        bpdu2 = rst_bpdu(4096, new_root, 4, 8192, bridge2, 0x8001, flags=0x3c)
        frames.append((t2 + i * 2.0 + 0.1, stp_frame(bridge2, bpdu2)))
        # TC flag set during transition
        if i < 2:
            bpdu_tc = rst_bpdu(4096, new_root, 4, 8192, bridge2, 0x8001, flags=0x3d)  # TC bit
            frames.append((t2 + i * 2.0 + 0.2, stp_frame(bridge2, bpdu_tc)))

    frames.sort(key=lambda x: x[0])
    path = f"{OUT}/02-root-change"
    os.makedirs(path, exist_ok=True)
    write_timed_pcap(f"{path}/capture.pcap", frames)
    print(f"[+] 02-root-change: {len(frames)} frames")

# ── Scenario 3: TC Storm ──────────────────────────────────────────────────────
def scenario_03():
    """Topology Change storm: flapping access port causes continuous TC flags"""
    root_mac  = "00:11:22:33:44:01"
    sw_mac    = "00:11:22:33:44:02"
    frames = []
    t = BASE

    # Root BPDUs normal
    for i in range(30):
        bpdu = rst_bpdu(4096, root_mac, 0, 4096, root_mac, 0x8001, flags=0x3c)
        frames.append((t + i * 1.0, stp_frame(root_mac, bpdu)))

    # sw_mac sends BPDUs with TC flag constantly (access port flapping)
    for i in range(30):
        flags = 0x3d  # 0x3c | 0x01 (TC bit)
        bpdu = rst_bpdu(4096, root_mac, 4, 8192, sw_mac, 0x8001, flags=flags)
        frames.append((t + i * 1.0 + 0.05, stp_frame(sw_mac, bpdu)))
        # Also sends TCN BPDUs
        if i % 3 == 0:
            frames.append((t + i * 1.0 + 0.1, stp_frame(sw_mac, tcn_bpdu())))

    frames.sort(key=lambda x: x[0])
    path = f"{OUT}/03-tc-storm"
    os.makedirs(path, exist_ok=True)
    write_timed_pcap(f"{path}/capture.pcap", frames)
    print(f"[+] 03-tc-storm: {len(frames)} frames")

# ── Scenario 4: Root Flapping ─────────────────────────────────────────────────
def scenario_04():
    """Root bridge flapping: two bridges fighting for root"""
    mac_a = "00:11:22:33:44:01"
    mac_b = "00:11:22:33:44:02"
    frames = []
    t = BASE

    # Two bridges alternately claim to be root (misconfiguration / loop)
    for cycle in range(8):
        base_t = t + cycle * 4.0
        # A claims root for 2s
        for i in range(2):
            bpdu = rst_bpdu(4096, mac_a, 0, 4096, mac_a, 0x8001, flags=0x3d)
            frames.append((base_t + i * 1.0, stp_frame(mac_a, bpdu)))
            bpdu_b = rst_bpdu(4096, mac_a, 4, 8192, mac_b, 0x8001, flags=0x3d)
            frames.append((base_t + i * 1.0 + 0.1, stp_frame(mac_b, bpdu_b)))
        # B claims root for 2s
        for i in range(2):
            bpdu = rst_bpdu(4096, mac_b, 0, 4096, mac_b, 0x8001, flags=0x3d)
            frames.append((base_t + 2.0 + i * 1.0, stp_frame(mac_b, bpdu)))
            bpdu_a = rst_bpdu(4096, mac_b, 4, 8192, mac_a, 0x8001, flags=0x3d)
            frames.append((base_t + 2.0 + i * 1.0 + 0.1, stp_frame(mac_a, bpdu_a)))

    frames.sort(key=lambda x: x[0])
    path = f"{OUT}/04-root-flapping"
    os.makedirs(path, exist_ok=True)
    write_timed_pcap(f"{path}/capture.pcap", frames)
    print(f"[+] 04-root-flapping: {len(frames)} frames")

# ── Scenario 5: PVST+ per-VLAN ───────────────────────────────────────────────
def scenario_05():
    """Cisco Rapid-PVST+: different roots per VLAN"""
    root_v10  = "00:11:22:33:44:01"
    root_v20  = "00:11:22:33:44:02"
    bridge    = "00:11:22:33:44:03"
    frames = []
    t = BASE

    for i in range(10):
        # VLAN 10: root_v10 is root
        bpdu10 = rst_bpdu(4096, root_v10, 0, 4096, root_v10, 0x8001, flags=0x3c)
        frames.append((t + i * 2.0, pvst_frame(root_v10, bpdu10, vlan_id=10)))

        # VLAN 20: root_v20 is root
        bpdu20 = rst_bpdu(4096, root_v20, 0, 4096, root_v20, 0x8001, flags=0x3c)
        frames.append((t + i * 2.0 + 0.05, pvst_frame(root_v20, bpdu20, vlan_id=20)))

        # Non-root bridge on both VLANs
        bpdu_br10 = rst_bpdu(4096, root_v10, 4, 8192, bridge, 0x8001, flags=0x3c)
        frames.append((t + i * 2.0 + 0.1, pvst_frame(bridge, bpdu_br10, vlan_id=10)))

        bpdu_br20 = rst_bpdu(4096, root_v20, 4, 8192, bridge, 0x8001, flags=0x3c)
        frames.append((t + i * 2.0 + 0.15, pvst_frame(bridge, bpdu_br20, vlan_id=20)))

    frames.sort(key=lambda x: x[0])
    path = f"{OUT}/05-pvst-per-vlan"
    os.makedirs(path, exist_ok=True)
    write_timed_pcap(f"{path}/capture.pcap", frames)
    print(f"[+] 05-pvst-per-vlan: {len(frames)} frames")

# ── Scenario 6: Rogue Root Bridge ────────────────────────────────────────────
def scenario_06():
    """Rogue bridge with priority 0 takes over as root"""
    legit_root = "00:11:22:33:44:01"
    rogue      = "de:ad:be:ef:00:01"
    bridge2    = "00:11:22:33:44:02"
    frames = []
    t = BASE

    # Phase 1 (0-10s): legit_root is root, stable
    for i in range(5):
        bpdu = rst_bpdu(4096, legit_root, 0, 4096, legit_root, 0x8001, flags=0x3c)
        frames.append((t + i * 2.0, stp_frame(legit_root, bpdu)))
        bpdu2 = rst_bpdu(4096, legit_root, 4, 8192, bridge2, 0x8001, flags=0x3c)
        frames.append((t + i * 2.0 + 0.1, stp_frame(bridge2, bpdu2)))

    # Phase 2 (t=10s): rogue bridge with priority 0 takes over
    t2 = t + 10.0
    for i in range(8):
        # Rogue claims root with priority 0 (lowest possible)
        bpdu = rst_bpdu(0, rogue, 0, 0, rogue, 0x8001, flags=0x3d)
        frames.append((t2 + i * 2.0, stp_frame(rogue, bpdu)))
        # Other bridges accept rogue as root
        bpdu2 = rst_bpdu(0, rogue, 4, 8192, bridge2, 0x8001, flags=0x3d)
        frames.append((t2 + i * 2.0 + 0.1, stp_frame(bridge2, bpdu2)))
        bpdu3 = rst_bpdu(0, rogue, 4, 4096, legit_root, 0x8001, flags=0x3d)
        frames.append((t2 + i * 2.0 + 0.2, stp_frame(legit_root, bpdu3)))

    frames.sort(key=lambda x: x[0])
    path = f"{OUT}/06-rogue-root"
    os.makedirs(path, exist_ok=True)
    write_timed_pcap(f"{path}/capture.pcap", frames)
    print(f"[+] 06-rogue-root: {len(frames)} frames")

if __name__ == "__main__":
    scenario_01()
    scenario_02()
    scenario_03()
    scenario_04()
    scenario_05()
    scenario_06()
    print("\n[OK] All datasets generated in ./dataset/")
