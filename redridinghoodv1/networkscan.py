import os
import subprocess
import sys
import urllib.request
import random
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt

networks_file_path = "redridinghoodv1/Results/networks.txt"
bssids_file_path = "redridinghoodv1/Results/bssids.txt"
mac_vendor_file_path = "redridinghoodv1/Misc/mac-vendor.txt"

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    return result.returncode

def check_interface(interface):
    if run_command(["sudo", "ifconfig", interface]) != 0:
        print(f"Error: Interface {interface} does not exist.")
        sys.exit(1)
    print(f"Interface {interface} is valid.")

def set_monitor_mode(interface):
    try:
        run_command(["sudo", "ifconfig", interface, "down"])
        run_command(["sudo", "macchanger", "-r", interface])
        run_command(["sudo", "iwconfig", interface, "mode", "monitor"])
        run_command(["sudo", "ifconfig", interface, "up"])
    except subprocess.CalledProcessError as e:
        print(f"Error setting monitor mode: {e}")
        sys.exit(1)

def monitor_off(iface):
    try:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"], check=True)
        subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "managed"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"], check=True)
        print(f"[INFO] {iface} set to managed mode.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to set {iface} to managed mode: {e}")

def set_channel(interface, channel):
    try:
        run_command(["sudo", "iwconfig", interface, "channel", str(channel)])
    except subprocess.CalledProcessError as e:
        print(f"Error setting channel: {e}")

def resolve_vendor(bssid):
    mac_prefixes = {}
    try:
        with open(mac_vendor_file_path) as f:
            for line in f:
                if line.strip():
                    parts = line.split("\t")
                    if len(parts) == 2:
                        mac_prefix = parts[0].strip().upper()[:6]
                        vendor = parts[1].strip()
                        mac_prefixes[mac_prefix] = vendor
                    else:
                        print("Invalid line format in mac-vendor.txt:", line)
    except Exception as e:
        print("Error reading mac-vendor.txt file:", e)
    bssid_clean = bssid.replace(':', '').upper()
    prefix = bssid_clean[:6]
    vendor = mac_prefixes.get(prefix, "Unknown")
    return vendor

def process_packet(packet, discovered_networks):
    try:
        if packet.haslayer(Dot11Beacon):
            bssid = packet.addr3
            ssid = packet.info.decode()
            
            # Extract channel information from the Dot11 layer
            channel = None
            if packet.haslayer(Dot11Elt):
                elt = packet[Dot11Elt]
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 3:  # Element ID 3 refers to channel information
                        channel = int(ord(elt.info))
                        break
                    elt = elt.payload
            
            if bssid not in [network['BSSID'] for network in discovered_networks]:
                vendor = resolve_vendor(bssid)
                discovered_networks.append({"BSSID": bssid, "SSID": ssid, "Vendor": vendor, "Channel": channel})
                print_networks(discovered_networks)
                save_to_file(discovered_networks)
    except Exception as e:
        print(f"Error processing packet: {e}")

def scan_channel(interface, discovered_networks):
    try:
        channel = random.randint(1, 13)
        set_channel(interface, channel)
        sniff(iface=interface, prn=lambda pkt: process_packet(pkt, discovered_networks), store=0, timeout=0.5, count=1000)
    except Exception as e:
        print(f"Error during scanning: {e}")

def print_networks(discovered_networks):
    os.system('clear')
    print("{:<6} {:<20} {:<40} {:<40} {:<8}".format("Count", "BSSID", "Vendor", "SSID", "Channel"))
    print("-" * 116)
    if discovered_networks:
        for i, network in enumerate(discovered_networks, start=1):
            bssid = network.get('BSSID', 'Unknown')
            ssid = network.get('SSID', 'Unknown')
            vendor = network.get('Vendor', 'Unknown')
            channel = network.get('Channel', 'Unknown')
            print("{:<6} {:<20} {:<40} {:<40} {:<8}".format(i, bssid, vendor, ssid, channel))
    else:
        print("No networks discovered yet.")
    print("-" * 116)

def save_to_file(discovered_networks):
    try:
        with open(networks_file_path, 'w') as f:
            for network in discovered_networks:
                f.write("{:<20} {:<40} {:<40} {:<8}\n".format(network.get('BSSID', 'Unknown'), network.get('Vendor', 'Unknown'), network.get('SSID', 'Unknown'), network.get('Channel', 'Unknown')))

        with open(bssids_file_path, 'w') as f:
            for network in discovered_networks:
                f.write("{}\n".format(network.get('BSSID', 'Unknown')))
    except OSError as e:
        print(f"Error saving to file: {e}")

def stop_network_manager():
    """ Stops network manager to prevent interference. """
    try:
        subprocess.run(["sudo", "systemctl", "stop", "NetworkManager"], check=True)
        print("[INFO] NetworkManager stopped to avoid interference.")
    except subprocess.CalledProcessError:
        print("[ERROR] Failed to stop NetworkManager.")

def start_network_manager():
    """ Restarts network manager. """
    try:
        subprocess.run(["sudo", "systemctl", "start", "NetworkManager"], check=True)
        print("[INFO] NetworkManager restarted.")
    except subprocess.CalledProcessError:
        print("[ERROR] Failed to restart NetworkManager.")

def networkscanner():
    run_command(["sudo", "ifconfig"])
    interface = input("Interface? ")  # You can change this or make it a command-line argument
    stop_network_manager()
    run_command(["clear"])
    check_interface(interface)
    set_monitor_mode(interface)
    discovered_networks = []
    try:
        while True:
            scan_channel(interface, discovered_networks)
            save_to_file(discovered_networks)
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
        save_to_file(discovered_networks)
        monitor_off(iface)
        start_network_manager()
        pass
    
if __name__ == "__main__":
    networkscanner()
