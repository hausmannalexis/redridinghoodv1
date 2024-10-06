from scapy.all import RandMAC, Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp
import subprocess

def start_monitor(iface):
    """
    Puts the given interface into monitor mode.
    """
    try:
        # Bring the interface down
        subprocess.run(["sudo", "ifconfig", iface, "down"], check=True)
        # Set the interface to monitor mode
        subprocess.run(["sudo", "iwconfig", iface, "mode", "monitor"], check=True)
        # Bring the interface up
        subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)
        print(f"Interface {iface} set to monitor mode.")
    except subprocess.CalledProcessError:
        print(f"Failed to set {iface} to monitor mode. Please check the interface or permissions.")

def stop_monitor(iface):
    """
    Puts the given interface back to managed mode.
    """
    try:
        # Bring the interface down
        subprocess.run(["sudo", "ifconfig", iface, "down"], check=True)
        # Set the interface to managed mode
        subprocess.run(["sudo", "iwconfig", iface, "mode", "managed"], check=True)
        # Bring the interface up
        subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)
        print(f"Interface {iface} set back to managed mode.")
    except subprocess.CalledProcessError:
        print(f"Failed to set {iface} back to managed mode. Please check the interface or permissions.")

def main():
    # Display available network interfaces
    subprocess.run(["ifconfig"])

    # Get the interface from the user (should be in monitor mode)
    iface = input("Interface to use (in monitor mode)?: ")
    
    # Start monitor mode
    start_monitor(iface)
    
    # Generate a random MAC address
    sender_mac = RandMAC()

    # Get the SSID from the user
    ssid = input("Enter Wi-Fi Name (SSID)?: ")

    # Create the 802.11 frame for the beacon
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))

    # Stack all the layers and add a RadioTap header
    frame = RadioTap() / dot11 / beacon / essid

    print("Sending beacon frames... Press Ctrl+C to stop.")

    try:
        # Send the frame in layer 2 every 100 milliseconds forever using the specified interface
        sendp(frame, inter=0.05, iface=iface, loop=1)
    except KeyboardInterrupt:
        print("\nStopped sending beacon frames.")
    except Exception as e:
        print(f"Error while sending frames: {e}")
    finally:
        # Ensure the interface is reset to managed mode
        stop_monitor(iface)

if __name__ == "__main__":
    main()

