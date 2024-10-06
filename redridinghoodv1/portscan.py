import socket  # for connecting
import requests  # for API calls
import json  # for parsing JSON responses
import re
from colorama import init, Fore
from threading import Thread, Lock
from queue import Queue
import os
import time

# Initialize colorama for colored output in terminal
init()
GREEN = Fore.GREEN
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX
RED = Fore.RED
CYAN = Fore.CYAN

# Default thread count, can be adjusted dynamically
DEFAULT_THREADS = 50
N_THREADS = DEFAULT_THREADS
q = Queue()  # Queue for thread-based port scanning
print_lock = Lock()  # Lock for thread-safe printing
log_file = "Results/scan_results.log"  # Log file path

# Dictionary of common ports and their services
common_ports = {
    7: 'ECHO',  
    19: 'Chargen',
    20: 'FTP-Data',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    42: 'WINS Replication',
    43: 'WHOIS',
    49: 'TACAS',
    53: 'DNS',
    67: 'DHCP',
    68: 'DHCP',
    69: 'TFTP',
    70: 'Gopher',
    79: 'Finger',
    80: 'HTPP',
    88: 'Kerberos',
    102: 'Microsoft Exchange ISO-TSAP',
    110: 'POP3',
    113: 'Ident',
    119: 'NNTP',
    123: 'NTP',
    135: 'Microsoft RPC EPMAP',
    137: 'NetBIOS-ns',
    138: 'NetBIOS-dgm',
    139: 'NetBIOS-ssn',
    143: 'IMAP',
    161: 'SNMP-agents',
    162: 'SNP-trap',
    177: 'XDMCP',
    179: 'BGP',
    194: 'IRC',
    201: "AppleTalk",
    264: "BGMP",
    318: "TSP",
    381: "HP Openview",
    383: "HP Openview",
    389: "LDAP",
    411: "Direct Connect Hub",
    412: "Direct Connect Client-to-CLient",
    427: "SLP",
    443: "HTTPS",
    445: "Microsoft DS SMB",
    464: "Kerberos",
    465: "SMTP over SSL",
    497: "Dantz Retrospect",
    500: "IPSec",
    512: "Rexec",
    513: "Rlogin",
    514: "Syslog",
    515: "LPD/LPR",
    520: "Routing Information Protocol",
    521: "RIPng (IPv6)",
    540: "UUCP",
    546: "DHCPv6",
    547: "DHCPv6",
    548: "AFP",
    554: "RTSP",
    560: "monitor",
    563: "NNTP over SSL",
    587: "SMTP",
    591: "FileMaker",
    593: "Microsoft DCOM",
    596: "SMSD",
    631: "IPP",
    636: "LDAP over SSL",
    639: "MDSP",
    646: "LDP",
    691: "Microsoft Exchange",
    860: "ISCSI",
    873: "rsync",
    902: "VMWAre Server",
    989: "FTPS",
    990: "FTPS",
    993: "IMAP over SSL",
    995: "POP3 over SSL",
    1025: "Microsoft RPC",
    1026: "Windows Messenger",
    1027: "Windows Messenger",
    1028: "Windows Messenger",
    1029: "Windows Messenger",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1214: "KAZAA",
    1241: "Nessus",
    1311: "Dell OpenManage",
    1337: "WASTE",
    1589: "Cisco VQP",
    1701: "L2TP VPN",
    1720: "H.323",
    1723: "Microsoft PPTP",
    1725: "Steam",
    1741: "CiscoWorks SNMS 2000",
    1755: "MMS",
    1812: "RADIUS",
    1813: "RADIUS",
    1863: "MSN Messenger or Xbox Live 360",
    1900: "UPnP",
    1985: "Cisco HSRP",
    2000: "Cisco SCCP",
    2002: "Cisco ACS",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel",
    2100: "amiganetfs",
    2222: "DirectAdmin",
    2302: "Gaming",
    2483: "Oracle",
    2484: "Oracle",
    2745: "Bagle.C-Bagle.H",
    2967: "Symantec AV",
    3050: "Interbase DB",
    3074: "XBOX Live",
    3127: "MyDoom", 
    3128: "HTTP Proxy",
    3222: "GLBP",
    3260: "iSCSI Target",
    3306: "MySQL",
    3389: "RDP",
    3689: "DAAP",
    3690: "SVN",
    3724: "World of Warcraft",
    3784: "Ventrilo VoIP",
    3785: "Ventrilo VoIP",
    4333: "mSQL",
    4444: "Blaster",
    4500: "IPSec NAT Traversal",
    4664: "Google Desktop",
    4672: "eMule",
    4899: "Radmin",
    5000: "UPnP",
    5001: "iperf",
    5004: "RTP",
    5005: "RTSP",
    5050: "Yahoo Messenger",
    5060: "SIP",
    5061: "SIP-TLS",
    5190: "ICQ, AIM or Apple iChat",
    5222: "XMPP",
    5223: "XMPP",
    5353: "MDNS",
    5432: "PostgreSQL",
    5554: "Sasser",
    5631: "pcAnywhere",
    5632: "pcAnywhere",
    5800: "VNC over HTTP",
    6000: "X11",
    6001: "X11",
    6112: "Diablo",
    6129: "DameWare",
    6257: "WinMX",
    6346: "Gnutella2",
    6347: "Gnutella2",
    6379: "Redis",
    6500: "GameSpy",
    6566: "Sane",
    6588: "HTTP Proxy"
}

# Global host variable
host = None

def banner_grab(s):
    """ Try to grab the banner of a service running on an open port. """
    try:
        s.settimeout(2)
        banner = s.recv(1024).decode().strip()
        return banner
    except Exception as e:
        log(f"Banner grab error: {e}")
        return None

def query_nvd(service, version=None):
    """ Query the NVD API (version 2.0) for known vulnerabilities for a service and optional version. """
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'keywordSearch': service,
        'resultsPerPage': 5,
        'startIndex': 0,
    }
    if version:
        params['keywordSearch'] += f" {version}"

    try:
        response = requests.get(api_url, params=params, timeout=10)
        if response.status_code == 200 and response.text.strip():
            data = response.json()
            cves = data.get('vulnerabilities', [])
            return cves
        else:
            log(f"Invalid NVD API response: {response.status_code}, {response.text[:200]}")
            return None
    except Exception as e:
        log(f"Error querying NVD API: {e}")
        return None

def extract_version(banner):
    """ Extract a version number from a banner, if possible. """
    match = re.search(r'\b\d+(\.\d+)+\b', banner)
    return match.group(0) if match else None

def display_vulnerabilities(cves):
    """ Display the list of vulnerabilities returned by the NVD API (v2.0). """
    if cves:
        log("Vulnerabilities found:")
        for item in cves:
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('id', 'Unknown')
            description = "No description available"
            for desc in cve_data.get('descriptions', []):
                if desc.get('lang') == 'en':
                    description = desc.get('value', description)
                    break
            log(f"{cve_id}: {description}")
    else:
        log("No known vulnerabilities found for this service.")

def port_scan(port):
    """ Scan a port on the global variable `host`. """
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((host, port))

        with print_lock:
            service = common_ports.get(port, 'Unknown Service')
            log(f"{host:15}:{port:5} is open  ({service})")

            # Try to grab the banner (optional)
            banner = banner_grab(s)
            if banner:
                log(f"Banner: {banner}")
                version = extract_version(banner)
            else:
                version = None

            # Query for vulnerabilities if banner/service version is available
            cves = query_nvd(service, version)
            display_vulnerabilities(cves)

    except ConnectionRefusedError:
        # Silently handle closed ports (do nothing)
        pass
    except socket.timeout:
        # Silently handle timeouts (do nothing)
        pass
    except Exception as e:
        with print_lock:
            log(f"Error scanning port {port} on {host}: {e}")
    finally:
        s.close()

def scan_thread():
    """ Thread worker function for scanning ports. """
    while True:
        worker = q.get()
        port_scan(worker)
        q.task_done()

def log(message):
    """ Log messages to both the terminal and a log file. """
    print(message)
    with open(log_file, 'a') as f:
        f.write(message + '\n')

def validate_host(target_host):
    """ Validate the host input, ensuring it's a valid IP address or domain. """
    try:
        socket.gethostbyname(target_host)
        return True
    except socket.error:
        return False

def validate_port_range(port_range):
    """ Validate that the port range is in the format start-end and within valid port limits. """
    try:
        start_port, end_port = map(int, port_range.split("-"))
        if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
            return start_port, end_port
        else:
            return None
    except (ValueError, AttributeError):
        return None

def main(target_host, ports, thread_count):
    """ Main function to initiate the port scanning with multiple threads. """
    global host, N_THREADS
    host = target_host
    N_THREADS = min(thread_count, len(ports))  # Adjust thread count dynamically based on the number of ports
    
    # Start the threads
    for t in range(N_THREADS):
        thread = Thread(target=scan_thread)
        thread.daemon = True
        thread.start()

    # Add the ports to the queue
    for port in ports:
        q.put(port)

    # Wait for all threads to finish
    q.join()

def portscanner():
    """ Simple function to gather user input and run the port scanner. """
    target_host = input("Enter the host to scan (IP or domain): ")
    if not validate_host(target_host):
        log("Invalid host. Please enter a valid IP address or domain name.")
        return

    port_range = input("Enter the port range to scan (e.g., 1-65535): ")
    valid_range = validate_port_range(port_range)
    if not valid_range:
        log(f"Invalid port range. Please enter a valid range (e.g., 1-65535).")
        return

    start_port, end_port = valid_range
    ports = list(range(start_port, end_port + 1))

    thread_count = input(f"Enter the number of threads (default {DEFAULT_THREADS}, max {len(ports)}): ")
    try:
        thread_count = int(thread_count) if thread_count else DEFAULT_THREADS
        thread_count = max(1, min(thread_count, len(ports)))  # Ensure thread count is between 1 and the number of ports
    except ValueError:
        log(f"Invalid thread count. Using default {DEFAULT_THREADS}.")
        thread_count = DEFAULT_THREADS

    # Clear previous log if it exists
    if os.path.exists(log_file):
        os.remove(log_file)

    log(f"Scanning {target_host} on ports {start_port}-{end_port} with {thread_count} threads...\n")
    
    main(target_host, ports, thread_count)
    log(f"Scan completed. Results saved to {log_file}.")
    time.sleep(3)
    return

if __name__ == "__main__":
    portscanner()
