#To Do

#FakeAP
#DOS Tool testen
#EvilAp testen

#Add Wifi Handshake Capture
#Add Wifi Handshake Brute Forcing
#Automate Vulnerability Exploitation w/ vulnerable Ports (Automatic Exploits?)


from server import *
from networkscan import *
from portscan import *
import subprocess

def startup():
    subprocess.run(["clear"])
    print("Welcome to RedRidingHood V1 Testing")
    print("Choose what you would like to do")
    print("0. Verifiy the Integrity of Files")
    print("1. Wi-Fi Scan")
    print("2. Handshake Capture")
    print("3. Port Scan")
    print("4. Create your own Fake Access Point")
    print("5. Copy an existing Access Point")
    print("6. Start Listener")
    choice = input(">>> ")

    if choice == "0":
        pass
    elif choice == "1":
        try:
            # Execute the networkscan script
            subprocess.run(["python", "/home/randompolymath/Desktop/RedRidingHoodCompany/redridinghoodv1/networkscan.py"])
        except KeyboardInterrupt:
            print("Network Scanner Interrupted, returning to the Main Menu")
            startup()
    elif choice == "2":
        try:
            # Execute the portscan script
            subprocess.run(["python", "/home/randompolymath/Desktop/RedRidingHoodCompany/redridinghoodv1/handshake.py"])  # example
        except KeyboardInterrupt:
            print("Handshake Capture interrupted, returning to Main Menu")
            startup()
    elif choice == "3":
        try:
            # Execute the portscan script
            subprocess.run(["python", "/home/randompolymath/Desktop/RedRidingHoodCompany/redridinghoodv1/portscan.py"])  # example
        except KeyboardInterrupt:
            print("Port Scanner interrupted, returning to Main Menu")
            startup()
    elif choice == "4":
        try:
            # Execute the portscan script
            subprocess.run(["python", "/home/randompolymath/Desktop/RedRidingHoodCompany/redridinghoodv1/ownap.py"])  # example
        except KeyboardInterrupt:
            print("Your own AP got interrupted, returning to Main Menu")
            startup()
    elif choice == "5":
        try:
            # Execute the portscan script
            subprocess.run(["python", "/home/randompolymath/Desktop/RedRidingHoodCompany/redridinghoodv1/fakeap.py"])  # example
        except KeyboardInterrupt:
            print("Fake AP interrupted, returning to Main Menu")
            startup()
    elif choice == "6":
        try:
            # Execute the reverse shell server
            subprocess.run(["python", "/home/randompolymath/Desktop/RedRidingHoodCompany/redridinghoodv1/server.py"])
        except KeyboardInterrupt:
            print("Listener Interrupted, returning to the Main Menu")
            startup()
    elif choice == "exit":
        pass
    else:
        print("Invalid option, returning to Main Menu.")
        startup()

startup()