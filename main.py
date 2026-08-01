import time
import os
import rich
import getpass
import subprocess
import socket
from mac_vendor_lookup import MacLookup
from scapy.all import IP, ARP, Ether, srp
from scapy.all import conf
from rich.console import Console

MacLookup().update_vendors()
conf.verb = 0
console = Console()
mac = MacLookup()
wuser = getpass.getuser()
os.system('cls')

console.print("""
[#2021b9]            _   _ _            [/]
[#5a70f6]  ___  _   _| |_| (_)_ __   ___ [/]
[#5192fa] / _ \\| | | | __| | | '_ \\ / _ \\ [/]
[#a3b4cc]| (_) | |_| | |_| | | | | |  __/[/]
[#c1d4cd] \\___/ \\__,_|\\__|_|_|_| |_|\\___/[/]
""")
while True:
    print('')
    command = console.input(f'[[#79b2fc]{wuser}[/]|user] - ')


    if command in ('help', 'helpita'):
        print("""
scan - scans all the devices it can find on ur ip 
""")

    elif command in ('scan', 'scanita'):
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24")

            answered, unanswered = srp(packet, timeout=2, verbose=False)

            for _, received in answered:
                ip = received.psrc
                mac_addr = received.hwsrc

                # Try hostname
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    name = None

                # If no hostname, try vendor
                if not name:
                    try:
                        vendor = mac.lookup(mac_addr)
                        name = f"{vendor} device"
                    except Exception:
                        name = "Unknown device"

                print(f"{ip}: {name}")

    elif command in ('exit', 'exita', 'quit', 'quitita'):
         break


    elif command in ("placeholder"):
         pass

    else:
         console.print(f"[red]{command} isnt recognized as a command[/]")