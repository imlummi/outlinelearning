import time
import os
import rich
import getpass
import subprocess
import socket
import ipaddress
from mac_vendor_lookup import MacLookup
from scapy.all import IP, ARP, Ether, srp
from scapy.all import conf
from rich.console import Console

conf.verb = 0
console = Console()
mac = MacLookup()
wuser = getpass.getuser()
os.system('cls')

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("192.168.1.1", 80)) 
local_ip = s.getsockname()[0]
s.close()

subnet = str(ipaddress.IPv4Network(f"{local_ip}/255.255.255.0", strict=False))

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
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        subnet = local_ip.rsplit('.', 1)[0] + '.0/24'

        # Auto-detect and bind Scapy to the exact physical adapter holding local_ip
        try:
            target_iface = [iface for iface in conf.ifaces.values() if iface.ip == local_ip][0]
            conf.iface = target_iface
        except IndexError:
            target_iface = conf.iface

        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        
        # Explicitly pass iface to srp
        answered, unanswered = srp(packet, timeout=3, verbose=False, iface=conf.iface)

        if not answered:
            console.print("[red]No devices responded[/]")
        else:
            for _, received in answered:
                ip = received.psrc
                mac_addr = received.hwsrc

                try:
                    name = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror):
                    name = None

                if not name:
                    try:
                        vendor = mac.lookup(mac_addr)
                        name = f"{vendor} device"
                    except Exception:
                        name = "unknown device"

                print(f"{ip}: {name} ({mac_addr})")

    elif command in ('exit', 'exita', 'quit', 'quitita'):
         break


    elif command in ("placeholder"):
         pass

    else:
         console.print(f"[red]{command} isnt recognized as a command[/]")