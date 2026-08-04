import os
import socket
import getpass
from rich import spinner
from concurrent.futures import ThreadPoolExecutor
from mac_vendor_lookup import MacLookup
from scapy.all import ARP, Ether, srp, conf
from rich.console import Console

console = Console()

mac = MacLookup()

wuser = getpass.getuser() 
os.system('cls' if os.name == 'nt' else 'clear')

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip = s.getsockname()[0]
s.close()

conf.iface = next((i for i in conf.ifaces.values() if getattr(i, 'ip', None) == my_ip), conf.iface)
base = ".".join(my_ip.split(".")[:-1]) + '.0/24'

console.print("""
[#2021b9]            _   _ _            [/]
[#5a70f6]  ___  _   _| |_| (_)_ __   ___ [/]
[#5192fa] / _ \\| | | | __| | | '_ \\ / _ \\ [/]
[#a3b4cc]| (_) | |_| | |_| | | | | |  __/[/]
[#c1d4cd] \\___/ \\__,_|\__|_|_|_| |_|\\___/[/]
""")
while True:
    command = console.input(f'[[#79b2fc]{wuser}[/]|user] - ')

    if command in ('help', 'helpita'):
        print("scan - scans all the devices it can find on ur ip\nports <ip> - scans all ports from the provided ip\nupdatevendors - updates mac vendors \nexit/quit - close outline")

    elif command in ('scan', 'scanita'):
        with console.status('scanning network', spinner='line', spinner_style='#79b2fc'):
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=base)
            answered, _ = srp(packet, timeout=3, verbose=False, iface=conf.iface)

            if not answered:
                console.print("[red]no devices found[/red]")
            else:
                for _, received in answered:
                    ip = received.psrc
                    mac_addr = received.hwsrc

                    try:
                        name = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        name = None

                    if not name:
                        try:
                            vendor = mac.lookup(mac_addr)
                            name = f"{vendor} device"
                        except Exception:
                            name = "unknown device"

                    console.print(f"[#79b2fc]{ip}[/#79b2fc]: {name} ({mac_addr})")

    elif command.startswith('ports'):
        with console.status('scanning ports', spinner='line', spinner_style='#79b2fc'):
            parts = command.split()
            if len(parts) < 2:
                console.print('[yellow]usage: ports <ip>[/]')
            else:
                ports_target_ip = parts[1]
                def check_port(ports_target_ip, port):
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        banner = ''
                        if s.connect_ex((ports_target_ip, port)) == 0:
                            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                            banner = s.recv(1024).decode('utf-8', errors='ignore').strip().split('\n')[0]
                            console.print(f'[#79b2fc]{port}[/] [green]OPEN[/] {banner}')
                        s.close()
                    except Exception:
                        pass
                with ThreadPoolExecutor(max_workers=500) as executor:
                    executor.map(lambda p: check_port(ports_target_ip, p), range(1, 65536))
                console.print('ports scan has been completed')

    elif command in ('updatevendors', 'updatevendorita'):
        with console.status('scanning ports', spinner='line', spinner_style='#79b2fc'):
            try:
                mac.update_vendors()
                console.status("updated vendors")
            except Exception:
                pass

    elif command in ('exit', 'exita', 'quit', 'quitita'):
        break

    else:
        console.print(f"[red]{command} isn't recognized as a command[/red]")