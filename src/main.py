import logging
import docker
import asyncio
import threading
import psutil
from datetime import datetime
from pathlib import Path
from scapy.all import sniff
from scapy.layers.inet import IP
import sys
import keyboard
import os
import smtplib
import socket

os.system('color')

BLACK = '\033[30m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m' # orange on some systems
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
LIGHT_GRAY = '\033[37m'
DARK_GRAY = '\033[90m'
BRIGHT_RED = '\033[91m'
BRIGHT_GREEN = '\033[92m'
BRIGHT_YELLOW = '\033[93m'
BRIGHT_BLUE = '\033[94m'
BRIGHT_MAGENTA = '\033[95m'
BRIGHT_CYAN = '\033[96m'
WHITE = '\033[97m'

RESET = '\033[0m' # called to return to standard terminal text color

def send_mail():
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login('sihbpit2024@gmail.com', 'redacted secret')
    msg = 'DDOS ALERT'
    server.sendmail('sihbpit2024@gmail.com', 'krishm848@gmail.com', msg)

# Constants
IMG_NAME = "tools"

# Paths
BASE_LOG_DIR = Path(__file__).parent.resolve() / Path("../logs")
NIKTO_LOG_DIR = BASE_LOG_DIR / "nikto-logs"
NMAP_LOG_DIR = BASE_LOG_DIR / "nmap-logs"
SCAPY_LOG_DIR = BASE_LOG_DIR / "scapy-logs"

# Ensure log directories exist
NIKTO_LOG_DIR.mkdir(parents=True, exist_ok=True)
NMAP_LOG_DIR.mkdir(parents=True, exist_ok=True)
SCAPY_LOG_DIR.mkdir(parents=True, exist_ok=True)

# Logging Configuration
LOGNAME = 'LOG-' + datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + '.log'

NIKTO_LOG = f'NIKTO-{LOGNAME}'
NMAP_LOG = f'NMAP-{LOGNAME}'
SCAPY_LOG = f'SCAPY-{LOGNAME}'

def setup_logger(name, log_file, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    handler = logging.FileHandler(log_file, mode='w')
    logger.addHandler(handler)
    return logger

NIKTO_LOGGER = setup_logger('NIKTO_LOGGER', NIKTO_LOG_DIR / NIKTO_LOG)
NMAP_LOGGER = setup_logger('NMAP_LOGGER', NMAP_LOG_DIR / NMAP_LOG)
SCAPY_LOGGER = setup_logger('SCAPY_LOGGER', SCAPY_LOG_DIR / SCAPY_LOG)

# Events
sniffing_event = threading.Event()
stop_event = threading.Event()
monitoring_event = threading.Event()

# Detect potential DDoS
blocked_ip = []
ddos_threshold = 1000
ip_counts = {}

def detect_ddos(src_ip):
    global ip_counts
    if src_ip not in ip_counts:
        ip_counts[src_ip] = 1
    else:
        ip_counts[src_ip] += 1
    
    if ip_counts[src_ip] > ddos_threshold:
        return True
    return False

# Block IP (for Windows) in a separate thread
def block_ip_windows(ip):
    os.system(f"netsh advfirewall firewall add rule name=blockip{ip} dir=out interface=any action=block remoteip={ip}/32")

def async_block_ip_windows(ip):
    threading.Thread(target=block_ip_windows, args=(ip,), daemon=True).start()

# Scapy Packet Handler with DDoS detection
def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src  # Source IP
        packet_summary = packet.summary()
        SCAPY_LOGGER.info(packet_summary)

        if sniffing_event.is_set():
            print(f"{GREEN}Captured Packet:{RESET} {packet_summary}")

        # Detect DDoS and block IP if necessary
        if (src_ip not in ip_addresses) &(src_ip not in blocked_ip) & detect_ddos(src_ip):
            print(f"{BRIGHT_RED}Potential DDoS attack detected from IP: {src_ip}. Blocking...{RESET}")
            async_block_ip_windows(src_ip)
            blocked_ip.append(src_ip)
            send_mail()
    else:
        SCAPY_LOGGER.info(f"Packet without an IP layer received, ignoring: {packet.summary()}")

# Scapy Sniffing Thread
def scapy_sniffing_thread(interface):
    print(f"{GREEN}Starting Scapy packet sniffing on interface:{RESET} {interface}")
    sniff(iface=interface, prn=packet_handler, store=False, stop_filter=lambda p: stop_event.is_set())

# Start Scapy Sniffing
async def start_scapy_sniffing(interface="Wi-Fi"):
    global stop_event
    stop_event.clear()
    threading.Thread(target=scapy_sniffing_thread, args=(interface,), daemon=True).start()

# Display Resource Usage
async def display_resource_usage():
    print(f"{GREEN}Monitoring system resource usage...{RESET}")
    monitoring_event.set()
    try:
        while monitoring_event.is_set():
            cpu_usage = psutil.cpu_percent(interval=1)
            mem_info = psutil.virtual_memory()
            net_info = psutil.net_io_counters()

            sys.stdout.write(f"\r{YELLOW}CPU: {BRIGHT_YELLOW}{cpu_usage}% {MAGENTA}Memory: {BRIGHT_MAGENTA}{mem_info.percent}% {GREEN}Network Sent: {BRIGHT_GREEN}{net_info.bytes_sent / (1024 * 1024):.2f} MB, {BLUE}Received: {BRIGHT_BLUE}{net_info.bytes_recv / (1024 * 1024):.2f} MB{RESET}")
            sys.stdout.flush()

            await asyncio.sleep(1)
    except asyncio.CancelledError:
        print(f"{RED}Resource monitoring stopped.{RESET}")

# Stop Monitoring on Keystroke
def stop_monitoring_on_keystroke():
    keyboard.wait('q')
    print(f"{YELLOW}Stopping resource monitoring...{RESET}")
    monitoring_event.clear()

# Run Docker Command
async def docker_run(command, logger):
    try:
        client = docker.from_env()
        container = client.containers.run(
            image=IMG_NAME,
            command=command,
            network_mode='host',
            detach=True
        )
        for line in container.logs(stream=True):
            logger.info(line.strip().decode('utf-8'))
    except Exception as e:
        print(f"{RED}An error occurred: {BRIGHT_RED}{e}")

# Run Nmap and Nikto Scans
async def run_scans():
    global ip_addresses
    ip_addresses = get_ip_addresses()
    os.system('cls')

    print(f"""{MAGENTA}
    _              _     _   _      _   
   / \   ___  __ _(_)___| \ | | ___| |_ 
  / _ \ / _ \/ _` | / __|  \| |/ _ \ __|
 / ___ \  __/ (_| | \__ \ |\  |  __/ |_ 
/_/   \_\___|\__, |_|___/_| \_|\___|\__|
             |___/                      
                          
{BRIGHT_BLUE}Welcome to AegisNet, Agentless Monitoring System for Windows.
          
{YELLOW}Running Nmap and Nikto scans on all networks to scan for any vulnerability since last run....{RESET}""")

    tasks = []
    for ip in ip_addresses:
        try:
            NIKTO_LOGGER.info(ip)
            NMAP_LOGGER.info(ip)
            tasks.append(docker_run(f"nmap -A {ip}", NMAP_LOGGER))
            tasks.append(docker_run(f"nikto -h {ip}", NIKTO_LOGGER))
        except Exception as e:
            print(f"An error occurred: {e}")
            break

    # Run scans concurrently
    await asyncio.gather(*tasks)

    print(f"Scans completed. Check the logs in {YELLOW}{NIKTO_LOG_DIR}{RESET}, {YELLOW}{NMAP_LOG_DIR}{RESET}, and {YELLOW}{SCAPY_LOG_DIR}")
    print(ip_addresses)

# Retrieve IP addresses using psutil
def get_ip_addresses():
    ip_addresses = []
    for interface_name, interface_addrs in psutil.net_if_addrs().items():
        for addr in interface_addrs:
            if addr.family == socket.AF_INET: 
                ip_addresses.append(addr.address)
    return ip_addresses

# Display Menu
async def display_menu():
    while True:
        os.system('cls')
        print(f"""{MAGENTA} 
    _              _     _   _      _   
   / \   ___  __ _(_)___| \ | | ___| |_ 
  / _ \ / _ \/ _` | / __|  \| |/ _ \ __|
 / ___ \  __/ (_| | \__ \ |\  |  __/ |_ 
/_/   \_\___|\__, |_|___/_| \_|\___|\__|
             |___/                      
                      
{CYAN}1. Start Packet Viewing
2. Stop Packet Viewing
3. Switch Network Interface
4. Start Resource Monitoring
5. Stop Resource Monitoring
6. Run Nmap and Nikto Scans
7. Exit {RESET}""")
        choice = input(f"{YELLOW}Select an option:{RESET} ").strip()

        if choice == '1':
            sniffing_event.set()
            print(f"{BRIGHT_GREEN}Packet viewing started.{RESET}")
        elif choice == '2':
            sniffing_event.clear()
            print(f"{RED}Packet viewing stopped. Packet capture continues in the background.{RESET}")
        elif choice == '3':
            new_interface = input(f"{CYAN}Enter new interface to switch to:{RESET} ").strip()
            stop_event.set()
            await asyncio.sleep(1)  # Give some time for the sniffing thread to stop
            await start_scapy_sniffing(new_interface)
        elif choice == '4':
            if not monitoring_event.is_set():
                threading.Thread(target=stop_monitoring_on_keystroke, daemon=True).start()
                await display_resource_usage()
            else:
                print("Resource monitoring is already running.")
        elif choice == '5':
            if monitoring_event.is_set():
                monitoring_event.clear()  # Stop the resource monitoring loop
                print(f"{YELLOW}Stopping resource monitoring...{RESET}")
            else:
                print("Resource monitoring is not currently running.")
        elif choice == '6':
            await run_scans()
        elif choice == '7':
            print("Exiting...")
            stop_event.set()
            monitoring_event.clear()  # Stop resource monitoring if it's running
            break
        else:
            print(f"{RED}Unknown command. Please enter a valid option.{RESET}")

# Main Async Function
async def main():
    # Run Nmap and Nikto scans before displaying the menu
    await run_scans()

    # Start async Scapy sniffing in the background
    await start_scapy_sniffing()

    # Display menu to user
    await display_menu()

if __name__ == "__main__":
    asyncio.run(main())
