# Network Sniffer and ARP Spoofer
A Python script for network sniffing and ARP spoofing. This tool captures HTTP requests and potential login credentials while disrupting connections between the target and router. It's useful for testing network security, identifying vulnerabilities, and educational purposes.

## Features
- **Packet Sniffing**: Captures HTTP requests and searches for potential credentials in network traffic.
- **ARP Spoofing**: Disrupts connections between a target and the router by sending forged ARP responses.
- **Network Scanning**: Identifies MAC addresses of devices in the network.
- **Error Handling**: Displays detailed error messages for invalid inputs or issues during packet processing.
- **Customizable**: Allows users to specify target IP, router IP, and network interface for sniffing.

## Prerequisites
Before using the script, ensure you have the following:
- **Python**: Version 3.x is required.
- **Scapy Library**: Install using `pip install scapy`.
- **Administrator/Sudo Privileges**: Required for ARP spoofing and packet sniffing.
- **Linux or macOS**: The script is designed for Unix-like systems.

## Installation
1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/Esammansour883/network-sniffer.git
   cd network-sniffer
2. Install the required Python libraries:
  ```bash
  pip install scapy

## Usage
To start ARP spoofing and packet sniffing, run the script with the following command:
  ```bash
  python network_sniffer.py -t <TARGET_IP> -r <ROUTER_IP> -i <INTERFACE>
## Where:
- `<TARGET_IP>`: IP address of the victim.  
- `<ROUTER_IP>`: Gateway IP address.  
- `<INTERFACE>`: Network interface to sniff packets.  

### Example:
    ```bash
    python network_sniffer.py -t 192.168.1.10 -r 192.168.1.1 -i wlan0

## How It Works
- **Input Validation**: Validates the target IP, router IP, and interface input.  
- **ARP Spoofing**: Sends forged ARP packets to the target and router to disrupt their communication.  
- **Packet Sniffing**: Captures HTTP packets, extracts the Host and Path, and searches for potential login credentials.  

## Enhancements and Use Cases
- **Network Security Testing**: Simulate real-world attacks to test network defenses.  
- **Educational Tool**: Understand packet sniffing and ARP spoofing techniques.  
- **Troubleshooting**: Analyze network traffic to identify potential issues.  

## Limitations
- **Windows Compatibility**: The script is primarily designed for Linux and macOS. Modifications may be needed for Windows.  
- **Hardware Support**: Performance may vary based on the network adapter used.  

## License
This project is licensed under the MIT License - see the LICENSE file for details.  

## Author
Created by Essam Mansour.  
