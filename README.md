BASIC FIREWALL SIMULATION:

This project is a basic firewall simulation written in Python, utilizing Linux `iptables` for rule enforcement and `scapy` for packet capturing and inspection. It simulates firewall behavior by allowing or denying network packets based on predefined rules.

FEATURES: 

1. Packet Capture: Captures incoming network packets using `scapy`
2. Rule-Based Filtering: Evaluates packets against user-defined rules for `ALLOW` or `DENY` actions
3. Integration with iptables: Adds iptables rules to enforce firewall policies on the Linux system.

FILES:

1. firewall_sim.py: The main Python script that loads firewall rules, captures packets, and applies filtering logic.
2. firewall_rules.txt: A file containing custom firewall rules that define `ALLOW` and `DENY` conditions based on IP, port, and protocol.

SETUP INSTRUCTIONS:

Prerequisites:
1. pyhton
2. scapy
3. iptables 

RUNNING THE SIMULATION:

1. Clone this Repository:
 ```bash
   git clone https://github.com/yourusername/your-repo-name.git

2. Navigate to the project directory:
    cd your-repo-name

3. Update firewall_rules.txt as needed to define the rules.

4. Run the Firewall Simulation:
    sudo python3 firewall_sim.py
    Note: Root privileges may be required to modify iptables.

RULE CONFIGURATION:

Each rule in firewall_rules.txt follows this format:
<ALLOW/DENY> <IP> <PORT> <PROTOCOL> # Optional description

Example:
ALLOW 192.168.1.10 80 TCP # Allow HTTP traffic to 192.168.1.10
DENY 192.168.1.15 22 TCP # Deny SSH traffic to 192.168.1.15
ALLOW 0.0.0.0/0 443 TCP # Allow all HTTPS traffic

HOW IT WORKS:

1. Loading Rules: The script loads rules from firewall_rules.txt and parses each line to build a list of rule dictionaries.
2. Packet Processing: Captures network packets using scapy. For each packet:
* Checks if it matches any rule based on destination IP, port, and protocol.
* Logs and applies the ALLOW or DENY action based on the matched rule.
3. iptables Integration: Uses iptables commands to enforce persistent rules for allowed or blocked IP addresses on the system.

LIMITATIONS:

1. This simulation requires a Linux environment for iptables functionality.
2. Real-time packet filtering is limited by the performance of the Python interpreter and scapy.


This README provides an overview, setup instructions, and a detailed description of how your firewall simulation operates. Let me know if you need any adjustments!
