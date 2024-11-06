def load_rules(filename):
    rules=[]
    with open(filename,'r') as f:
        for line in f:
            if(line.strip() and not line.startswith("#")):
                parts=line.split()
                if len(parts)>=4:
                    action,ip,port,protocol=parts[:4]
                    rules.append({"action":action.upper(), "ip":ip, "port":int(port), "protocol":protocol.upper()})
    return rules

from scapy.all import sniff
def capture_packets():
    print("Starting packet capture...")
    sniff(prn=process_packet,store=False)

from scapy.layers.inet import IP,TCP,UDP
def process_packet(packet):
               if IP in packet:
                    src_ip=packet[IP].src
                    dest_ip=packet[IP].dst
                    protocol='TCP' if TCP in packet else 'UDP' if UDP in packet else None
                    dest_port=packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None

                    for rule in rules:
                        if(rule['ip']==dest_ip and rule['protocol']==protocol and rule['port']==dest_port):
                           if rule['action']=="DENY":
                                print(f"Blocked packet: {packet.summary()}")
                                return False
                           else:
                                print(f"Allowed packet: {packet.summary()}")
                                return True
                    print(f"No matching rule, allowing packet: {packet.summary()}")

import subprocess
def add_iptables_rule(ip,action):
    cmd=f"iptables -A INPUT -s {ip} -j DROP" if action == "DENY" else f"iptables -A INPUT -s {ip} -j ACCEPT"
    subprocess.run(cmd,shell=True)
if __name__=="__main__":
    rules=load_rules("firewall_rules.txt")
    capture_packets()
