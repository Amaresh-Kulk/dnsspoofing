from scapy.all import sniff, DNS, DNSQR, DNSRR
import socket
import datetime

# Log file for detected spoofing attempts
LOG_FILE = "dns_log.txt"

# Trusted DNS servers
TRUSTED_DNS = ["8.8.8.8", "1.1.1.1"]

def log_to_file(data):
    """Save detected spoofing attempts to a log file."""
    with open(LOG_FILE, "a") as log:
        log.write(data + "\n")

def get_trusted_dns_response(domain):
    """Queries trusted DNS servers to verify the correct IP address."""
    try:
        resolved_ip = socket.gethostbyname(domain)
        return resolved_ip
    except socket.gaierror:
        return None

def process_packet(packet):
    """Processes captured DNS packets, detects spoofing attempts."""
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query_name = packet[DNSQR].qname.decode().strip()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Capture DNS response
        if packet.haslayer(DNSRR):
            for i in range(packet[DNS].ancount):
                answer = packet[DNSRR][i]
                resolved_ip = answer.rdata

                # Get trusted DNS response
                trusted_ip = get_trusted_dns_response(query_name)

                if trusted_ip and resolved_ip != trusted_ip:
                    # Detected DNS spoofing attempt
                    alert_msg = f"[ALERT] Spoofing Detected! {query_name} -> Fake IP: {resolved_ip} (Expected: {trusted_ip})"
                    print(f"\n🚨 {alert_msg}")
                    log_to_file(f"[{timestamp}] {alert_msg}")

                else:
                    print(f"\n[+] DNS Query: {query_name} -> Resolved IP: {resolved_ip}")
                    log_to_file(f"[{timestamp}] [+] DNS Query: {query_name} -> {resolved_ip}")

# Sniff DNS packets
print("📡 Monitoring DNS traffic for spoofing attempts... Press Ctrl+C to stop.\n")
sniff(filter="udp port 53", prn=process_packet, store=0)

