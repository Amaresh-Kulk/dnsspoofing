from scapy.all import sniff, DNS, DNSQR, DNSRR
import socket
import datetime
import smtplib
import os

# Log file
LOG_FILE = "dns_log.txt"

# Trusted DNS servers
TRUSTED_DNS = ["8.8.8.8", "1.1.1.1"]

# Email Alert Settings (Replace with your email details)
EMAIL_ALERTS = True  # Set to False to disable email alerts
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SENDER = "your_email@gmail.com"
EMAIL_PASSWORD = "your_email_password"  # Use an App Password for security
EMAIL_RECEIVER = "your_email@gmail.com"

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

def send_email_alert(domain, fake_ip, expected_ip):
    """Send an email alert for DNS spoofing detection."""
    if EMAIL_ALERTS:
        subject = "🚨 DNS Spoofing Detected!"
        message = f"ALERT! Spoofing detected:\n\nDomain: {domain}\nFake IP: {fake_ip}\nExpected IP: {expected_ip}"
        email_msg = f"Subject: {subject}\n\n{message}"

        try:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, email_msg)
            server.quit()
            print(f"📧 Email alert sent to {EMAIL_RECEIVER}!")
        except Exception as e:
            print(f"❌ Failed to send email: {e}")

def play_alert_sound():
    """Play a sound alert when spoofing is detected."""
    if os.name == "posix":  # Linux/macOS
        os.system("echo -e '\a'")  # Terminal bell sound
    elif os.name == "nt":  # Windows
        import winsound
        winsound.Beep(1000, 500)  # Beep sound

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
                    
                    # Play sound alert
                    play_alert_sound()
                    
                    # Send email alert
                    send_email_alert(query_name, resolved_ip, trusted_ip)

                else:
                    print(f"\n[+] DNS Query: {query_name} -> Resolved IP: {resolved_ip}")
                    log_to_file(f"[{timestamp}] [+] DNS Query: {query_name} -> {resolved_ip}")

# Sniff DNS packets
print("📡 Monitoring DNS traffic for spoofing attempts... Press Ctrl+C to stop.\n")
sniff(filter="udp port 53", prn=process_packet, store=0)

