import json
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR
from netfilterqueue import NetfilterQueue
import time
import datetime

config_file = "firewall_config.json"

with open(config_file, "r") as f:
    config = json.load(f)

blocked_ips = set(config["blocked_ips"])
blocked_ports = set(config["blocked_ports"])
whitelisted_ips = set(config["whitelisted_ips"])
blocked_protocols = set(config["blocked_protocols"])
rate_limit = config["rate_limit"]
rate_time_window = config["rate_time_window"]
volume_limit = config["volume_limit"]
log_file = config.get("log_file", "firewall.log")
time_block_rules = config["time_block_rules"]
blocked_domains = set(config["blocked_domains"])

ip_request_count = {}
ip_volume_count = {}
last_reset_time = time.time()


def reset_request_and_volume_count():
    global ip_request_count, ip_volume_count, last_reset_time
    current_time = time.time()
    if current_time - last_reset_time > rate_time_window:
        ip_request_count.clear()
        ip_volume_count.clear()
        last_reset_time = current_time


def log_packet_decision(packet, decision):
    log_entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Packet from {packet.src} to {packet.dst} {decision}\n"
    with open(log_file, "a") as f:
        f.write(log_entry)
    print(log_entry.strip())


def is_time_blocked():
    now = datetime.datetime.now()
    for rule in time_block_rules:
        start = datetime.datetime.strptime(rule["start"], "%H:%M").time()
        end = datetime.datetime.strptime(rule["end"], "%H:%M").time()
        if start <= now.time() <= end:
            return True
    return False


def is_domain_blocked(domain):
    for blocked in blocked_domains:
        if domain.endswith(blocked):
            return True
    return False


def process_packet(packet):
    global ip_request_count, ip_volume_count
    reset_request_and_volume_count()

    scapy_packet = IP(packet.get_payload())
    src_ip = scapy_packet.src
    dst_port = getattr(scapy_packet, "dport", None)
    packet_size = len(scapy_packet)

    if src_ip in whitelisted_ips:
        log_packet_decision(scapy_packet, "ACCEPTED (Whitelisted IP)")
        packet.accept()
        return

    if is_time_blocked():
        log_packet_decision(scapy_packet, "BLOCKED (Time-Based Rule)")
        packet.drop()
        return

    if scapy_packet.haslayer(DNS) and scapy_packet[DNS].qd:
        queried_domain = scapy_packet[DNSQR].qname.decode('utf-8').rstrip('.')
        if is_domain_blocked(queried_domain):
            log_packet_decision(scapy_packet, f"BLOCKED (Blocked Domain: {queried_domain})")
            packet.drop()
            return

    if src_ip in blocked_ips:
        log_packet_decision(scapy_packet, "BLOCKED (Blacklisted IP)")
        packet.drop()
        return

    if dst_port and dst_port in blocked_ports:
        log_packet_decision(scapy_packet, "BLOCKED (Blacklisted Port)")
        packet.drop()
        return

    protocol = scapy_packet.proto
    if protocol in blocked_protocols:
        log_packet_decision(scapy_packet, "BLOCKED (Blacklisted Protocol)")
        packet.drop()
        return

    if src_ip not in ip_request_count:
        ip_request_count[src_ip] = 0
    ip_request_count[src_ip] += 1

    if ip_request_count[src_ip] > rate_limit:
        log_packet_decision(scapy_packet, "BLOCKED (Rate Limit Exceeded)")
        packet.drop()
        return

    if src_ip not in ip_volume_count:
        ip_volume_count[src_ip] = 0
    ip_volume_count[src_ip] += packet_size

    if ip_volume_count[src_ip] > volume_limit:
        log_packet_decision(scapy_packet, "BLOCKED (Volume Limit Exceeded)")
        packet.drop()
        return

    if scapy_packet.haslayer(ICMP):
        log_packet_decision(scapy_packet, "BLOCKED (ICMP Ping Detected)")
        packet.drop()
        return

    log_packet_decision(scapy_packet, "ACCEPTED")
    packet.accept()


queue_num = 1  
nfqueue = NetfilterQueue()
nfqueue.bind(queue_num, process_packet)

try:
    print("Starting the enhanced firewall with time-based blocking and DNS filtering...")
    nfqueue.run()
except KeyboardInterrupt:
    print("\nStopping the enhanced firewall...")
finally:
    nfqueue.unbind()

