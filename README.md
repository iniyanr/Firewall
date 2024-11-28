# Python Firewall with Enhanced Features

This Python-based firewall provides real-time traffic filtering and monitoring using `NetfilterQueue` and `Scapy`. It includes functionalities like time-based blocking, DNS filtering, rate limiting, volume monitoring, and more.

---

## Features

1. **Time-Based Blocking**: Restrict traffic during specified hours (e.g., block websites during work hours).
2. **DNS Filtering**: Block specific domains (e.g., `example.com`, `facebook.com`).
3. **Rate Limiting**: Block IPs sending excessive requests.
4. **Volume Monitoring**: Limit the total data volume from an IP within a time window.
5. **Protocol and Port Blocking**: Block specific ports or protocols like ICMP, TCP, or UDP.
6. **Whitelist and Blacklist**: Always allow or block traffic from specific IPs.
7. **Logging**: Logs all blocked or accepted packets to a file.

---

## Prerequisites

1. **Python 3.x**: Install Python 3.x on your system.
2. **Dependencies**: Install the required Python libraries:
   ```bash
   pip install scapy netfilterqueue
   ```
3. **Linux System**: This script uses `iptables` and requires Linux.

---

## Setup

### 1. Firewall Configuration

Create a configuration file named `firewall_config.json`. Below is an example:

```json
{
    "blocked_ips": ["192.168.1.10", "10.0.0.5"],
    "blocked_ports": [22, 23, 80],
    "whitelisted_ips": ["192.168.1.1"],
    "blocked_protocols": [1, 6],  
    "rate_limit": 100,
    "rate_time_window": 60,
    "volume_limit": 1048576,
    "log_file": "firewall.log",
    "time_block_rules": [
        {
            "start": "09:00",
            "end": "17:00"
        }
    ],
    "blocked_domains": [
         "google.com",
        "linkedin.com",
        "twitter.com"

    ]
}
```

### 2. Set Up iptables Rules

Redirect packets to the firewall using `iptables`:
```bash
sudo iptables -I INPUT -j NFQUEUE --queue-num 1
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1
```

### 3. Run the Firewall Script

Start the firewall:
```bash
sudo python3 enhanced_firewall.py
```

---

## How It Works

- The firewall inspects each packet in real-time and applies the following rules:
  - Blocks traffic from blacklisted IPs or ports.
  - Blocks traffic during specific hours based on `time_block_rules`.
  - Blocks DNS queries for specific domains in `blocked_domains`.
  - Limits traffic based on rate and volume thresholds.
  - Logs decisions to `firewall.log`.

---

## Logs

All actions are logged in the specified log file (default: `firewall.log`):
```bash
cat firewall.log
```

---

## Stopping the Firewall

1. **Stop the Script**:
   Press `Ctrl+C` in the terminal running the script.

2. **Remove iptables Rules**:
   ```bash
   sudo iptables -D INPUT -j NFQUEUE --queue-num 1
   sudo iptables -D OUTPUT -j NFQUEUE --queue-num 1
   ```

