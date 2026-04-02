import time
from collections import defaultdict, deque
import socket
from scapy.all import sniff, IP, TCP, UDP, ICMP
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash
import urllib.request
import json

# Global Monitoring Status
sniffing_active = True

# In-memory structures to track packet counts for floods/scans
syn_counts = defaultdict(list)
icmp_counts = defaultdict(list)
port_scans = defaultdict(set)

import threading

# Global Monitoring Status
sniffing_active = True
stats_lock = threading.Lock()
sniffer_error = None  # Track internal sniffer errors (e.g. permission issues)
simulation_mode = False # Fallback to mock data if hardware capture fails

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()

def get_active_interface():
    """Finds the best interface to sniff on, based on the default route."""
    try:
        from scapy.all import conf
        # Try to find interface matching LOCAL_IP
        for iface in conf.ifaces.values():
            if hasattr(iface, 'ip') and iface.ip == LOCAL_IP:
                return iface
        return conf.iface
    except Exception:
        return None

recent_traffic = deque(maxlen=50)
recent_dns = deque(maxlen=50)

# GeoIP Cache
ip_geo_cache = {}

def get_ip_geo(ip):
    # Check for private or loopback IPs
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") or ip == "127.0.0.1":
        return {"country": "Unknown", "city": "Local", "isp": "Local"}
        
    if ip in ip_geo_cache:
        return ip_geo_cache[ip]
        
    geo = {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
    try:
        url = f"http://ip-api.com/json/{ip}"
        # Keep timeout extremely short to prevent sniff blocking
        with urllib.request.urlopen(url, timeout=1.0) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                geo = {
                    "country": data.get("country", "Unknown"), 
                    "city": data.get("city", "Unknown"), 
                    "isp": data.get("isp", "Unknown")
                }
        ip_geo_cache[ip] = geo
    except Exception:
        ip_geo_cache[ip] = geo
    
    return ip_geo_cache[ip]

# In-memory structures to track packet counts for floods/scans
syn_counts = defaultdict(list)
icmp_counts = defaultdict(list)
port_scans = defaultdict(set)

# Statistics tracking
total_packets = 0
packets_this_second = 0
packets_per_second = 0

packet_stats = {
    "tcp": 0,
    "udp": 0,
    "icmp": 0
}

def pps_timer_worker():
    global packets_this_second, packets_per_second
    while True:
        time.sleep(1.0)
        with stats_lock:
            packets_per_second = packets_this_second
            packets_this_second = 0
            
        # Periodic heartbeat for debugging
        if int(time.time()) % 10 == 0:
            mode = "SIMULATION" if simulation_mode else "LIVE"
            print(f"[*] Sniffer [{mode}] Heartbeat - PPS: {packets_per_second} | Total: {total_packets}")

# Detection Thresholds
TIME_WINDOW = 10  # Seconds to remember a packet
SYN_THRESHOLD = 50 # Number of SYN packets inside window to trigger alert
ICMP_THRESHOLD = 50 # Number of ICMP packets inside window to trigger alert
PORT_SCAN_THRESHOLD = 15 # Number of distinct ports scanned by same IP inside window

DB_FILE = "alerts.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  rule TEXT,
                  source_ip TEXT,
                  details TEXT,
                  risk_level TEXT DEFAULT 'LOW')''')
                  
    # Gracefully add new geolocation columns if they don't exist yet
    try:
        c.execute("ALTER TABLE alerts ADD COLUMN country TEXT")
        c.execute("ALTER TABLE alerts ADD COLUMN city TEXT")
        c.execute("ALTER TABLE alerts ADD COLUMN isp TEXT")
    except sqlite3.OperationalError:
        pass # Columns already exist

    try:
        c.execute("ALTER TABLE alerts ADD COLUMN risk_level TEXT DEFAULT 'LOW'")
    except sqlite3.OperationalError:
        pass # Column already exists
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT)''')
    
    # Insert default admin user if not exists
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        hashed_pw = generate_password_hash("admin123")
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", hashed_pw))
        
    conn.commit()
    conn.close()

def log_alert(rule, source_ip, details, risk_level="LOW"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    conn = sqlite3.connect(DB_FILE, timeout=10)
    c = conn.cursor()
    
    # Avoid duplicate alert spam for the same IP and Rule within the last 5 seconds
    c.execute('''SELECT timestamp FROM alerts 
                 WHERE rule=? AND source_ip=? 
                 ORDER BY id DESC LIMIT 1''', (rule, source_ip))
    row = c.fetchone()
    if row:
        try:
            last_time = datetime.strptime(row[0], "%H:%M:%S")
            if (datetime.now() - last_time).seconds < 5:
                conn.close()
                return  # Prevent duplicate
        except ValueError:
            pass

    # Fetch geolocation stats for logging
    geo = get_ip_geo(source_ip)

    c.execute("INSERT INTO alerts (timestamp, rule, source_ip, details, country, city, isp, risk_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
              (timestamp, rule, source_ip, details, geo['country'], geo['city'], geo['isp'], risk_level))
    conn.commit()
    conn.close()
    
    print(f"[!] IDS ALERT: [{risk_level}] {rule} from {source_ip} ({geo['country']}, {geo['city']}, {geo['isp']}) - {details}")

def clean_old_logs(ip_dict, current_time):
    """Removes timestamps that are older than our TIME_WINDOW."""
    for ip in list(ip_dict.keys()):
        ip_dict[ip] = [t for t in ip_dict[ip] if current_time - t <= TIME_WINDOW]
        if not ip_dict[ip]:
            del ip_dict[ip]

def packet_callback(packet):
    global sniffing_active, total_packets, packets_this_second
    
    if not sniffing_active:
        return
        
    with stats_lock:
        packets_this_second += 1
        total_packets += 1
        
    try:
        # Only process IP packets
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            current_time = time.time()
            
            protocol = "IP"
            dport = ""
            
            if TCP in packet:
                protocol = "TCP"
                dport = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                dport = packet[UDP].dport
            elif ICMP in packet:
                protocol = "ICMP"
                
            direction = "OUTGOING" if src_ip == LOCAL_IP else "INCOMING"
            
            with stats_lock:
                recent_traffic.appendleft({
                    "src": src_ip,
                    "dst": dst_ip,
                    "protocol": protocol,
                    "port": dport,
                    "direction": direction
                })
                
            # Track ICMP
            if ICMP in packet:
                with stats_lock:
                    packet_stats["icmp"] += 1
                icmp_counts[src_ip].append(current_time)
                clean_old_logs(icmp_counts, current_time)
                if len(icmp_counts[src_ip]) > ICMP_THRESHOLD:
                    log_alert("ICMP Flood", src_ip, f"More than {ICMP_THRESHOLD} ICMP packets detected in {TIME_WINDOW}s", "HIGH")

            # Track UDP
            if UDP in packet:
                with stats_lock:
                    packet_stats["udp"] += 1
                    
                # DNS Monitoring (usually over UDP)
                if packet.haslayer("DNS") and packet.haslayer("DNSQR"):
                    try:
                        domain = packet.getlayer("DNSQR").qname.decode('utf-8', errors='ignore')
                        if domain.endswith('.'):
                            domain = domain[:-1]
                            
                        q_time = datetime.now().strftime("%H:%M:%S")
                        log_dns = False
                        with stats_lock:
                            if not any(d['domain'] == domain for d in recent_dns):
                                recent_dns.appendleft({"timestamp": q_time, "domain": domain})
                                log_dns = True
                        
                        if log_dns:
                            # Log DNS query as LOW risk alert (outside of lock)
                            log_alert("DNS Query", src_ip, f"Domain: {domain}", "LOW")
                    except Exception:
                        pass

            # Track TCP (SYN Flood & Port Scanning)
            if TCP in packet:
                with stats_lock:
                    packet_stats["tcp"] += 1
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                # SYN Flood Detection (Flags == 'S' or 0x02)
                if flags == 0x02 or flags == "S":
                    syn_counts[src_ip].append(current_time)
                    clean_old_logs(syn_counts, current_time)
                    if len(syn_counts[src_ip]) > SYN_THRESHOLD:
                        log_alert("SYN Flood", src_ip, f"More than {SYN_THRESHOLD} SYN requests detected in {TIME_WINDOW}s", "HIGH")
                    
                    # Port Scan Detection (Tracking unique ports pinged by a single IP)
                    port_scans[src_ip].add(dst_port)
                    if len(port_scans[src_ip]) > PORT_SCAN_THRESHOLD:
                        log_alert("Port Scan", src_ip, f"Scanned {len(port_scans[src_ip])} distinct ports", "HIGH")
                        port_scans[src_ip].clear()

                # Suspicious Port Access (MEDIUM)
                SUSPICIOUS_PORTS = [22, 23, 3389]
                if dst_port in SUSPICIOUS_PORTS:
                    port_name = {22: "SSH", 23: "TELNET", 3389: "RDP"}.get(dst_port, "Unknown")
                    log_alert(f"Suspicious Port Access ({port_name})", src_ip, f"Attempted connection to port {dst_port}", "MEDIUM")
                
                # Repeated Connections Detection (MEDIUM)
                # Reusing syn_counts for general TCP connection frequency
                if len(syn_counts[src_ip]) > (SYN_THRESHOLD / 2):
                    log_alert("Repeated Connections", src_ip, f"High frequency of connections ({len(syn_counts[src_ip])}) detected", "MEDIUM")
    except Exception:
        pass

def run_simulation():
    """Generates mock traffic for demonstration when capture fails."""
    global simulation_mode, total_packets, packets_this_second
    simulation_mode = True
    print("[!] IDS is now running in SIMULATION MODE (Mock Data).")
    
    import random
    mock_ips = ["192.168.1.5", "10.0.0.42", "172.16.5.10", "8.8.8.8", "1.1.1.1"]
    mock_domains = ["google.com", "malicious-site.net", "update.windows.com", "github.com"]
    
    while simulation_mode:
        time.sleep(random.uniform(0.1, 0.5))
        if not sniffing_active: continue
        
        src = random.choice(mock_ips)
        dst = LOCAL_IP if random.random() > 0.5 else random.choice(mock_ips)
        proto = random.choice(["TCP", "UDP", "ICMP"])
        port = random.randint(20, 1024) if proto != "ICMP" else ""
        
        with stats_lock:
            total_packets += 1
            packets_this_second += 1
            recent_traffic.appendleft({
                "src": src, "dst": dst, "protocol": proto, 
                "port": port, "direction": "INCOMING" if dst == LOCAL_IP else "OUTGOING"
            })
            
            # Occasionally log an alert for testing
            if random.random() < 0.05:
                # Trigger a mock alert
                pass # Logic handled by app logic or direct call

def start_sniffing():
    """Initializes the database and starts Scapy sniffer in continuous mode."""
    from scapy.all import conf
    init_db()
    
    # Start the background timer for PPS calculation
    threading.Thread(target=pps_timer_worker, daemon=True).start()
    
    best_iface = get_active_interface()
    print(f"[*] Best Network Interface: {best_iface}")
    
    print("[*] Starting Web-Based Network IDS Sniffer...")
    # Update start time just before sniffing starts
    packet_stats["start_time"] = time.time()
    
    try:
        # Default sniffing with discovered interface
        sniff(iface=best_iface, prn=packet_callback, store=False)
    except Exception as e:
        print(f"[!] Sniffer failed with iface {best_iface}: {e}")
        print("[!] Attempting L3 socket fallback (Administrator recommended)...")
        try:
            sniff(prn=packet_callback, store=False, L2socket=conf.L3socket)
        except Exception as e_l3:
            global sniffer_error
            sniffer_error = str(e_l3)
            print(f"[CRITICAL] IDS Hardware capture failed: {e_l3}")
            # Final fallback: Run simulation so UI works
            run_simulation()

def get_stats():
    """Returns current packet statistics."""
    with stats_lock:
        return {
            "total_packets": total_packets,
            "packets_per_second": packets_per_second,
            "sniffer_error": sniffer_error,
            "protocols": {
                "TCP": packet_stats["tcp"],
                "UDP": packet_stats["udp"],
                "ICMP": packet_stats["icmp"]
            }
        }

def get_recent_traffic():
    """Returns the most recent 50 packets captured."""
    with stats_lock:
        return list(recent_traffic)

def get_recent_dns():
    """Returns the most recent 50 unique DNS queries."""
    with stats_lock:
        return list(recent_dns)

def toggle_sniffing(state: bool):
    global sniffing_active
    sniffing_active = state
    return sniffing_active

def get_sniffing_status():
    global sniffing_active
    return sniffing_active
