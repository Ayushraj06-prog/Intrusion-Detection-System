# Web-Based Intrusion Detection System (IDS)

A real-time network monitoring and intrusion detection system built with Python, Flask, and Scapy. This tool provides a live dashboard for tracking network traffic, identifying security threats, and classifying risks.

## 🚀 Key Features

- **Real-Time Sniffing:** Capturing and analyzing TCP, UDP, and ICMP packets on any active network interface.
- **Threat Detection:** 
  - **SYN Flood Detection:** Monitoring for suspicious volumes of SYN requests.
  - **ICMP Flood Detection:** Identifying abnormal ping activity.
  - **Port Scan Detection:** Tracking multiple port connection attempts from a single IP.
  - **Suspicious Port Access:** Identifying attempts on critical ports like 22 (SSH), 23 (Telnet), and 3389 (RDP).
- **Risk Level Classification:** Alerts are automatically tagged as **HIGH**, **MEDIUM**, or **LOW** risk for better prioritization.
- **IP Geolocation:** Live tracking of source IP locations, including Country, City, and ISP information.
- **Simulation Mode:** Intelligent fallback that generates mock traffic if hardware capture is blocked (e.g., missing drivers or permissions).
- **Modern UI Dashboard:** Responsive design with real-time charts, traffic health monitoring, and a searchable alert history.

## 🛠️ Technical Requirements

- **Python 3.x**
- **Npcap (Windows Only):** Required for Scapy to access network hardware.
  - *Note: During installation, select "Install Npcap in WinPcap API-compatible Mode".*
- **Administrator/Sudo Privileges:** Required for packet sniffing and raw socket access.

## 📦 Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-username/ids-system.git
   cd ids-system
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application:**
   *Open your terminal/command prompt as **Administrator** and run:*
   ```bash
   python app.py
   ```

4. **Access the Dashboard:**
   Open `http://localhost:5000` in your web browser.

## 🛡️ Security Modes

- **LIVE Mode:** Uses Npcap and Administrator rights to monitor your actual local network.
- **SIMULATION Mode:** Automatically activates if hardware capture fails, allowing you to test the UI and detection logic without complex setup.

## 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request or report bugs via issues.

## 📄 License
This project is licensed under the MIT License.
