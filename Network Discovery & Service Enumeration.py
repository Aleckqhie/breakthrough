import socket
import requests
import json
import time
from datetime import datetime
from threading import Thread, Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
import subprocess
import platform

# Suppress SSL warnings for self-signed certificates
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class SmartTVScanner:
    def __init__(self, tv_ip=None):
        self.tv_ip = tv_ip
        self.open_ports = []
        self.services = []
        self.vulnerabilities = []
        self.lock = Lock()
        self.found_tvs = []
        self.all_devices = []  # Store ALL discovered devices
        
        if not self.tv_ip:
            print("[*] Ready to scan network. Use discover_network() to find all devices.")
    
    def get_local_network_range(self):
        """Automatically detect local network range"""
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Extract network prefix (e.g., 192.168.1 from 192.168.1.8)
            parts = local_ip.split('.')
            network_prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
            
            print(f"[*] Detected local network: {network_prefix}.0/24")
            print(f"[*] Your IP: {local_ip}")
            
            return network_prefix, local_ip
        except Exception as e:
            print(f"[-] Could not detect network: {e}")
            return "192.168.1", None
    
    def ping_sweep(self, network_prefix, start=1, end=254):
        """Fast ping sweep to find live hosts"""
        print(f"\n[*] Step 1: Finding live hosts on {network_prefix}.{start}-{end}")
        print("[*] This may take 30-60 seconds...")
        
        live_hosts = []
        
        def ping_host(ip):
            """Ping a single host"""
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
            
            command = ['ping', param, '1', timeout_param, '1', ip]
            
            try:
                result = subprocess.run(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
                if result.returncode == 0:
                    return ip
            except:
                pass
            return None
        
        # Parallel ping sweep
        with ThreadPoolExecutor(max_workers=50) as executor:
            ips = [f"{network_prefix}.{i}" for i in range(start, end + 1)]
            futures = {executor.submit(ping_host, ip): ip for ip in ips}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)
                    print(f"[+] Live host: {result}")
        
        print(f"\n[*] Found {len(live_hosts)} live hosts")
        return live_hosts
    
    def scan_all_ports(self, ip, common_only=True):
        """Scan ports on a single host"""
        open_ports = []
        
        if common_only:
            # Common ports - faster scan
            ports = [
                21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 554, 1900, 3306, 3389,
                5000, 5001, 5900, 6007, 7676, 8000, 8008, 8009, 8060, 8080, 8081,
                8443, 8888, 9090, 9091, 27017
            ]
        else:
            # Extended port range
            ports = list(range(1, 1024)) + [1900, 3306, 3389, 5000, 5001, 5900, 8000, 8008, 8080, 8443, 9090]
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.3)
                    if sock.connect_ex((ip, port)) == 0:
                        return port
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            results = executor.map(check_port, ports)
            open_ports = [port for port in results if port is not None]
        
        return open_ports
    
    def identify_device_type(self, ip, open_ports):
        """Identify what type of device this is"""
        device_info = {
            'ip': ip,
            'type': 'Unknown',
            'ports': open_ports,
            'services': [],
            'is_tv': False,
            'confidence': 'low'
        }
        
        # TV-specific port signatures
        tv_ports = {8008, 8009, 8060, 7676, 1900, 9090}
        tv_port_matches = len(set(open_ports) & tv_ports)
        
        # Check for TV-specific services
        if 8008 in open_ports or 8009 in open_ports:
            # Google Cast / Chromecast
            try:
                resp = requests.get(f"http://{ip}:8008/setup/eureka_info", timeout=2)
                if resp.status_code == 200:
                    data = resp.json()
                    device_info['type'] = 'Smart TV (Google Cast)'
                    device_info['is_tv'] = True
                    device_info['confidence'] = 'high'
                    device_info['name'] = data.get('name', 'Unknown')
                    device_info['services'].append('Google Cast')
                    return device_info
            except:
                pass
        
        if 8060 in open_ports:
            # Roku device
            device_info['type'] = 'Smart TV (Roku)'
            device_info['is_tv'] = True
            device_info['confidence'] = 'high'
            device_info['services'].append('Roku')
            return device_info
        
        if 7676 in open_ports:
            # Samsung TV
            device_info['type'] = 'Smart TV (Samsung)'
            device_info['is_tv'] = True
            device_info['confidence'] = 'high'
            device_info['services'].append('Samsung Smart View')
            return device_info
        
        # Check web interfaces for TV indicators
        for port in [80, 8080, 9090]:
            if port in open_ports:
                try:
                    resp = requests.get(f"http://{ip}:{port}", timeout=2)
                    content = resp.text.lower()
                    if any(keyword in content for keyword in ['smarttv', 'smart tv', 'television', 'tv remote', 'webos', 'tizen']):
                        device_info['type'] = 'Smart TV (Web Interface)'
                        device_info['is_tv'] = True
                        device_info['confidence'] = 'medium'
                        return device_info
                except:
                    pass
        
        # Guess device type based on port combinations
        if tv_port_matches >= 2:
            device_info['type'] = 'Possible Smart TV'
            device_info['is_tv'] = True
            device_info['confidence'] = 'medium'
        elif 22 in open_ports and 80 in open_ports:
            device_info['type'] = 'Server/Linux Device'
        elif 445 in open_ports or 3389 in open_ports:
            device_info['type'] = 'Windows Computer'
        elif 5900 in open_ports:
            device_info['type'] = 'VNC Server'
        elif 1900 in open_ports:
            device_info['type'] = 'UPnP Device'
            device_info['services'].append('UPnP')
        elif len(open_ports) == 0:
            device_info['type'] = 'Filtered/Firewalled Device'
        
        return device_info
    
    def discover_network(self, network_prefix=None, quick_scan=True):
        """Full network discovery - finds ALL devices"""
        
        # Auto-detect network if not provided
        if not network_prefix:
            network_prefix, local_ip = self.get_local_network_range()
        
        print("\n" + "="*60)
        print("FULL NETWORK DISCOVERY")
        print("="*60)
        
        # Step 1: Ping sweep to find live hosts
        live_hosts = self.ping_sweep(network_prefix)
        
        if not live_hosts:
            print("[-] No live hosts found. Check your network connection.")
            return None
        
        # Step 2: Port scan each live host
        print(f"\n[*] Step 2: Scanning ports on {len(live_hosts)} live hosts...")
        print("[*] This may take 1-2 minutes...")
        
        for idx, ip in enumerate(live_hosts, 1):
            print(f"\n[*] Scanning {ip} ({idx}/{len(live_hosts)})...")
            open_ports = self.scan_all_ports(ip, common_only=quick_scan)
            
            if open_ports:
                print(f"    [+] Found {len(open_ports)} open ports: {open_ports[:10]}{'...' if len(open_ports) > 10 else ''}")
                
                # Identify device type
                device_info = self.identify_device_type(ip, open_ports)
                self.all_devices.append(device_info)
                
                device_icon = "📺" if device_info['is_tv'] else "💻"
                print(f"    {device_icon} Device Type: {device_info['type']} (confidence: {device_info['confidence']})")
                
                if device_info['is_tv']:
                    self.found_tvs.append(device_info)
            else:
                print(f"    [-] No open ports found (device may be firewalled)")
                device_info = {
                    'ip': ip,
                    'type': 'Firewalled Device',
                    'ports': [],
                    'is_tv': False
                }
                self.all_devices.append(device_info)
        
        # Step 3: Display results
        self.display_discovery_results()
        
        return self.found_tvs
    
    def display_discovery_results(self):
        """Display comprehensive discovery results"""
        print("\n" + "="*60)
        print("NETWORK DISCOVERY COMPLETE")
        print("="*60)
        
        print(f"\n📊 Total Devices Found: {len(self.all_devices)}")
        print(f"📺 Smart TVs Found: {len(self.found_tvs)}")
        
        if self.found_tvs:
            print("\n🎯 SMART TV DEVICES:")
            print("-" * 60)
            for idx, tv in enumerate(self.found_tvs, 1):
                print(f"\n  {idx}. {tv['ip']}")
                print(f"     Type: {tv['type']}")
                print(f"     Confidence: {tv['confidence']}")
                print(f"     Open Ports: {tv['ports'][:10]}{'...' if len(tv['ports']) > 10 else ''}")
                if tv.get('name'):
                    print(f"     Name: {tv['name']}")
                if tv.get('services'):
                    print(f"     Services: {', '.join(tv['services'])}")
        
        print("\n💻 ALL DEVICES ON NETWORK:")
        print("-" * 60)
        for device in self.all_devices:
            icon = "📺" if device['is_tv'] else "💻"
            print(f"  {icon} {device['ip']:15} - {device['type']:30} - {len(device['ports'])} ports")
        
        print("="*60 + "\n")
    
    def check_tv_ports(self, ip, ports):
        """Legacy method - kept for compatibility"""
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)
                    if sock.connect_ex((ip, port)) == 0:
                        service = self.identify_service(ip, port)
                        if service != "Unknown":
                            with self.lock:
                                self.found_tvs.append({
                                    'ip': ip,
                                    'port': port,
                                    'service': service
                                })
                            print(f"[+] Potential TV found: {ip}:{port} - {service}")
            except Exception as e:
                pass
    
    def identify_service(self, ip, port):
        """Identify service running on port"""
        try:
            if port == 8060:
                return "Roku/Chromecast"
            elif port == 8008:
                return "Google Cast"
            elif port == 8009:
                return "Google Cast Secure"
            elif port == 8080:
                try:
                    resp = requests.get(f"http://{ip}:{port}", timeout=1)
                    if any(keyword in resp.text.lower() for keyword in ['tv', 'remote', 'smarttv']):
                        return "Smart TV Web Interface"
                except:
                    pass
                return "HTTP Service"
            elif port == 1900:
                return "UPnP/SSDP"
            elif port == 7676:
                return "Samsung TV"
            elif port == 9090:
                return "Web/Management Interface"
            return "Unknown"
        except:
            return "Unknown"
    
    def comprehensive_scan(self):
        """Perform comprehensive scan of the TV"""
        if not self.tv_ip:
            print("[-] No TV IP specified. Run discover_network() first or set tv_ip manually.")
            return
        
        print(f"\n[*] Starting comprehensive security scan of {self.tv_ip}")
        print("="*60)
        
        # Port scanning
        self.scan_ports()
        
        # Service enumeration
        self.enumerate_services()
        
        # Vulnerability checks
        self.check_common_vulnerabilities()
        
        # Generate report
        self.generate_report()
    
    def scan_ports(self):
        """Scan common ports"""
        print("\n[*] Scanning ports...")
        
        ports_to_scan = [
            21, 22, 23, 80, 443, 445, 554, 1900, 3389, 5000, 5001,
            6007, 7676, 8000, 8008, 8009, 8060, 8080, 8081, 8443, 9090, 9091
        ]
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((self.tv_ip, port))
                    if result == 0:
                        service = self.guess_service(port)
                        with self.lock:
                            self.open_ports.append({
                                'port': port,
                                'service': service,
                                'state': 'open'
                            })
                        print(f"[+] Open: {port}/tcp - {service}")
            except Exception as e:
                pass
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_port, ports_to_scan)
        
        print(f"[*] Found {len(self.open_ports)} open ports")
    
    def guess_service(self, port):
        """Guess service based on port number"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
            445: "SMB", 554: "RTSP", 1900: "UPnP", 3389: "RDP", 5000: "UPnP",
            6007: "X11", 7676: "Samsung TV", 8000: "HTTP Alt", 8008: "Google Cast",
            8009: "Cast Secure", 8060: "Roku", 8080: "HTTP Proxy", 8443: "HTTPS Alt",
            9090: "Web Interface"
        }
        return services.get(port, "Unknown")
    
    def enumerate_services(self):
        """Enumerate specific TV services"""
        print("\n[*] Enumerating TV services...")
        
        web_ports = [80, 8080, 8008, 9090]
        for port in web_ports:
            if any(p['port'] == port for p in self.open_ports):
                self.check_web_interface(port)
        
        if any(p['port'] == 1900 for p in self.open_ports):
            self.check_upnp()
        
        self.check_casting_services()
    
    def check_web_interface(self, port):
        """Check TV web interface"""
        print(f"[*] Checking web interface on port {port}...")
        
        urls = [
            f"http://{self.tv_ip}:{port}",
            f"http://{self.tv_ip}:{port}/index.html",
            f"http://{self.tv_ip}:{port}/tv",
            f"http://{self.tv_ip}:{port}/remote",
            f"http://{self.tv_ip}:{port}/api"
        ]
        
        for url in urls:
            try:
                response = requests.get(url, timeout=3, verify=False)
                if response.status_code == 200:
                    print(f"[+] Web interface found: {url}")
                    with self.lock:
                        self.services.append({
                            'type': 'web_interface',
                            'url': url,
                            'status_code': response.status_code
                        })
                    
                    self.test_default_credentials(url)
                    
            except requests.RequestException:
                pass
    
    def test_default_credentials(self, url):
        """Test common default credentials"""
        print(f"[*] Testing default credentials on {url}...")
        
        common_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", ""),
            ("root", "root"),
            ("user", "user"),
            ("admin", "1234")
        ]
        
        for username, password in common_creds:
            try:
                response = requests.get(url, auth=(username, password), timeout=2)
                if response.status_code == 200:
                    print(f"[!] VULNERABILITY: Default credentials work: {username}:{password}")
                    with self.lock:
                        self.vulnerabilities.append({
                            'type': 'default_credentials',
                            'severity': 'HIGH',
                            'url': url,
                            'credentials': f"{username}:{password}"
                        })
            except:
                pass
    
    def check_upnp(self):
        """Check UPnP vulnerabilities"""
        print("[*] Checking UPnP services...")
        
        ssdp_msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: ssdp:all\r\n\r\n"
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(ssdp_msg.encode(), (self.tv_ip, 1900))
            
            response, addr = sock.recvfrom(2048)
            if response:
                print("[+] UPnP service active")
                with self.lock:
                    self.services.append({
                        'type': 'upnp',
                        'active': True,
                        'response': response.decode('utf-8', errors='ignore')[:200]
                    })
            sock.close()
        except Exception as e:
            pass
    
    def check_casting_services(self):
        """Check casting protocol vulnerabilities"""
        print("[*] Checking casting services...")
        
        try:
            response = requests.get(f"http://{self.tv_ip}:8008/setup/eureka_info", timeout=3)
            if response.status_code == 200:
                data = response.json()
                device_name = data.get('name', 'Unknown')
                print(f"[+] Google Cast device detected: {device_name}")
                with self.lock:
                    self.services.append({
                        'type': 'google_cast',
                        'name': device_name,
                        'data': data
                    })
        except:
            pass
    
    def check_common_vulnerabilities(self):
        """Check for known smart TV vulnerabilities"""
        print("\n[*] Checking common vulnerabilities...")
        
        self.check_directory_traversal()
        self.check_info_disclosure()
    
    def check_directory_traversal(self):
        """Test for path traversal vulnerabilities"""
        print("[*] Testing for directory traversal...")
        
        payloads = [
            "../../../../etc/passwd",
            "../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini"
        ]
        
        for payload in payloads:
            test_urls = [
                f"http://{self.tv_ip}:8080/{payload}",
                f"http://{self.tv_ip}:80/{payload}"
            ]
            
            for url in test_urls:
                try:
                    response = requests.get(url, timeout=2, verify=False)
                    if "root:" in response.text or "[extensions]" in response.text:
                        print(f"[!] VULNERABILITY: Directory traversal possible at {url}")
                        with self.lock:
                            self.vulnerabilities.append({
                                'type': 'directory_traversal',
                                'severity': 'CRITICAL',
                                'url': url,
                                'payload': payload
                            })
                except:
                    pass
    
    def check_info_disclosure(self):
        """Check for information disclosure"""
        print("[*] Checking for information disclosure...")
        
        info_paths = [
            "/api/info",
            "/api/status",
            "/system/info",
            "/device/info",
            "/status"
        ]
        
        for port in [80, 8080, 9090]:
            for path in info_paths:
                try:
                    url = f"http://{self.tv_ip}:{port}{path}"
                    response = requests.get(url, timeout=2)
                    if response.status_code == 200:
                        print(f"[+] Information endpoint found: {url}")
                        with self.lock:
                            self.services.append({
                                'type': 'info_disclosure',
                                'url': url,
                                'data': response.text[:200]
                            })
                except:
                    pass
    
    def generate_report(self):
        """Generate security assessment report"""
        print("\n[*] Generating security report...")
        
        report = {
            'target': self.tv_ip,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'open_ports': self.open_ports,
            'services': self.services,
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total_open_ports': len(self.open_ports),
                'total_services': len(self.services),
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical_vulns': len([v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']),
                'high_vulns': len([v for v in self.vulnerabilities if v.get('severity') == 'HIGH'])
            },
            'recommendations': [
                "Change default credentials immediately if any were found",
                "Disable unused services and close unnecessary ports",
                "Update TV firmware to the latest version",
                "Use network segmentation to isolate IoT devices",
                "Disable remote management if not needed",
                "Enable firewall rules to restrict access",
                "Disable UPnP if not required"
            ]
        }
        
        filename = f"tv_security_scan_{self.tv_ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to {filename}")
        
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Target: {self.tv_ip}")
        print(f"Open Ports: {report['summary']['total_open_ports']}")
        print(f"Services Found: {report['summary']['total_services']}")
        print(f"Vulnerabilities: {report['summary']['total_vulnerabilities']}")
        print(f"  - Critical: {report['summary']['critical_vulns']}")
        print(f"  - High: {report['summary']['high_vulns']}")
        print("="*60 + "\n")


# Usage
if __name__ == "__main__":
    print("Smart TV Security Scanner - Full Network Discovery")
    print("="*60)
    
    scanner = SmartTVScanner()
    
    # Discover all devices on network
    found_tvs = scanner.discover_network(quick_scan=True)
    
    # If TVs were found, offer to scan them
    if found_tvs:
        print("\n[?] Would you like to perform detailed security scan on a TV?")
        print("    Run: scanner.tv_ip = 'TV_IP_HERE'")
        print("    Then: scanner.comprehensive_scan()")
        
        # Auto-scan first TV found
        if len(found_tvs) > 0:
            print(f"\n[*] Auto-scanning first TV found: {found_tvs[0]['ip']}")
            scanner.tv_ip = found_tvs[0]['ip']
            scanner.comprehensive_scan()
    else:
        print("\n[-] No Smart TVs detected on network")
        print("[*] Showing all discovered devices above")