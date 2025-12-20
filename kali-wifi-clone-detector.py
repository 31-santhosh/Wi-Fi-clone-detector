from PyQt5 import QtWidgets, QtGui, QtCore
import sys, time, subprocess, json, re, threading, os

class KaliWiFiCloneDetector(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kali WiFi Clone Detector")
        self.resize(1100, 700)
        self.setStyleSheet(self.get_stylesheet())
        
        # Store scan results
        self.networks = []
        self.threats = []

        # Title
        self.title = QtWidgets.QLabel("Kali WiFi Clone Detector", self)
        self.title.setFont(QtGui.QFont("Monospace", 24, QtGui.QFont.Bold))
        self.title.setAlignment(QtCore.Qt.AlignCenter)
        self.title.setObjectName("title")

        # Table
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(10)
        self.table.setHorizontalHeaderLabels([
            "SSID", "BSSID (MAC)", "Signal", "Strength", "Security", 
            "Channel", "Vendor", "AP Count", "Risk Level", "Details"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setObjectName("networkTable")

        # Buttons
        self.scan_btn = QtWidgets.QPushButton("🔍 Scan Networks")
        self.scan_btn.setObjectName("scanButton")
        self.scan_btn.clicked.connect(self.start_scan)

        self.advanced_btn = QtWidgets.QPushButton("🔍 Advanced Scan")
        self.advanced_btn.setObjectName("advancedButton")
        self.advanced_btn.clicked.connect(self.start_advanced_scan)

        self.quit_btn = QtWidgets.QPushButton("❌ Quit")
        self.quit_btn.setObjectName("quitButton")
        self.quit_btn.clicked.connect(self.close)

        # Status Label
        self.status = QtWidgets.QLabel("Status: Ready")
        self.status.setObjectName("statusLabel")

        # Loading animation placeholder
        self.loading_label = QtWidgets.QLabel("Scanning with Kali tools...")
        self.loading_label.setAlignment(QtCore.Qt.AlignCenter)
        self.loading_label.hide()
        self.loading_label.setObjectName("loadingLabel")

        # Layouts
        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.addWidget(self.title)
        main_layout.addWidget(self.table)

        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addWidget(self.scan_btn)
        button_layout.addWidget(self.advanced_btn)
        button_layout.addWidget(self.quit_btn)
        main_layout.addLayout(button_layout)

        main_layout.addWidget(self.status)
        main_layout.addWidget(self.loading_label)
        
        # Initialize interface check
        self.check_interface()

    def check_interface(self):
        """Check for available wireless interfaces"""
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            interfaces = re.findall(r'(\w+)(?=.*IEEE 802.11)', result.stdout)
            if not interfaces:
                QtWidgets.QMessageBox.warning(self, "Warning", "No wireless interface found. Ensure you're running this on a system with a wireless card.")
            else:
                self.interface = interfaces[0]  # Use first available interface
                self.status.setText(f"Status: Using interface {self.interface}")
        except Exception as e:
            self.status.setText(f"Status: Error detecting interface - {str(e)}")

    def get_stylesheet(self):
        return """
        QWidget {
            background-color: #1e1e2e;
            color: #cdd6f4;
            font-family: "Monospace", "Courier New", monospace;
        }
        
        #title {
            color: #89b4fa;
            padding: 15px;
            font-size: 24px;
        }
        
        #networkTable {
            background-color: #313244;
            border-radius: 8px;
            gridline-color: #6c7086;
            selection-background-color: #45475a;
        }
        
        QHeaderView::section {
            background-color: #45475a;
            color: #89b4fa;
            font-weight: bold;
            padding: 8px;
            border: none;
        }
        
        QTableWidget::item {
            padding: 6px;
        }
        
        #scanButton, #advancedButton, #quitButton {
            padding: 12px;
            font-size: 14px;
            font-weight: bold;
            border-radius: 6px;
            border: none;
        }
        
        #scanButton {
            background-color: #a6e3a1;
            color: #11111b;
        }
        
        #scanButton:hover {
            background-color: #86c286;
        }
        
        #advancedButton {
            background-color: #f9e2af;
            color: #11111b;
        }
        
        #advancedButton:hover {
            background-color: #d9c28f;
        }
        
        #quitButton {
            background-color: #f38ba8;
            color: #11111b;
        }
        
        #quitButton:hover {
            background-color: #d36b88;
        }
        
        #statusLabel {
            color: #7f8c8d;
            font-size: 14px;
            padding: 10px;
        }
        
        #loadingLabel {
            color: #89b4fa;
            font-size: 16px;
            font-weight: bold;
        }
        """

    def start_scan(self):
        """Start lightweight scan using iwlist"""
        self.loading_label.setText("Scanning with iwlist...")
        self.loading_label.show()
        self.status.setText("Status: Scanning networks...")
        self.status.setStyleSheet("color: #89b4fa; font-weight: bold;")

        thread = threading.Thread(target=self.scan_with_iwlist)
        thread.start()

    def start_advanced_scan(self):
        """Start advanced scan using Kali tools (airodump-ng, nmap)"""
        self.loading_label.setText("Advanced scanning with airodump-ng...")
        self.loading_label.show()
        self.status.setText("Status: Performing advanced scan...")
        self.status.setStyleSheet("color: #fab387; font-weight: bold;")

        thread = threading.Thread(target=self.advanced_scan)
        thread.start()

    def scan_with_iwlist(self):
        """Scan networks using iwlist (faster)"""
        try:
            # Parse iwlist output
            result = subprocess.run(
                ['iwlist', self.interface, 'scan'], 
                capture_output=True, 
                text=True, 
                timeout=15
            )
            
            networks = self.parse_iwlist_output(result.stdout)
            
            # Update UI safely
            QtCore.QMetaObject.invokeMethod(
                self, 
                "update_table", 
                QtCore.Qt.QueuedConnection, 
                QtCore.Q_ARG(list, networks),
                QtCore.Q_ARG(str, "iwlist")
            )
        except subprocess.TimeoutExpired:
            self.update_status_error("Scan timed out. Try again or use advanced scan.")
        except Exception as e:
            self.update_status_error(f"Scan error: {str(e)}")

    def advanced_scan(self):
        """Perform advanced scan using airodump-ng and other Kali tools"""
        try:
            # Create temporary directory for output files
            temp_dir = "/tmp/wifi_scan_" + str(int(time.time()))
            os.makedirs(temp_dir, exist_ok=True)
            
            # Start airodump-ng scan (10 seconds)
            subprocess.run([
                'airodump-ng', 
                self.interface, 
                '--write', f'{temp_dir}/scan',
                '--output-format', 'csv',
                '--band', 'bg',
                '--write-interval', '1'
            ], timeout=12)
            
            # Parse CSV output
            csv_file = f'{temp_dir}/scan-01.csv'
            networks = self.parse_airodump_csv(csv_file)
            
            # Clean up temporary files
            subprocess.run(['rm', '-rf', temp_dir])
            
            # Update UI
            QtCore.QMetaObject.invokeMethod(
                self, 
                "update_table", 
                QtCore.Qt.QueuedConnection, 
                QtCore.Q_ARG(list, networks),
                QtCore.Q_ARG(str, "airodump")
            )
        except subprocess.TimeoutExpired:
            self.update_status_error("Advanced scan timed out")
        except Exception as e:
            self.update_status_error(f"Advanced scan error: {str(e)}")

    def parse_iwlist_output(self, output):
        """Parse iwlist scan output"""
        networks = []
        current_network = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if 'Cell ' in line and 'Address:' in line:
                if current_network:
                    networks.append(current_network)
                current_network = {'bssid': '', 'ssid': '', 'channel': '', 'signal': '', 'security': []}
                current_network['bssid'] = line.split('Address: ')[1].strip()
                
            elif 'ESSID:' in line:
                current_network['ssid'] = line.split('ESSID:"')[1].rstrip('"')
                
            elif 'Channel:' in line:
                current_network['channel'] = line.split('Channel:')[1].strip()
                
            elif 'Quality=' in line:
                quality = line.split('Quality=')[1].split(' ')[0]
                signal = line.split('Signal level=')[1].split(' ')[0]
                current_network['signal'] = f"{signal} dBm"
                
            elif 'Encryption key:' in line:
                if 'on' in line:
                    current_network['security'].append('WEP')
                else:
                    current_network['security'].append('Open')
                    
            elif 'IE: IEEE 802.11i/WPA2 Version 1' in line:
                if 'WPA2' not in current_network['security']:
                    current_network['security'].append('WPA2')
                    
            elif 'IE: WPA Version 1' in line:
                if 'WPA' not in current_network['security']:
                    current_network['security'].append('WPA')
        
        if current_network:
            networks.append(current_network)
            
        return networks

    def parse_airodump_csv(self, csv_file):
        """Parse airodump-ng CSV output"""
        networks = []
        try:
            with open(csv_file, 'r') as f:
                content = f.read()
                
            # Split into sections (stations and APs)
            sections = content.split('\n\n')
            if len(sections) < 2:
                return []
                
            # Parse AP section (first section)
            ap_lines = sections[0].split('\n')[2:]  # Skip headers
            
            for line in ap_lines:
                if line.strip() == '':
                    continue
                    
                parts = [p.strip() for p in line.split(',')]
                if len(parts) < 14:
                    continue
                    
                # Extract data
                bssid = parts[0]
                ssid = parts[13] if len(parts) > 13 else 'Unknown'
                channel = parts[3] if parts[3] else 'N/A'
                signal = parts[8] if parts[8] else '-100'
                security = parts[5] if parts[5] else 'Open'
                
                networks.append({
                    'bssid': bssid,
                    'ssid': ssid,
                    'channel': channel,
                    'signal': f"{signal} dBm",
                    'security': [security]
                })
        except Exception as e:
            print(f"Error parsing CSV: {e}")
            
        return networks

    def get_vendor_from_mac(self, mac):
        """Extract vendor information from MAC address"""
        oui_db = {
            # Common vendors
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:1C:14": "VMware",
            "00:16:3E": "XenSource",
            "08:00:27": "VirtualBox",
            "DC:A6:32": "Raspberry Pi",
            "B8:27:EB": "Raspberry Pi",
            "28:CD:C1": "Apple",
            "34:42:62": "Apple",
            "00:23:6C": "Apple",
            "78:67:D7": "Apple",
            "70:5A:0F": "HP",
            "00:1B:21": "Dell",
            "00:24:E8": "Dell",
            "00:19:B9": "Dell",
            "00:1E:C2": "Apple",
            "00:26:BB": "Apple",
            "E4:98:D6": "Apple",
            "98:03:D8": "Apple",
            "00:03:7F": "Apple",
            "00:1F:29": "HP",
            "00:17:F2": "Apple",
            "00:0F:1F": "Dell",
            "00:15:C5": "Dell",
            "00:21:5A": "HP",
            "00:23:7D": "HP",
            "00:0B:DB": "Dell",
            "00:1C:4D": "Dell",
            "00:0D:87": "D-Link",
            "00:11:95": "D-Link",
            "00:1E:58": "D-Link",
            "3C:5A:B4": "Google",
            "94:EB:2C": "Google",
            "A4:F3:C1": "TP-Link",
            "1C:BF:C0": "D-Link",
            "00:17:9A": "D-Link",
            "C0:C9:76": "Shenzhen TINNO",
            "18:8B:45": "Cisco",
            "00:1A:A9": "Honeywell",
            "00:1B:D3": "Panasonic",
            "00:1C:4F": "MACAB",
            "00:1E:2A": "Intel",
            "00:1F:3B": "Intel",
            "00:1C:C0": "Intel",
            "A4:4E:31": "Intel",
            "B8:08:CF": "Intel",
            "00:16:EA": "Intel",
            "00:1B:77": "Intel",
            "B4:6D:83": "Intel",
            "58:91:CF": "Intel",
            "00:03:47": "Intel",
            "00:E0:98": "Intel",
            "00:0F:34": "D-Link",
            "E4:50:9A": "HW Communications",
            "E0:61:B2": "HUAWEI",
            "34:6A:CF": "HUAWEI",
            "00:19:E2": "Juniper Networks",
            "00:1B:2B": "TP-Link",
            "00:1F:33": "Nintendo",
            "00:21:29": "Nintendo",
            "00:22:AA": "Nintendo",
            "38:BA:F8": "Samsung",
            "00:12:FB": "Samsung",
            "D0:DF:9A": "LG Electronics",
            "F8:A9:63": "COMPAL INFORMATION",
            "3C:E5B4": "Kaiomy Computers",
            "00:23:48": "Samsung",
            "20:25:64": "PEGATRON CORPORATION",
            "00:05:4F": "BUFFALO.INC",
            "00:0C:42": "Routerboard.com",
            "00:17:94": "ARRIS Group",
            "00:1F:3F": "AVM GmbH",
            "00:12:17": "Samsung",
            "3C:8A:E5": "Tensun Information Tech",
            "00:15:E9": "D-Link",
            "AC:F1:DF": "D-Link International",
            "00:14:2F": "Savvius",
            "00:0F:66": "Cisco-Linksys",
            "00:18:F8": "Thecus Technology",
            "00:1A:92": "ASUSTek COMPUTER INC",
            "00:1B:FC": "ASKEY COMPUTER CORP",
            "00:1F:C1": "ASUSTek COMPUTER INC",
            "00:1E:8C": "ASUSTek COMPUTER INC",
            "00:15:F9": "ASUSTek COMPUTER INC",
            "00:90:4B": "ASUSTek COMPUTER INC",
            "C4:12:F5": "D-Link International",
            "00:0C:AE": "ASUSTek COMPUTER INC"
        }
        
        # Extract OUI (first 3 octets)
        oui = ':'.join(mac.upper().split(':')[:3])
        
        # Check for virtual machines
        for prefix in ["00:50:56", "00:0C:29", "00:1C:14", "08:00:27"]:
            if mac.upper().startswith(prefix):
                return f"{oui_db.get(oui, 'Unknown')} (VM)"
                
        # Check for Raspberry Pi
        if mac.upper().startswith("DC:A6:32") or mac.upper().startswith("B8:27:EB"):
            return "Raspberry Pi"
            
        return oui_db.get(oui, "Unknown Vendor")

    def calculate_risk_level(self, ssid, bssid, data):
        """Calculate risk score based on multiple factors"""
        risk_score = 0
        risk_details = []
        
        # Check for multiple APs with same SSID (clone suspicion)
        ap_count = len([n for n in self.networks if n['ssid'] == ssid])
        if ap_count > 1:
            risk_score += 3
            risk_details.append(f"Multiple APs ({ap_count}) with same SSID")
            
        # Check for open networks (high risk)
        if 'Open' in data['security']:
            risk_score += 2
            risk_details.append("Open network (no encryption)")
            
        # Check for weak security (WEP/WPA)
        if any(security in data['security'] for security in ['WEP', 'WPA']):
            risk_score += 1
            risk_details.append("Outdated security protocol")
            
        # Check for suspicious signal variance
        same_ssid_networks = [n for n in self.networks if n['ssid'] == ssid]
        if len(same_ssid_networks) > 1:
            signals = []
            for net in same_ssid_networks:
                try:
                    signals.append(int(net['signal'].split(' ')[0]))
                except:
                    pass
            
            if signals:
                signal_range = max(signals) - min(signals)
                if signal_range > 25:
                    risk_score += 2
                    risk_details.append(f"Significant signal variation ({signal_range} dBm)")
                    
        # Check for non-standard channels
        try:
            channel = int(data['channel'])
            if channel not in [1, 6, 11] and channel != 0:
                risk_score += 1
                risk_details.append(f"Non-standard channel ({channel})")
        except:
            pass
            
        # Check for suspicious BSSID patterns
        oui = ':'.join(bssid.upper().split(':')[:3])
        if "00:00:00" in oui or "FF:FF:FF" in oui:
            risk_score += 3
            risk_details.append("Suspicious BSSID pattern")
            
        return risk_score, risk_details

    def get_risk_text(self, risk_score):
        """Get risk level text"""
        if risk_score >= 6:
            return "Critical Risk"
        elif risk_score >= 4:
            return "High Risk"
        elif risk_score >= 2:
            return "Medium Risk"
        elif risk_score >= 1:
            return "Low Risk"
        else:
            return "Normal"

    def get_risk_color(self, risk_score):
        """Get color based on risk score"""
        if risk_score >= 6:
            return QtGui.QColor(231, 76, 60)    # Red (Critical)
        elif risk_score >= 4:
            return QtGui.QColor(230, 126, 34)   # Orange (High)
        elif risk_score >= 2:
            return QtGui.QColor(241, 196, 15)   # Yellow (Medium)
        elif risk_score >= 1:
            return QtGui.QColor(52, 152, 219)   # Blue (Low)
        else:
            return QtGui.QColor(46, 204, 113)   # Green (Normal)

    def update_status_error(self, message):
        """Safely update status with error message"""
        QtCore.QMetaObject.invokeMethod(
            self, 
            "set_status_error", 
            QtCore.Qt.QueuedConnection, 
            QtCore.Q_ARG(str, message)
        )

    @QtCore.pyqtSlot(str)
    def set_status_error(self, message):
        self.loading_label.hide()
        self.status.setText(f"Status: Error - {message}")
        self.status.setStyleSheet("color: #f38ba8; font-weight: bold;")
        QtWidgets.QMessageBox.critical(self, "Error", message)

    @QtCore.pyqtSlot(list, str)
    def update_table(self, networks, scan_type):
        self.table.setRowCount(0)
        self.networks = networks
        self.threats = []
        
        # Group networks by SSID
        ssid_groups = {}
        for net in networks:
            ssid = net['ssid']
            if ssid not in ssid_groups:
                ssid_groups[ssid] = []
            ssid_groups[ssid].append(net)

        # Populate table
        for ssid, aps in ssid_groups.items():
            for net in aps:
                row = self.table.rowCount()
                self.table.insertRow(row)
                
                # SSID
                self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(ssid))
                
                # BSSID (MAC Address) - emphasized
                bssid_item = QtWidgets.QTableWidgetItem(net['bssid'])
                bssid_item.setFont(QtGui.QFont("Monospace", 9, QtGui.QFont.Bold))
                self.table.setItem(row, 1, bssid_item)
                
                # Signal Strength
                self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(net['signal']))

                # Convert dBm to percentage (approximation)
                try:
                    signal_dbm = int(net['signal'].split(' ')[0])
                    strength = min(max(2 * (signal_dbm + 100), 0), 100)
                    self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(f"{strength}%"))
                except:
                    self.table.setItem(row, 3, QtWidgets.QTableWidgetItem("N/A"))
                
                # Security Information
                security_text = ", ".join(net['security'])
                self.table.setItem(row, 4, QtWidgets.QTableWidgetItem(security_text))
                
                # Channel Information
                self.table.setItem(row, 5, QtWidgets.QTableWidgetItem(str(net['channel'])))
                
                # Vendor Information
                vendor = self.get_vendor_from_mac(net['bssid'])
                self.table.setItem(row, 6, QtWidgets.QTableWidgetItem(vendor))
                
                # AP Count (for this SSID)
                ap_count = len(aps)
                self.table.setItem(row, 7, QtWidgets.QTableWidgetItem(str(ap_count)))
                
                # Risk Level with color coding
                risk_score, risk_details = self.calculate_risk_level(ssid, net['bssid'], net)
                risk_text = self.get_risk_text(risk_score)
                
                risk_item = QtWidgets.QTableWidgetItem(risk_text)
                risk_item.setForeground(self.get_risk_color(risk_score))
                risk_item.setFont(QtGui.QFont("Monospace", 9, QtGui.QFont.Bold))
                self.table.setItem(row, 8, risk_item)
                
                # Details column
                details = "\n".join(risk_details) if risk_details else "No issues detected"
                self.table.setItem(row, 9, QtWidgets.QTableWidgetItem(details))
                
                # Track threats
                if risk_score >= 3:
                    self.threats.append({
                        'ssid': ssid,
                        'bssid': net['bssid'],
                        'vendor': vendor,
                        'risk_score': risk_score,
                        'details': risk_details
                    })

        # Hide loading indicator
        self.loading_label.hide()

        # Update status with threat count
        if self.threats:
            self.status.setText(f"Status: Scan complete ({scan_type}) - {len(self.threats)} potential threats")
            self.status.setStyleSheet("color: #fab387; font-weight: bold;")
            
            # Show threat details
            threat_msg = f"Potential threats detected ({len(self.threats)} found):\n\n"
            for threat in self.threats[:5]:  # Show first 5 threats
                threat_msg += f"SSID: {threat['ssid']}\n"
                threat_msg += f"  BSSID: {threat['bssid']}\n"
                threat_msg += f"  Vendor: {threat['vendor']}\n"
                threat_msg += f"  Risk Score: {threat['risk_score']}\n"
                if threat['details']:
                    threat_msg += f"  Issues: {', '.join(threat['details'][:2])}\n"
                threat_msg += "\n"
            
            if len(self.threats) > 5:
                threat_msg += f"... and {len(self.threats) - 5} more threats\n"
            
            QtWidgets.QMessageBox.warning(self, "Threats Detected", threat_msg)
        else:
            self.status.setText(f"Status: Scan complete ({scan_type}) - No threats detected")
            self.status.setStyleSheet("color: #a6e3a1; font-weight: bold;")


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    
    # Check if running as root (required for wireless tools)
    if os.geteuid() != 0:
        QtWidgets.QMessageBox.critical(None, "Error", "This application must be run as root to access wireless interfaces.")
        sys.exit(1)
        
    window = KaliWiFiCloneDetector()
    window.show()
    sys.exit(app.exec_())