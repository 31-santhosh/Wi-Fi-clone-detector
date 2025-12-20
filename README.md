# Kali WiFi Clone Detector
   
   A PyQt5-based tool for detecting potential rogue access points and WiFi clones in Kali Linux.
   
   ## Features
   - Network scanning with iwlist
   - Advanced scanning with airodump-ng
   - Risk assessment for potential rogue APs
   - Color-coded threat visualization
   
   ## Requirements
   - Kali Linux
   - Python 3.6+
   - PyQt5
   - aircrack-ng suite
   - Root privileges
   ## User Permissions
   -Root Access: The user must run the program with sudo or as root because:
   -Direct wireless interface access requires root privileges
   -airodump-ng and other wireless tools require root access
   -System interface configuration requires elevated permissions
   ## Usage Requirements
   -Legal Authorization: User must have explicit permission to scan the target networks (which you've confirmed you have)
   -Physical Location: User should be within range of the wireless networks they want to scan
   -Basic Understanding: Familiarity with wireless networks and security concepts
   ## Runtime Notes
   -The program automatically detects the first available wireless interface
   -Temporary files are created in /tmp/ during advanced scans and cleaned up automatically
   -Scans may take 10-30 seconds depending on network environment
   -Interface may briefly go down during advanced scans as it switches to monitor mode
   -Before running, ensure your wireless adapter is properly connected and recognized by the system with iwconfig.
