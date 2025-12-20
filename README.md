# 🔐 Kali WiFi Clone Detector

A **PyQt5-based security tool** designed for **Kali Linux** to detect potential **Wi-Fi clone (Evil Twin) attacks** and rogue access points by analyzing wireless network behavior.

This project is intended for **educational and authorized security testing purposes only**.

---

## 📌 Overview

Wi-Fi Evil Twin attacks occur when an attacker creates a fake access point with the same SSID as a legitimate network.  
This tool helps identify such threats by combining **basic scanning** and **advanced monitor-mode analysis**.

The application provides a **graphical interface** to visualize detected networks and highlight potential risks.

---

## ✨ Features

- 📡 **Basic Wi-Fi scanning** using `iwlist`
- 🕵️ **Advanced scanning** using `airodump-ng`
- 🚨 **Detection of duplicate SSIDs with different BSSIDs**
- 🎯 **Risk assessment for potential rogue access points**
- 🎨 **Color-coded threat visualization**
- 🖥️ **User-friendly PyQt5 GUI**
- 🧹 Automatic cleanup of temporary scan files

---

## 🖥️ System Requirements

### Operating System
- **Kali Linux** (recommended)  
  *(Other Linux distributions may work if required tools are available)*

### Python
- **Python 3.6 or higher**

### Privileges
- **Root access required**
  - Wireless interface configuration
  - Monitor mode activation
  - `airodump-ng` execution

---

## 📶 Hardware Requirements

### Wireless Network Interface Card (WNIC)
- Must support **monitor mode**
- Examples:
  - Internal wireless cards (chipset dependent)
  - External USB adapters (e.g., **Alfa AWUS036ACS**)

> ⚠️ Not all wireless adapters support monitor mode. Verify compatibility before use.

### System Resources
- Minimum **2 GB RAM** (4 GB recommended)
- Sufficient disk space for temporary scan files

---

## 📦 Software Dependencies

### Core Dependencies
- **PyQt5** – GUI framework
- **iwlist** – Basic wireless scanning (usually pre-installed on Kali)
- **aircrack-ng** – Advanced wireless analysis
- **nmap** – Additional network discovery features

---

## ⚙️ Installation

### 1️⃣ Update system
```bash
sudo apt update
