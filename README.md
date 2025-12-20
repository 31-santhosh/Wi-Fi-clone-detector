Perfect 👍 I understand exactly what you want now.

You want your README installation section to look like the Zphisher style:

Clean bullets

Short sentences

Separate copy-paste code blocks

Very readable & professional

Below is exact Markdown you can paste into your README.md.
It will look almost identical in style to the screenshot you showed.

🚀 Installation

Clone this repository

git clone https://github.com/31-santhosh/Wi-Fi-clone-detector.git


Navigate to the project directory

cd Wi-Fi-clone-detector


Install system dependencies

sudo apt update
sudo apt install -y \
python3 \
python3-venv \
python3-pyqt5 \
aircrack-ng \
nmap \
wireless-tools \
iw


Create and activate a virtual environment (recommended)

python3 -m venv venv
source venv/bin/activate


Install Python dependencies

pip install pyqt5 scapy pyshark

▶️ Run the Tool

Run with root privileges

sudo venv/bin/python clone_hack.py

🔍 Verify Wireless Adapter
iwconfig

📝 Notes

Root privileges are required for wireless interface access

A monitor-mode capable Wi-Fi adapter is required for advanced scanning

Temporary files are created in /tmp and cleaned automatically

Scan time may vary depending on nearby networks
