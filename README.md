# 🕵️ Enhanced Network Sniffer in Python

This project is a simple but enhanced network packet sniffer built using **Scapy**. It captures only **TCP packets**, counts protocols, adds **timestamps**, and **logs** each capture into a text file.

## 🔧 Features
- TCP packet filtering
- Real-time console display
- Logs to `captured_packets_log.txt`
- Timestamped packet capture
- Packet counting by protocol (TCP, UDP, ICMP, Other)

## 🛠️ Requirements
- Python 3.x
- Scapy (`pip install scapy`)

## 🚀 How to Run
```bash
sudo python sniffer.py
