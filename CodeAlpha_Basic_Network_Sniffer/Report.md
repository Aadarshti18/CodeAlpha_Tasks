# Task 1: Basic Network Sniffer Using Python

## Author

Aadarsh Tiwari

## Internship Program

CodeAlpha Cyber Security Internship

## Task Title

Basic Network Sniffer


## 1. Introduction

A network sniffer is a tool used to capture and analyze network packets traveling through a network. It helps in understanding how data flows between devices and is widely used for network troubleshooting, monitoring, and learning purposes in cybersecurity.

In this task, a basic network sniffer is implemented using Python and the Scapy library. The program captures a limited number of packets and displays important information such as source IP, destination IP, protocol type, and packet length.

---

## 2. Objective of the Task

The main objectives of this task are:

* To understand how network packets are transmitted
* To learn packet sniffing using Python
* To analyze basic packet information
* To gain hands-on experience with cybersecurity tools

---

## 3. Tools and Technologies Used

* Programming Language: Python 3
* Library: Scapy
* Operating System: Windows
* Code Editor: Visual Studio Code
* Packet Capture Driver: Npcap

---

## 4. System Requirements

* Python installed on the system
* Scapy library installed using pip
* Npcap installed in WinPcap compatible mode
* Administrator privileges to capture packets

---

## 5. Code Implementation

```python
from scapy.all import sniff, IP

def packet_analyzer(packet):
    if IP in packet:
        print("=" * 50)
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")
        print(f"Protocol       : {packet[IP].proto}")
        print(f"Packet Length  : {len(packet)}")

print("Starting Network Sniffer...")
sniff(filter="ip", prn=packet_analyzer, count=20)
```

---

## 6. Code Explanation

* `from scapy.all import sniff, IP`
  Imports required functions and the IP layer from the Scapy library.

* `packet_analyzer(packet)`
  This function is called every time a packet is captured.

* `if IP in packet:`
  Checks whether the captured packet contains an IP layer.

* `packet[IP].src`
  Displays the source IP address of the packet.

* `packet[IP].dst`
  Displays the destination IP address of the packet.

* `packet[IP].proto`
  Shows the protocol number used in the packet.

* `len(packet)`
  Displays the total length of the packet.

* `sniff()` function
  Captures network packets. The `filter="ip"` ensures only IP packets are captured, and `count=20` limits the capture to 20 packets.

---

## 7. Output Description

When the program is executed, it starts capturing network packets and displays details for each packet such as:

* Source IP address
* Destination IP address
* Protocol used
* Packet length
* Source Port
* Destination Port

The program stops automatically after capturing 20 packets.

---

## 8. Ethical Considerations

Packet sniffing can be misused if performed on networks without permission. This project is strictly created for educational purposes and was tested only on a local system with proper authorization.

---

## 9. Conclusion

This task provided a practical understanding of how network sniffers work at a basic level. By using Python and Scapy, packet capture and analysis were successfully implemented. The project enhanced knowledge of networking concepts and ethical cybersecurity practices.

---

## 10. Final Outcome

The basic network sniffer was successfully developed and executed. The task helped in gaining hands-on experience with packet analysis and network monitoring using Python.
