# Introduction
This project is a simple packet sniffer implemented in Python. A packet sniffer is a tool used to capture and analyze packets of data as they are transmitted across a network. This tool can be used for network troubleshooting, security monitoring, and educational purposes to understand network protocols.

# Features
- Capture packets from a specified network interface
- Display packet details such as source and destination IP addresses, protocol, and payload
- Filter packets by protocol (e.g., TCP, UDP, ICMP)
- Save captured packets to a file for later analysis
- Run in text mode for console-based operation
- Run in GUI mode for a graphical user interface

# Requirements
- Python 3.x
- scapy library (for packet capturing and manipulation)
- argparse library (for command-line argument parsing)
- tkinter library (for GUI mode)
  
# Additional Files
 ``` sniffer.py ```
This is the main file to run the packet sniffer. It supports both text and GUI modes. Depending on the mode specified, it either starts capturing packets and displaying them in the console or opens a graphical user interface for capturing and displaying packets.

``` utils/packet_utils.py ```
Contains utility functions related to packet capturing and processing. The start_sniffer function initializes the packet sniffer in text mode.

``` gui/sniffer_gui.py ```
Contains functions for setting up and running the graphical user interface. The start_gui function initializes the packet sniffer in GUI mode.

# Usage
To run the packet sniffer, execute the following command in your terminal:
``` python sniffer.py --mode <mode> ```

--mode: Mode to run the sniffer in (text for console-based, gui for graphical user interface)
