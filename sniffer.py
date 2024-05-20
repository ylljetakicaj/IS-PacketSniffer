import argparse
from utils.packet_utils import start_sniffer
from gui.sniffer_gui import start_gui

def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument('--mode', choices=['text', 'gui'], required=True, help="Mode to run the sniffer in")

    args = parser.parse_args()

    if args.mode == 'text':
        start_sniffer()
    elif args.mode == 'gui':
        start_gui()

if __name__ == "__main__":
    main()
