import socket
import struct
import argparse
import logging
import sys
import time
import pcapy  # If pcapy is not available, consider alternatives like scapy
import dpkt  # For packet parsing

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Captures network packets and saves them to a PCAP file.")
    parser.add_argument("-i", "--interface", dest="interface", default="eth0", help="Network interface to capture packets from (default: eth0)")
    parser.add_argument("-o", "--output", dest="output_file", default="capture.pcap", help="Output PCAP file (default: capture.pcap)")
    parser.add_argument("-p", "--port", dest="port", type=int, help="Filter packets by port number")
    parser.add_argument("-proto", "--protocol", dest="protocol", help="Filter packets by protocol (e.g., tcp, udp, icmp)")
    parser.add_argument("-src", "--source", dest="source_ip", help="Filter packets by source IP address")
    parser.add_argument("-dst", "--destination", dest="destination_ip", help="Filter packets by destination IP address")
    parser.add_argument("-n", "--number", dest="packet_number", type=int, default=0, help="Number of packets to capture (default: 0, capture until interrupted)")
    parser.add_argument("--promisc", dest="promiscuous", action="store_true", help="Enable promiscuous mode")
    parser.add_argument("--timeout", dest="timeout", type=int, default=100, help="Timeout in milliseconds")
    return parser.parse_args()

def validate_args(args):
    """
    Validates the command-line arguments.
    """
    if args.port is not None and (args.port < 0 or args.port > 65535):
        logging.error("Invalid port number. Port must be between 0 and 65535.")
        return False

    if args.protocol and args.protocol.lower() not in ["tcp", "udp", "icmp"]:
        logging.warning("Specified Protocol will still be used, but is not standard. Continuing...")
        # Consider logging this as a warning if non-standard protocols are accepted.

    return True


def capture_packets(interface, output_file, port=None, protocol=None, source_ip=None, destination_ip=None, packet_number=0, promisc=False, timeout=100):
    """
    Captures network packets based on specified criteria and saves them to a PCAP file.
    """
    try:
        # Create a PCAP dumper to write the packets to a file.
        pcap_dumper = pcapy.open_dead(1500, dpkt.datalink.DLT_EN10MB) # DLT_EN10MB = Ethernet
        dumper = pcap_dumper.dump_open(output_file)

        # Open the live capture
        cap = pcapy.open_live(interface, 65536, promisc, timeout)

        packet_count = 0

        def packet_handler(header, data):
            nonlocal packet_count
            try:
                # Parse ethernet header (to support IP packet parsing)
                eth = dpkt.ethernet.Ethernet(data)

                # Filter by IP, if it's not an IP packet skip filtering and store
                if not isinstance(eth.data, dpkt.ip.IP):
                    logging.debug("Non-IP Packet, Skipping IP-based filters")

                    # Check port before writing to file, we want to check if the traffic has a port
                    if port:
                        logging.debug("Port filtering enabled but no IP traffic found.")
                        return  # Skip saving if port filter exists but no IP

                    dumper.dump(header, data)  # Store everything even if non-IP
                    packet_count += 1
                    return

                ip = eth.data

                # Filter by source IP
                if source_ip and socket.inet_ntoa(ip.src) != source_ip:
                    return

                # Filter by destination IP
                if destination_ip and socket.inet_ntoa(ip.dst) != destination_ip:
                    return

                # Filter by protocol
                if protocol:
                    proto_lower = protocol.lower()
                    if proto_lower == "tcp" and not isinstance(ip.data, dpkt.tcp.TCP):
                        return
                    elif proto_lower == "udp" and not isinstance(ip.data, dpkt.udp.UDP):
                        return
                    elif proto_lower == "icmp" and not isinstance(ip.data, dpkt.icmp.ICMP):
                        return
                    else: # User specified protocol but it does not match
                        logging.debug("Packet Protocol: %s, Filter Protocol: %s", type(ip.data).__name__, protocol)


                # Filter by port
                if port:
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        if ip.data.sport != port and ip.data.dport != port:
                            return
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        if ip.data.sport != port and ip.data.dport != port:
                            return
                    else: # We do not have a TCP or UDP packet!
                        logging.debug("Port specified but this is not TCP or UDP Packet, skipping")
                        return # Do not save the packet


                dumper.dump(header, data)  # Write the packet to the PCAP file
                packet_count += 1

                if packet_number > 0 and packet_count >= packet_number:
                    logging.info(f"Captured {packet_count} packets. Stopping capture.")
                    sys.exit(0)

            except Exception as e:
                logging.error(f"Error processing packet: {e}")


        logging.info(f"Capturing packets on interface {interface}, saving to {output_file}")
        if packet_number > 0:
            logging.info(f"Capturing {packet_number} packets.")
        else:
            logging.info("Capturing packets until interrupted (Ctrl+C).")
        if port:
            logging.info(f"Filtering by Port: {port}")
        if protocol:
            logging.info(f"Filtering by Protocol: {protocol}")
        if source_ip:
            logging.info(f"Filtering by Source IP: {source_ip}")
        if destination_ip:
            logging.info(f"Filtering by Destination IP: {destination_ip}")

        cap.loop(0, packet_handler)  # 0 means loop forever until interrupted

    except pcapy.PcapError as e:
        logging.error(f"Error opening interface: {e}.  Ensure you have sufficient permissions (e.g., run as root).")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        try:
            dumper.close() # Close the pcap file writer.
        except:
            pass # Already closed, or never opened


def main():
    """
    Main function to parse arguments and initiate packet capture.
    """
    args = setup_argparse()

    if not validate_args(args):
        sys.exit(1)

    try:
        capture_packets(
            interface=args.interface,
            output_file=args.output_file,
            port=args.port,
            protocol=args.protocol,
            source_ip=args.source_ip,
            destination_ip=args.destination_ip,
            packet_number=args.packet_number,
            promisc=args.promiscuous,
            timeout=args.timeout
        )
    except KeyboardInterrupt:
        logging.info("Packet capture stopped by user.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":

    # Example usage 1: Capture all packets on eth0 and save to capture.pcap
    # python net_packet_capture.py

    # Example usage 2: Capture packets on eth0 filtered by port 80 and save to capture.pcap
    # python net_packet_capture.py -p 80

    # Example usage 3: Capture packets on eth0 filtered by TCP protocol and save to capture.pcap
    # python net_packet_capture.py -proto tcp

    # Example usage 4: Capture 100 packets on wlan0 filtered by source IP 192.168.1.100 and save to output.pcap
    # python net_packet_capture.py -i wlan0 -src 192.168.1.100 -n 100 -o output.pcap

    main()