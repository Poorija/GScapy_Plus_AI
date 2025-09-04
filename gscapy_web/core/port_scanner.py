import socket
import logging
from scapy.all import sr1, IP, TCP, UDP, ICMP
from scapy.layers.inet import fragment

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def _parse_ports(ports_str: str) -> list[int]:
    """Parses a string of ports (e.g., '22,80,100-200') into a list of integers."""
    ports = set()
    if not ports_str:
        return []
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if start > end:
                    start, end = end, start
                ports.update(range(start, end + 1))
            except ValueError:
                logging.warning(f"Invalid port range: {part}")
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                logging.warning(f"Invalid port number: {part}")
                continue
    return sorted(list(ports))

def scan_ports(target: str, ports_str: str, scan_type: str = "TCP SYN Scan", timeout: int = 1, use_fragments: bool = False):
    """
    Performs a port scan on a given target.

    Args:
        target: The IP address or hostname of the target.
        ports_str: A comma-separated string of ports or port ranges (e.g., "22,80,443,1000-2000").
        scan_type: The type of scan to perform. Options:
                   "TCP SYN Scan", "TCP FIN Scan", "TCP Xmas Scan", "TCP Null Scan",
                   "TCP ACK Scan", "UDP Scan".
        timeout: The timeout in seconds for each probe.
        use_fragments: Whether to send fragmented packets.

    Returns:
        A list of dictionaries, where each dictionary represents a scanned port
        and contains 'port', 'protocol', 'state', and 'service' keys.
    """
    scan_results = []
    ports = _parse_ports(ports_str)
    if not ports:
        logging.error("No valid ports specified for scanning.")
        return []

    logging.info(f"Starting port scan on {target} for ports: {ports_str} ({scan_type})")

    protocol = "udp" if "UDP" in scan_type else "tcp"

    tcp_scan_flags = {
        "TCP SYN Scan": "S",
        "TCP FIN Scan": "F",
        "TCP Xmas Scan": "FPU",
        "TCP Null Scan": "",
        "TCP ACK Scan": "A"
    }

    for port in ports:
        pkt = None
        if protocol == "tcp":
            flags = tcp_scan_flags.get(scan_type, "S")
            pkt = IP(dst=target) / TCP(dport=port, flags=flags)
        elif protocol == "udp":
            pkt = IP(dst=target) / UDP(dport=port)

        if not pkt:
            continue

        probes = fragment(pkt) if use_fragments else [pkt]
        # Send the first probe (or the only one if not fragmented)
        resp = sr1(probes[0], timeout=timeout, verbose=0)

        state = "No Response / Filtered"
        if resp:
            if resp.haslayer(TCP):
                tcp_layer = resp.getlayer(TCP)
                if tcp_layer.flags == 0x12:  # SYN-ACK
                    state = "Open"
                elif tcp_layer.flags == 0x14:  # RST-ACK
                    state = "Closed"
                elif tcp_layer.flags == 0x4: # RST from ACK scan
                    state = "Unfiltered (RST)"
            elif resp.haslayer(UDP):
                # If we get any response for a UDP probe, the port is likely open.
                # A lack of response could mean open or filtered.
                # An ICMP Port Unreachable means closed.
                state = "Open | Filtered"
            elif resp.haslayer(ICMP):
                icmp_layer = resp.getlayer(ICMP)
                if icmp_layer.type == 3:  # Destination Unreachable
                    if icmp_layer.code == 3: # Port Unreachable
                        state = "Closed"
                    elif icmp_layer.code in [1, 2, 9, 10, 13]:
                        state = "Filtered"

        service = "unknown"
        if state == "Open":
            try:
                service = socket.getservbyport(port, protocol)
            except OSError:
                service = "unknown"

        result = {
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": service
        }
        scan_results.append(result)
        logging.info(f"Result for {target}:{port} ({protocol}) -> {state}")

    logging.info(f"Port scan on {target} finished.")
    return scan_results
