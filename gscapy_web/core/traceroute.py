import logging
import socket
import time
import json
from typing import Iterator, Dict, Any

from scapy.all import sr1, IP, UDP, ICMP

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_traceroute(target: str, max_hops: int = 30, timeout: int = 2) -> Iterator[Dict[str, Any]]:
    """
    Performs a traceroute to a target host and yields the result for each hop.

    Args:
        target: The IP address or hostname of the target.
        max_hops: The maximum number of hops to trace.
        timeout: The timeout in seconds for each probe.

    Yields:
        A dictionary for each hop containing 'hop', 'ip', 'hostname', and 'rtt_ms'.
    """
    try:
        dest_ip = socket.gethostbyname(target)
        logging.info(f"Starting traceroute to {target} ({dest_ip})")
        yield {"type": "status", "message": f"Traceroute to {target} ({dest_ip})"}
    except socket.gaierror:
        logging.error(f"Cannot resolve hostname: {target}")
        yield {"type": "error", "message": f"Cannot resolve hostname: {target}"}
        return

    for i in range(1, max_hops + 1):
        pkt = IP(dst=dest_ip, ttl=i) / UDP(dport=33434) # Classic UDP probe
        start_time = time.time()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        rtt_ms = (time.time() - start_time) * 1000

        hop_result = {"hop": i, "ip": "*", "hostname": "Timeout", "rtt_ms": None}

        if reply is None:
            # Timeout
            pass
        else:
            hop_ip = reply.src
            hop_result["ip"] = hop_ip
            hop_result["rtt_ms"] = f"{rtt_ms:.2f}"
            try:
                # Attempt to resolve the hostname
                hop_hostname, _, _ = socket.gethostbyaddr(hop_ip)
                hop_result["hostname"] = hop_hostname
            except socket.herror:
                hop_result["hostname"] = "Unknown"

            # Check if we've reached the destination
            if reply.type == 3 and reply.code == 3: # ICMP Port Unreachable
                yield {"type": "hop", "data": hop_result}
                logging.info(f"Traceroute complete: Reached destination {hop_ip}")
                yield {"type": "status", "message": "Trace Complete."}
                return
            elif reply.type == 11 and reply.code == 0: # ICMP TTL Exceeded
                pass # This is the expected response for an intermediate hop

        yield {"type": "hop", "data": hop_result}
        logging.info(f"Hop {i}: {hop_result['ip']} ({hop_result['hostname']})")

        # If we got a reply from the destination IP, we are done.
        if reply and reply.src == dest_ip:
            logging.info(f"Traceroute complete: Reached destination {dest_ip}")
            yield {"type": "status", "message": "Trace Complete."}
            return

    logging.info("Traceroute finished: Max hops reached.")
    yield {"type": "status", "message": "Finished (Max hops reached)."}
