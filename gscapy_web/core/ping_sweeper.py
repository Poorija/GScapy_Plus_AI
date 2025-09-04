import logging
import ipaddress
import queue
import threading
from typing import List, Dict, Any

from scapy.all import sr1, IP, ICMP, TCP, UDP

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s')

def _ping_sweep_worker(
    hosts_queue: queue.Queue,
    results_queue: queue.Queue,
    probe_type: str,
    ports: List[int],
    timeout: int
):
    """
    Worker function executed by each thread to perform the ping sweep on a subset of hosts.
    """
    while not hosts_queue.empty():
        try:
            host_str = hosts_queue.get_nowait()
        except queue.Empty:
            break

        logging.info(f"Pinging {host_str}...")
        reply = None
        try:
            if probe_type == "ICMP Echo":
                pkt = IP(dst=host_str) / ICMP()
                reply = sr1(pkt, timeout=timeout, verbose=0)
            elif probe_type == "TCP SYN":
                # For TCP/UDP, we only need one port to reply to confirm the host is up
                for port in ports:
                    pkt = IP(dst=host_str) / TCP(dport=port, flags="S")
                    reply = sr1(pkt, timeout=timeout, verbose=0)
                    if reply and reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x12:  # SYN-ACK
                        break
            elif probe_type == "TCP ACK":
                for port in ports:
                    pkt = IP(dst=host_str) / TCP(dport=port, flags="A")
                    reply = sr1(pkt, timeout=timeout, verbose=0)
                    if reply and reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x4:  # RST
                        break
            elif probe_type == "UDP Probe":
                for port in ports:
                    pkt = IP(dst=host_str) / UDP(dport=port)
                    reply = sr1(pkt, timeout=timeout, verbose=0)
                    # An ICMP "port unreachable" proves the host is up
                    if reply and reply.haslayer(ICMP) and reply.getlayer(ICMP).type == 3:
                        break

            if reply:
                results_queue.put({"ip": host_str, "status": "Host is up"})

        except Exception as e:
            logging.warning(f"Probe to {host_str} failed: {e}")
        finally:
            hosts_queue.task_done()

def run_ping_sweep(
    target_network: str,
    probe_type: str = "ICMP Echo",
    ports: List[int] = None,
    timeout: int = 1,
    num_threads: int = 20
) -> List[Dict[str, Any]]:
    """
    Performs a ping sweep on a target network to discover active hosts.

    Args:
        target_network: The network to scan in CIDR notation (e.g., "192.168.1.0/24").
        probe_type: The type of probe to use ("ICMP Echo", "TCP SYN", "TCP ACK", "UDP Probe").
        ports: A list of ports to use for TCP/UDP probes.
        timeout: The timeout in seconds for each probe.
        num_threads: The number of concurrent threads to use.

    Returns:
        A list of dictionaries, each representing an active host.
    """
    if ports is None:
        ports = [80, 443] # Default ports if none are provided for TCP/UDP scans

    try:
        network = ipaddress.ip_network(target_network, strict=False)
    except ValueError:
        logging.error(f"Invalid target network format: {target_network}")
        return []

    hosts_queue = queue.Queue()
    for host in network.hosts():
        hosts_queue.put(str(host))

    if hosts_queue.qsize() == 0:
        logging.info("No hosts to scan in the specified range.")
        return []

    results_queue = queue.Queue()
    threads = []

    for _ in range(num_threads):
        thread = threading.Thread(
            target=_ping_sweep_worker,
            args=(hosts_queue, results_queue, probe_type, ports, timeout),
            daemon=True
        )
        threads.append(thread)
        thread.start()

    # Wait for all hosts to be processed
    hosts_queue.join()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Collect results
    results = []
    while not results_queue.empty():
        results.append(results_queue.get_nowait())

    logging.info(f"Ping sweep finished. Found {len(results)} active hosts.")
    return sorted(results, key=lambda x: ipaddress.ip_address(x['ip']))
