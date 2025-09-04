import logging
import urllib.request
from scapy.all import srp, Ether, ARP

def get_vendor(mac_address: str) -> str:
    """
    Retrieves the vendor for a given MAC address from an online API.
    A helper function moved here to make the core logic self-contained.
    """
    if not mac_address or mac_address == "N/A":
        return "N/A"
    try:
        with urllib.request.urlopen(f"https://api.macvendors.com/{mac_address}", timeout=3) as url:
            data = url.read().decode()
            return data
    except Exception as e:
        logging.warning(f"Could not retrieve vendor for MAC {mac_address}: {e}")
        return "Unknown Vendor"

def run_arp_scan(target_network: str, iface: str = None, stop_event=None):
    """
    Performs an ARP scan on the given network and returns a list of found hosts.

    Args:
        target_network: The target network in CIDR notation (e.g., "192.168.1.0/24").
        iface: The network interface to use for the scan.
        stop_event: An optional threading.Event to allow for cancellation (not used in
                    this blocking version but kept for API consistency).

    Returns:
        A list of dictionaries, where each dict represents a host.
        Example: [{'ip': '192.168.1.1', 'mac': 'A1:B2:C3:D4:E5:F6', 'vendor': 'Dell Inc.'}]
        Returns an empty list if an error occurs.
    """
    logging.info(f"ARP scan started for target: {target_network} on iface: {iface}")
    results = []
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_network)

        # The srp function returns two lists: answered and unanswered packets.
        answered, _ = srp(packet, timeout=2, iface=iface, verbose=0)

        if answered:
            for sent_pkt, received_pkt in answered:
                host_info = {
                    'ip': received_pkt.psrc,
                    'mac': received_pkt.hwsrc,
                    'vendor': get_vendor(received_pkt.hwsrc)
                }
                results.append(host_info)
                logging.info(f"Found host: {host_info}")

        logging.info(f"ARP scan complete. Found {len(results)} active hosts.")
        return results

    except Exception as e:
        logging.error(f"An exception occurred during ARP scan: {e}", exc_info=True)
        return []
