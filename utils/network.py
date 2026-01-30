#!/usr/bin/env python3
"""
Network utilities for the ICS Scanner.
Provides functions for IP address handling and port scanning.
"""

import socket
import ipaddress
import concurrent.futures
from tqdm import tqdm

def parse_target_input(target_input):
    """
    Parse target input string into a list of IP addresses.
    Supports single IP, IP range (CIDR notation), and comma-separated IPs.
    
    Args:
        target_input (str): Target string (e.g., '192.168.1.1', '192.168.1.0/24', '192.168.1.1-10')
        
    Returns:
        list: List of IP address objects
    """
    targets = []
    
    # Check if it's a comma-separated list
    if ',' in target_input:
        for part in target_input.split(','):
            targets.extend(parse_target_input(part.strip()))
        return targets
    
    # Check if it's a range with dash notation (192.168.1.1-10)
    if '-' in target_input and '/' not in target_input:
        try:
            start, end = target_input.rsplit('-', 1)
            
            # If the start contains dots, it's an IP
            if '.' in start:
                ip_parts = start.split('.')
                prefix = '.'.join(ip_parts[:-1]) + '.'
                start_num = int(ip_parts[-1])
                end_num = int(end)
                
                for i in range(start_num, end_num + 1):
                    ip = prefix + str(i)
                    targets.append(ipaddress.ip_address(ip))
                
                return targets
        except (ValueError, IndexError):
            raise ValueError(f"Invalid IP range format: {target_input}")
    
    # Check if it's a CIDR network
    try:
        network = ipaddress.ip_network(target_input, strict=False)
        # If it's a single IP with /32 (IPv4) or /128 (IPv6), just return that IP
        if network.num_addresses == 1:
            return [network.network_address]
        
        # Otherwise, return all hosts in the network
        return list(network.hosts())
    except ValueError:
        # Not a network, try as a single IP
        try:
            return [ipaddress.ip_address(target_input)]
        except ValueError:
            # Try to resolve hostname to IP
            try:
                ip = socket.gethostbyname(target_input)
                return [ipaddress.ip_address(ip)]
            except socket.gaierror:
                raise ValueError(f"Invalid target format: {target_input}")

def check_port(ip, port, timeout=1):
    """
    Check if a port is open on a host.
    
    Args:
        ip (str): IP address
        port (int): Port number
        timeout (int): Connection timeout in seconds
        
    Returns:
        tuple: (port, is_open)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((str(ip), port))
    sock.close()
    return (port, result == 0)

def port_scan(ip, port_range, timeout=1, max_workers=100):
    """
    Scan a range of ports on a host.
    
    Args:
        ip (str): IP address
        port_range (str): Port range (e.g., '22-100', '22,23,80', '22,80-90')
        timeout (int): Connection timeout in seconds
        max_workers (int): Maximum number of threads for scanning
        
    Returns:
        list: List of open ports
    """
    ports_to_scan = []
    
    # Parse port range
    for part in port_range.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports_to_scan.extend(range(start, end + 1))
        else:
            ports_to_scan.append(int(part))
    
    open_ports = []
    
    # Scan ports in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(check_port, ip, port, timeout): port 
            for port in ports_to_scan
        }
        
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    
    return sorted(open_ports)

def get_service_name(port):
    """
    Get the service name for a port number.
    
    Args:
        port (int): Port number
        
    Returns:
        str: Service name or 'unknown'
    """
    try:
        return socket.getservbyport(port)
    except (socket.error, OSError):
        return 'unknown' 