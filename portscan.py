
### portscan.py

```python
#!/usr/bin/env python3
"""
portscan - Fast port scanner with banner grabbing
Pure Python, zero dependencies.
"""

import socket
import argparse
import sys
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MS-RPC', 139: 'NetBIOS',
    143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 5984: 'CouchDB',
    6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
    9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB',
}

PROBES = {
    21: None,       # FTP sends banner on connect
    22: None,       # SSH sends banner on connect
    25: b'EHLO scan\r\n',
    80: b'GET / HTTP/1.0\r\nHost: scan\r\n\r\n',
    110: None,      # POP3 sends banner on connect
    143: None,      # IMAP sends banner on connect
    443: None,      # TLS - skip
    8080: b'GET / HTTP/1.0\r\nHost: scan\r\n\r\n',
    8443: None,     # TLS - skip
    3306: None,     # MySQL sends banner on connect
    6379: b'INFO\r\n',
    27017: None,    # MongoDB binary protocol
}


def scan_port(host, port, timeout):
    """Scan a single TCP port and grab banner if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                banner = grab_banner(s, port)
                return port, True, banner
            return port, False, None
    except socket.gaierror:
        return port, False, None
    except socket.timeout:
        return port, False, None
    except OSError:
        return port, False, None


def grab_banner(sock, port):
    """Attempt to grab service banner from connected socket."""
    try:
        sock.settimeout(1.5)

        # First try: some services send banner on connect
        probe = PROBES.get(port, b'')
        if probe is None:
            # TLS or binary protocol - just try a connect-time recv
            try:
                data = sock.recv(1024)
                if data:
                    return data.decode('utf-8', errors='ignore').strip()[:200]
            except (socket.timeout, OSError):
                return None

        # For services that need a probe: send then recv
        if probe:
            try:
                sock.sendall(probe)
            except OSError:
                pass

        try:
            data = sock.recv(1024)
            if data:
                return data.decode('utf-8', errors='ignore').strip()[:200]
        except (socket.timeout, OSError):
            pass

        return None
    except Exception:
        return None


def scan_host(host, ports, threads=100, timeout=1.0, verbose=False):
    """Scan multiple ports on a host."""
    open_ports = []
    start = time.time()

    print(f"[*] Scanning {host}")
    print(f"[*] Ports: {len(ports)}")
    print(f"[*] Threads: {threads}")
    print(f"[*] Timeout: {timeout}s")
    print()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        completed = 0
        for future in as_completed(futures):
            completed += 1
            port, is_open, banner = future.result()
            if is_open:
                service = COMMON_PORTS.get(port, 'unknown')
                banner_str = banner[:60] if banner else ''
                print(f"[+] {port:>6}/tcp  open  {service:<16} {banner_str}")
                open_ports.append({
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'banner': banner
                })
            if verbose and completed % 1000 == 0:
                elapsed = time.time() - start
                rate = completed / elapsed if elapsed > 0 else 0
                print(f"[*] Progress: {completed}/{len(ports)} ({rate:.0f}/s)")

    elapsed = time.time() - start
    print(f"\n[*] Scan complete in {elapsed:.2f}s")
    print(f"[*] Open ports: {len(open_ports)}")

    return open_ports


def main():
    parser = argparse.ArgumentParser(
        description='portscan - Fast port scanner with banner grabbing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python portscan.py 192.168.1.1
  python portscan.py 192.168.1.1 --ports 1-1000
  python portscan.py 192.168.1.1 --all-ports
  python portscan.py 192.168.1.1 -t 200 --timeout 0.5
  python portscan.py 192.168.1.1 -o results.json
        """
    )

    parser.add_argument('host', help='Target host to scan')
    parser.add_argument('--ports', default='common',
                        help='Port range (e.g. 1-1000) or "common" (default: common)')
    parser.add_argument('--all-ports', action='store_true', help='Scan all 65535 ports')
    parser.add_argument('-t', '--threads', type=int, default=100,
                        help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='Connection timeout in seconds (default: 1.0)')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Resolve hostname
    try:
        ip = socket.gethostbyname(args.host)
        if ip != args.host:
            print(f"[*] Resolved: {args.host} -> {ip}")
    except socket.gaierror:
        print(f"[-] Cannot resolve host: {args.host}")
        sys.exit(1)

    # Parse ports
    if args.all_ports:
        ports = list(range(1, 65536))
    elif args.ports == 'common':
        ports = sorted(COMMON_PORTS.keys())
    else:
        try:
            if '-' in args.ports:
                parts = args.ports.split('-', 1)
                start_p = int(parts[0])
                end_p = int(parts[1])
                ports = list(range(start_p, end_p + 1))
            else:
                ports = [int(args.ports)]
        except ValueError:
            print(f"[-] Invalid port range: {args.ports}")
            sys.exit(1)

    # Validate ports
    for p in ports:
        if p < 1 or p > 65535:
            print(f"[-] Invalid port number: {p}")
            sys.exit(1)

    # Run scan
    results = scan_host(args.host, ports, args.threads, args.timeout, args.verbose)

    # Save results
    if args.output:
        output = {
            'host': args.host,
            'ip': ip,
            'open_ports': results,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"[*] Results saved to {args.output}")


if __name__ == '__main__':
    main()
