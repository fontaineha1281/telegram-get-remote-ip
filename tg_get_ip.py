import ipaddress
import netifaces
import requests
import argparse
import platform
import pyshark
import socket

# IP ranges for Telegram, Meta, Discord and X (Twitter)
EXCLUDED_NETWORKS = {
    'tele': ['91.108.13.0/24', '149.154.160.0/21', '149.154.160.0/22', '149.154.160.0/23', 
             '149.154.162.0/23', '149.154.164.0/22', '149.154.164.0/23', '149.154.166.0/23', 
             '149.154.168.0/22', '149.154.172.0/22', '185.76.151.0/24', '91.105.192.0/23', 
             '91.108.12.0/22', '91.108.16.0/22', '91.108.20.0/22', '91.108.4.0/22', 
             '91.108.56.0/22', '91.108.56.0/23', '91.108.58.0/23', '91.108.8.0/22', '95.161.64.0/20'],
    'meta': ['57.144.144.0/23', '163.70.158.0/24', '157.240.15.0/24', '157.240.7.0/24', 
             '157.240.235.0/24', '157.240.22.0/24', '157.240.199.0/24'],
    'discord': ['35.215.128.0/18', '35.215.183.0/24', '35.215.129.0/24', '35.215.131.0/24', 
                '35.215.149.0/24'],
    'X': ['54.255.128.0/17', '13.250.0.0/15']
}

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def get_my_ip():
    try:
        return requests.get('https://icanhazip.com').text.strip()
    except Exception as e:
        print(f"[!] Error fetching external IP: {e}")
        return None

def get_whois_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        hostname = get_hostname(ip)
        if hostname:
            print(f"[+] Hostname: {hostname}")
        return data
    except Exception as e:
        print(f"[!] Error fetching whois data: {e}")
        return None

def display_whois_info(data):
    """Display the fetched whois data."""
    if not data:
        return
    
    print(f"[!] Country: {data.get('country', 'N/A')}")
    print(f"[!] Country Code: {data.get('countryCode', 'N/A')}")
    print(f"[!] Region: {data.get('region', 'N/A')}")
    print(f"[!] Region Name: {data.get('regionName', 'N/A')}")
    print(f"[!] City: {data.get('city', 'N/A')}")
    print(f"[!] Zip Code: {data.get('zip', 'N/A')}")
    print(f"[!] Latitude: {data.get('lat', 'N/A')}")
    print(f"[!] Longitude: {data.get('lon', 'N/A')}")
    print(f"[!] Time Zone: {data.get('timezone', 'N/A')}")
    print(f"[!] ISP: {data.get('isp', 'N/A')}")
    print(f"[!] Organization: {data.get('org', 'N/A')}")
    print(f"[!] AS: {data.get('as', 'N/A')}")


def is_excluded_ip(ip, app):
    for network in EXCLUDED_NETWORKS.get(app, []):
        if ipaddress.ip_address(ip) in ipaddress.ip_network(network):
            return True
    return False

def is_local_ip(ip):
    ip_addr = ipaddress.ip_address(ip)
    return ip_addr.is_private or ip_addr.is_loopback

def extract_stun_xor_mapped_address(interface, app):
    print("[+] Capturing traffic, please wait...")
    if platform.system() == "Windows":
        interface = "\\Device\\NPF_" + interface
    cap = pyshark.LiveCapture(interface=interface, display_filter="stun")
    my_ip = get_my_ip()
    resolved = {}
    whois = {}

    for packet in cap.sniff_continuously(packet_count=999999):
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            if is_excluded_ip(src_ip, app) or is_excluded_ip(dst_ip, app):
                continue
            if src_ip not in resolved:
                resolved[src_ip] = f"{src_ip}({get_hostname(src_ip)})"
            if dst_ip not in resolved:
                resolved[dst_ip] = f"{dst_ip}({get_hostname(dst_ip)})"
            if src_ip not in whois:
                whois[src_ip] = get_whois_info(src_ip)
            if dst_ip not in whois:
                whois[dst_ip] = get_whois_info(dst_ip)
            if packet.stun:
                xor_mapped_address = packet.stun.get_field_value('stun.att.ipv4')
                xor_mapped_user = packet.stun.get_field_value('stun.att.username')
                print(f"[+] Found STUN packet: {resolved[src_ip]} ({whois[src_ip].get('org', 'N/A')}) -> ({resolved[dst_ip]} {whois[dst_ip].get('org', 'N/A')}). it's xor_mapped_address: {xor_mapped_address}")
                if xor_mapped_address and not is_local_ip(xor_mapped_address):
                    if xor_mapped_address != my_ip:
                        return xor_mapped_address, xor_mapped_user if xor_mapped_user else None
    return None

def choose_interface():
    interfaces = netifaces.interfaces()
    print("[+] Available interfaces:")
    for idx, iface in enumerate(interfaces, 1):
        print(f"{idx}. {iface}")
        try:
            ip_address = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
            print(f"[+] Selected interface: {iface} IP address: {ip_address}")
        except KeyError:
            print("[!] Unable to retrieve IP address for the selected interface.")
    choice = int(input("[+] Enter the number of the interface you want to use: "))
    return interfaces[choice - 1]

def main():
    parser = argparse.ArgumentParser(description="Retrieve IP address of a peer on supported platforms.")
    #Parser argument choose the app
    parser.add_argument('app', choices=EXCLUDED_NETWORKS.keys(), help="Choose the app (e.g., tele, meta (Messenger, Instagram), discord, X)")
    args = parser.parse_args()
    app = args.app

    try:
        interface_name = choose_interface()
        result = extract_stun_xor_mapped_address(interface_name, app)
        if result:
            xor_mapped_address, xor_mapped_user = result
            print(f"[+] SUCCESS! IP Address: {xor_mapped_address}, User: {xor_mapped_user}")
            whois_data = get_whois_info(xor_mapped_address)
            display_whois_info(whois_data)
        else:
            print("[!] Couldn't determine the IP address of the peer.")
    except (KeyboardInterrupt, EOFError):
        print("\n[+] Exiting gracefully...")

if __name__ == "__main__":
    main()
