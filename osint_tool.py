#!/usr/bin/env python3

import argparse
import requests
import socket
import whois
import dns.resolver
import subprocess
import re
import os

def banner():
    print("""
    ███████╗███████╗██████╗ ███████╗██████╗ 
    ██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗
    ███████╗███████╗██████╔╝█████╗  ██████╔╝
    ╚════██║╚════██║██╔══██╗██╔══╝  ██╔══██╗
    ███████║███████║██║  ██║███████╗██║  ██║
    ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    OSINT Tool for Termux
    """)

def get_ip_address(target):
    try:
        ip_address = socket.gethostbyname(target)
        return ip_address
    except socket.gaierror:
        return None

def get_whois_info(target):
    try:
        w = whois.whois(target)
        return w
    except whois.parser.PywhoisError as e:
        return str(e) #Handle whois errors gracefully.
    except Exception as e:
        return f"Error during WHOIS lookup: {e}"

def get_dns_records(target):
    dns_records = {}
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(target, record_type)
            dns_records[record_type] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            dns_records[record_type] = []
        except dns.resolver.NXDOMAIN:
            return "Domain does not exist."
        except dns.resolver.Timeout:
            return "DNS query timed out."
        except Exception as e:
            return f"Error during DNS lookup: {e}"

    return dns_records

def run_nmap(target, ports=None):
    if ports:
        command = f"nmap -p {ports} {target}"
    else:
        command = f"nmap {target}"

    try:
        result = subprocess.run(command.split(), capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Nmap error: {e.stderr}"
    except FileNotFoundError:
        return "Nmap is not installed. Please install it using 'pkg install nmap'"

def run_traceroute(target):
    try:
        result = subprocess.run(["traceroute", target], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Traceroute error: {e.stderr}"
    except FileNotFoundError:
        return "Traceroute is not installed. Please install it using 'pkg install traceroute'"

def get_geo_location(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        data = response.json()
        if data['status'] == 'success':
            return data
        else:
            return f"Geolocation lookup failed: {data['message']}"
    except requests.exceptions.RequestException as e:
        return f"Geolocation request error: {e}"
    except ValueError:
        return "Invalid JSON response from geolocation service."

def main():
    banner()
    parser = argparse.ArgumentParser(description="OSINT Tool for Termux")
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("-w", "--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("-d", "--dns", action="store_true", help="Perform DNS lookup")
    parser.add_argument("-n", "--nmap", nargs="?", const="1-1024", help="Perform Nmap scan (optional ports, default 1-1024)")
    parser.add_argument("-t", "--traceroute", action="store_true", help="Perform traceroute")
    parser.add_argument("-g", "--geo", action="store_true", help="Get geolocation information")

    args = parser.parse_args()

    ip_address = get_ip_address(args.target)

    if ip_address:
        print(f"IP Address: {ip_address}")
    else:
        print("Could not resolve IP address.")

    if args.whois:
        whois_info = get_whois_info(args.target)
        print("\nWHOIS Information:")
        print(whois_info)

    if args.dns:
        dns_records = get_dns_records(args.target)
        print("\nDNS Records:")
        if isinstance(dns_records, str):
            print(dns_records)
        else:
            for record_type, records in dns_records.items():
                print(f"{record_type} Records:")
                for record in records:
                    print(f"  {record}")

    if args.nmap:
        nmap_result = run_nmap(args.target, args.nmap)
        print("\nNmap Scan Results:")
        print(nmap_result)

    if args.traceroute:
        traceroute_result = run_traceroute(args.target)
        print("\nTraceroute Results:")
        print(traceroute_result)

    if args.geo and ip_address:
        geo_location = get_geo_location(ip_address)
        print("\nGeolocation Information:")
        if isinstance(geo_location, str):
            print(geo_location)
        else:
            for key, value in geo_location.items():
                print(f"{key}: {value}")

if __name__ == "__main__":
    main()