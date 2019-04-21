from __future__ import unicode_literals
from builtins import str

from ipwhois import IPWhois
from operator import itemgetter
from ipaddress import IPv4Network, IPv4Address
import re


def _get_abuse_emails(raw_whois):
    score = 0
    email_candidates = set()

    for line in raw_whois.splitlines():
        email_addresses = re.findall(r'[\w\.+-]+@[\w\.-]+', line)
        if email_addresses:
            abuse_references = line.count('abuse')

            if abuse_references == score:
                email_candidates = set(list(email_candidates) + email_addresses)
            elif abuse_references > score:
                email_candidates = set(email_addresses)
                score = abuse_references

    return list(email_candidates)


def _get_names(ip_address, parsed_whois):
    ip_address = IPv4Address(str(ip_address))
    names = []

    for network in parsed_whois['nets']:
        for cidr in network['cidr'].split(','):
            cidr = IPv4Network(cidr.strip())
            if ip_address in cidr and network['description']:
                names.append([cidr.prefixlen, network['description'].splitlines()[0]])
                break

    return [n[1] for n in sorted(names, key=itemgetter(0), reverse=True)]


def ip_abuse(ip_address):
    obj = IPWhois(ip_address)
    results = obj.lookup_whois(inc_raw=True)

    return {
        "value": ip_address,
        "names": _get_names(ip_address, results),
        "abuse": _get_abuse_emails(results['raw']),
        "raw": results['raw']
    }
