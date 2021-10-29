from __future__ import unicode_literals
from builtins import str

from ipwhois import IPWhois
from operator import itemgetter
from ipaddress import ip_network, ip_address
import re

abuse_terms = [
    'abuse',
    'OrgNOCEmail',
]

def _get_abuse_emails(raw_whois):
    score = 0
    email_candidates = set()

    for line in raw_whois.splitlines():
        email_addresses = re.findall(r'[\w\.+-]+@[\w-]+(?:\.[\w-]+)+', line)
        if email_addresses:
            abuse_references = sum(line.count(term) for term in abuse_terms)

            if abuse_references == score:
                email_candidates = set(list(email_candidates) + email_addresses)
            elif abuse_references > score:
                email_candidates = set(email_addresses)
                score = abuse_references

    return list(email_candidates)


def _get_names(address, parsed_whois):
    address = ip_address(str(address))
    names = []

    for network in parsed_whois['nets']:
        for cidr in network['cidr'].split(','):
            cidr = ip_network(cidr.strip())
            if address in cidr and network['description']:
                names.append([cidr.prefixlen, network['description'].splitlines()[0]])
                break

    return [n[1] for n in sorted(names, key=itemgetter(0), reverse=True)]


def ip_abuse(address):
    obj = IPWhois(address)
    results = obj.lookup_whois(inc_raw=True)

    return {
        "value": address,
        "names": _get_names(address, results),
        "abuse": _get_abuse_emails(results['raw']),
        "raw": results['raw']
    }
