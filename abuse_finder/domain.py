from __future__ import print_function,unicode_literals

from pythonwhois.net import get_whois_raw
from pythonwhois.parse import parse_raw_whois
from tldextract import extract


def _get_registrant_abuse(domain, parsed_whois):
    names = []
    emails = []

    if 'contacts' in parsed_whois:
        if 'registrant' in parsed_whois['contacts'] and parsed_whois['contacts']['registrant']:
            if 'organization' in parsed_whois['contacts']['registrant'] and parsed_whois['contacts']['registrant']['organization']:
                names.append(parsed_whois['contacts']['registrant']['organization'])
            elif 'name' in parsed_whois['contacts']['registrant'] and parsed_whois['contacts']['registrant']['name']:
                names.append(parsed_whois['contacts']['registrant']['name'])

        for _, contact in parsed_whois['contacts'].items():
            if contact and 'email' in contact and 'abuse' in contact['email']:
                emails.append(contact['email'])

    return {
        "value": domain,
        "names": names,
        "abuse": emails
    }


def _get_registrar_abuse(domain, parsed_whois):
    names = []
    emails = []

    if 'registrar' in parsed_whois:
        names = parsed_whois['registrar']

    if 'emails' in parsed_whois:
        emails = parsed_whois['emails']

    return {
        "value": domain,
        "names": names,
        "abuse": emails
    }


def domain_abuse(domain, registrant=False):
    parts = extract(domain)
    domain = parts.registered_domain

    try:
        data = get_whois_raw(domain)
        parsed = parse_raw_whois(data, ['Domain', 'contacts'])
    except Exception as e:
        print("Could not get WHOIS for {} ({})".format(domain, e))

        return {
            "value": domain,
            "names": [],
            "abuse": [],
            "raw": ""
        }

    if registrant:
        results = _get_registrant_abuse(domain, parsed)
    else:
        results = _get_registrar_abuse(domain, parsed)

    results['raw'] = "\n\n".join(data)

    return results
