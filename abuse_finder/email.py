from __future__ import unicode_literals

from dns.resolver import query, NoAnswer
from tldextract import extract

from .domain import domain_abuse


def email_abuse(email):
    email_domain = email.split('@')[1]
    results = domain_abuse(email_domain, registrant=True)

    if len(results['abuse']) == 0:
        alternative_domains = set()
        try:
            answers = query(email_domain, 'MX')
        except NoAnswer:
            answers = []

        for rdata in answers:
            parts = extract(str(rdata.exchange))
            if parts.registered_domain != email_domain and parts.registered_domain not in alternative_domains:
                alternative_domains.add(parts.registered_domain)

        for domain in alternative_domains:
            domain_results = domain_abuse(domain, registrant=True)
            results['raw'] += "\n{}\n{}\n".format(domain, domain_results['raw'])
            for key in ['names', 'abuse']:
                for value in domain_results[key]:
                    if value not in results[key]:
                        results[key].append(value)

    return results
