# abuse_finder

Python library to help automatically find the most appropriate contact for abuse reports.
Supports Python2.7 and Python3.6

Currently supports the following types of observables:

* Hostnames
* IP addresses
* URLs
* Email addresses

## Installation

You can install this using pip:

    $ pip install abuse_finder

Or from the source code:

    $ git clone https://github.com/certsocietegenerale/abuse_finder.git
    $ cd abuse_finder
    $ python setup.py install
    
## Usage

This library provides a function for each kind of supported observable: `domain_abuse`, `ip_abuse`, `url_abuse` and `email_abuse`.

All functions are similar, they are taking a single argument, which is a string containing the observable's value, and return a dict containing the following elements:

* `value`: value of the observable
* `names`: a list of guesses for the names of the organizations that should be contacted to report abuse
* `abuse`: a list of guesses of email addresses to contact to report abuse
* `raw`: raw data containing information used to make theses guesses (whois / network whois)

## Example

    >>> from abuse_finder import domain_abuse
    >>> domain_abuse('github.com')
    
    {
      u'value': 'github.com',
      u'abuse': [u'abusecomplaints@markmonitor.com'],
      u'names': [u'MarkMonitor, Inc.'],
      u'raw': u"Domain Name: github.com\nRegistry Domain ID: 1264983250_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar URL: http://www.markmonitor.com\nUpdated Date: 2016-10-21T13:15:27-0700\nCreation Date: 2007-10-09T11:20:50-0700\nRegistrar Registration Expiration Date: 2020-10-09T11:20:50-0700\nRegistrar: MarkMonitor, Inc.\nRegistrar IANA ID: 292\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2083895740\nDomain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)\nDomain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nRegistry Registrant ID: \nRegistrant Name: GitHub Hostmaster\nRegistrant Organization: GitHub, Inc.\nRegistrant Street: 88 Colin P Kelly Jr St, \nRegistrant City: San Francisco\nRegistrant State/Province: CA\nRegistrant Postal Code: 94107\nRegistrant Country: US\nRegistrant Phone: +1.4157354488\nRegistrant Phone Ext: \nRegistrant Fax: \nRegistrant Fax Ext: \nRegistrant Email: hostmaster@github.com\nRegistry Admin ID: \nAdmin Name: GitHub Hostmaster\nAdmin Organization: GitHub, Inc.\nAdmin Street: 88 Colin P Kelly Jr St, \nAdmin City: San Francisco\nAdmin State/Province: CA\nAdmin Postal Code: 94107\nAdmin Country: US\nAdmin Phone: +1.4157354488\nAdmin Phone Ext: \nAdmin Fax: \nAdmin Fax Ext: \nAdmin Email: hostmaster@github.com\nRegistry Tech ID: \nTech Name: GitHub Hostmaster\nTech Organization: GitHub, Inc.\nTech Street: 88 Colin P Kelly Jr St, \nTech City: San Francisco\nTech State/Province: CA\nTech Postal Code: 94107\nTech Country: US\nTech Phone: +1.4157354488\nTech Phone Ext: \nTech Fax: \nTech Fax Ext: \nTech Email: hostmaster@github.com\nName Server: ns-421.awsdns-52.com.\nName Server: ns-1707.awsdns-21.co.uk.\nName Server: ns-1283.awsdns-32.org.\nName Server: ns-520.awsdns-01.net.\nDNSSEC: unsigned\nURL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/\n>>> Last update of WHOIS database: 2017-01-04T08:44:03-0800 <<<\n\nThe Data in MarkMonitor.com's WHOIS database is provided by MarkMonitor.com for\ninformation purposes, and to assist persons in obtaining information about or\nrelated to a domain name registration record.  MarkMonitor.com does not guarantee\nits accuracy.  By submitting a WHOIS query, you agree that you will use this Data\nonly for lawful purposes and that, under no circumstances will you use this Data to:\n (1) allow, enable, or otherwise support the transmission of mass unsolicited,\n     commercial advertising or solicitations via e-mail (spam); or\n (2) enable high volume, automated, electronic processes that apply to\n     MarkMonitor.com (or its systems).\nMarkMonitor.com reserves the right to modify these terms at any time.\nBy submitting this query, you agree to abide by this policy.\n\nMarkMonitor is the Global Leader in Online Brand Protection.\n\nMarkMonitor Domain Management(TM)\nMarkMonitor Brand Protection(TM)\nMarkMonitor AntiPiracy(TM)\nMarkMonitor AntiFraud(TM)\nProfessional and Managed Services\n\nVisit MarkMonitor at http://www.markmonitor.com\nContact us at +1.8007459229\nIn Europe, at +44.02032062220\n\nFor more information on Whois status codes, please visit\n https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en\n--\n\n\n\n   Domain Name: GITHUB.COM\n   Registrar: MARKMONITOR INC.\n   Sponsoring Registrar IANA ID: 292\n   Whois Server: whois.markmonitor.com\n   Referral URL: http://www.markmonitor.com\n   Name Server: NS-1283.AWSDNS-32.ORG\n   Name Server: NS-1707.AWSDNS-21.CO.UK\n   Name Server: NS-421.AWSDNS-52.COM\n   Name Server: NS-520.AWSDNS-01.NET\n   Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n   Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\n   Updated Date: 21-oct-2016\n   Creation Date: 09-oct-2007\n   Expiration Date: 09-oct-2020",
    }
    
## Implementation

### Hostnames

For hostnames, a WHOIS request will be performed and parsed using `pythonwhois`. The name of the registrar will be returned, as well as the email address referenced for abuse reports if any.

### IP Addresses

For IP addresses, a network WHOIS is performed and parsed using ipwhois.

The names are determined by using the `description` field of the parsed `nets`. The smallest net comes first.

The email addresses are determined by counting the references to abuse on each line containing email addresses.

### URLs

When using URLs:

1. First, the URL is parsed in order to extract the registered domain, or an IP address
2. In case of a domain, a DNS request is made in order to get IP addresses matching with the registered domain
3. A lookup is made for every IP address, and the results are combined

### Email addresses

When using email addresses:

1. First, a domain lookup is made, but this time looking for an abuse contact provided by the registrant (looking for 'abuse' in provided email addresses).
2. If no contact was found, do the same for every domain present in MX records.
