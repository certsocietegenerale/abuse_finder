# -*- coding: utf-8 -*-
from setuptools import setup

setup(name='abuse_finder',
      version='0.2',
      description='Look for abuse contacts for IP, domain names, email addresses and URLs.',
      url='https://github.com/certsocietegenerale/abuse_finder',
      author='CERT Société Générale',
      author_email='cert.sg@socgen.com',
      license='GPLv3',
      packages=['abuse_finder'],
      install_requires=[
        'ipwhois',
        'ipaddress',
        'pythonwhois',
        'tldextract',
        'dnspython'
      ],
      zip_safe=False)
