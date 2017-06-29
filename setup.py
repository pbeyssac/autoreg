#!/usr/local/bin/python

from setuptools import setup

setup(name='autoreg',
      version='0.4',
      author='Pierre Beyssac', author_email='autoreg-devel@eu.org',
      url='https://nic.eu.org/',
      install_requires = ['bsddb3',
                          'dnspython',
                          'egenix-mx-base',
                          'python-dateutil',
                          'psycopg2',
                          'pygost',
                          'six'],
      packages=['autoreg', 'autoreg.dns', 'autoreg.whois',
                'autoreg.arf', 'autoreg.arf.arf',
                'autoreg.arf.webdns',
                'autoreg.arf.requests',
                'autoreg.arf.requests.management',
                'autoreg.arf.requests.management.commands',
		'autoreg.arf.logs',
                'autoreg.arf.whois'],
      entry_points = {
        'console_scripts': [
          'access-zone = autoreg.dns.access:main',
          'autoreg-expire = autoreg.common:expiremain',
          'check-ns = autoreg.dns.check:main',
          'checkallsoa = autoreg.dns.check:main_checkallsoa',
          'new-handle-secret = autoreg.common:new_handle_secret',
          'whoisdb = autoreg.whois.query:whoisdbmain',
          'whoisupdate = autoreg.whois.db:main'
        ]
      }
      )
