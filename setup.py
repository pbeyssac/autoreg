#!/usr/local/bin/python

from distutils.core import setup

setup(name='autoreg',
      version='0.1',
      author='Pierre Beyssac', author_email='autoreg-devel@eu.org',
      url='http://eu.org/',
      packages=['autoreg', 'autoreg.dns', 'autoreg.whois',
                'autoreg.arf', 'autoreg.arf.arf',
                'autoreg.arf.webdns',
                'autoreg.arf.requests',
                'autoreg.arf.requests.management',
                'autoreg.arf.requests.management.commands',
		'autoreg.arf.logs',
                'autoreg.arf.whois'],
      )
