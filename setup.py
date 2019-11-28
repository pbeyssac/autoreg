#!/usr/local/bin/python

from setuptools import setup

setup(name='autoreg',
      version='0.4',
      author='Pierre Beyssac', author_email='autoreg-devel@eu.org',
      url='https://nic.eu.org/',
      install_requires = ['bsddb3',
                          'cryptography',
                          'dnspython',
                          'pillow',
                          'psycopg2',
                          'pygost',
                          'pyotp',
                          'python-dateutil',
                          'qrcode',
                          'requests',
                          'six'],
      packages=['autoreg', 'autoreg.dns', 'autoreg.whois',
                'autoreg.arf', 'autoreg.arf.arf',
                'autoreg.arf.webdns',
                'autoreg.arf.requests',
                'autoreg.arf.requests.management',
                'autoreg.arf.requests.management.commands',
		'autoreg.arf.logs',
                'autoreg.arf.whois'],
      package_data={
        '': ['static/*',
             'locale/*/LC_MESSAGES/*.po',
             'locale/*/LC_MESSAGES/*.mo',
             'templates/*.html', 'templates/*.mail',
             'templates/*/*.html', 'templates/*/*.mail'],
      },
      entry_points = {
        'console_scripts': [
          'access-zone = autoreg.dns.access:main',
          'autoreg-expire = autoreg.common:expiremain',
          'check-ns = autoreg.dns.check:main',
          'checkallsoa = autoreg.dns.check:main_checkallsoa',
          'importzone = autoreg.dns.newzones:transfer',
          'new-handle-secret = autoreg.newsecret:new_handle_secret',
          'newzone = autoreg.dns.newzones:createmain',
          'whoisdb = autoreg.whois.query:whoisdbmain',
          'whoisupdate = autoreg.whois.db:main'
        ]
      }
      )
