#!/usr/local/bin/python

from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function


import os
import pwd
import sys


import autoreg.conf
import autoreg.dns.access


def create():
    if len(sys.argv) != 2:
      print("Usage: %s domain" % sys.argv[0])
      return 1
    domain = sys.argv[1].upper()

    pwent = pwd.getpwnam('autoreg')
    if os.getuid() != pwent.pw_uid:
      print("Please run as user autoreg")
      return 1

    autoreg.dns.access.main(['access-zone', '-anewzone', domain])

    filename = os.path.join(autoreg.conf.ZONEFILES_DIR, domain)
    with open(filename, 'w+') as file:
      autoreg.dns.access.main(['access-zone', '-acat', domain], outfile=file)

    print('Add the following to your BIND configuration file:')
    print('zone "%s" { type master; file \"%s\"; allow-transfer {}; };'
          % (domain, filename))
    print("Then run 'rndc reconfig'")


if __name__ == "__main__":
    main()
