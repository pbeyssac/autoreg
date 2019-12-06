#

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import os

FROMADDR='noreply@eu.org'
# number of grace days for domain restoration
DEFAULT_GRACE_DAYS=30
# for debug purposes
MAILBCC="debug@eu.org"
# eu.org/FreeDNS handle suffix
HANDLESUFFIX = '-FREE'
# contact handle for preempted domains
PREEMPTHANDLE = 'EOD1'
# right-hand side domain for anti-spam handles
HANDLEMAILHOST = 'handles.eu.org'
SITENAME = 'EU.org'
# Default master server shown in SOA record
SOA_MASTER='NS.EU.ORG'
# Default hostmaster email, in SOA record format (@ changed to .)
SOA_EMAIL='hostmaster.eu.org'
ZONEFILES_DIR='/etc/namedb/autoreg'

# Maximum zone age in seconds on older serial before autoreg.dns.check.SOAChecker() issues a warning
MAX_ZONE_AGE = 720

try:
  ENCRYPT_KEY=open('/usr/local/autoreg/arf/ENCRYPT_KEY', 'rb').read()[:-1]
except PermissionError:
  # default key for tests -- make sure this fails unless explicitly configured
  ENCRYPT_KEY=os.environ.get('ENCRYPT_KEY', '').encode()


# Postgres connect string
# Don't use this in Django modules, use autoreg.arf.util.dbstring instead,
# for compatibility with the test environment.
dbstring=os.getenv('AUTOREG_DBSTRING') or \
  'dbname=autoreg_dev host=192.168.0.4 user=autoreg password='

for kv in dbstring.split():
  k, v = kv.split('=', 1)
  if k == 'dbname':
    DATABASE_NAME=v
  elif k == 'host':
    DATABASE_HOST=v
  elif k == 'user':
    DATABASE_USER=v
  elif k == 'password':
    DATABASE_PASSWORD=v
  elif k == 'port':
    DATABASE_PORT=v
