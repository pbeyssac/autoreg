#
# $Id$

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import os

FROMADDR='noreply@eu.org'
# number of grace days for domain restoration
DEFAULT_GRACE_DAYS=30
# for debug purposes
MAILBCC="pb@eu.org"
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

dbstring=os.getenv('AUTOREG_DBSTRING') or 'dbname=autoreg'

# export database name in a form suitable for Django
if dbstring.startswith('dbname='):
  DATABASE_NAME=dbstring[7:]
else:
  # let's try that in case it works by pure chance...
  DATABASE_NAME=dbstring
