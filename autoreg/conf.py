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
# right-hand side domain for anti-spam handles
HANDLEMAILHOST = 'handles.eu.org'

dbstring=os.getenv('AUTOREG_DBSTRING') or 'dbname=eu.org'

# export database name in a form suitable for Django
if dbstring.startswith('dbname='):
  DATABASE_NAME=dbstring[7:]
else:
  # let's try that in case it works by pure chance...
  DATABASE_NAME=dbstring
