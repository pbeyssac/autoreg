#
# $Id$

import os

FROMADDR='noreply@eu.org'
# number of grace days for domain restoration
DEFAULT_GRACE_DAYS=30
# for debug purposes
MAILBCC="pb@eu.org"

dbstring=os.getenv('AUTOREG_DBSTRING') or 'dbname=eu.org'

# export database name in a form suitable for Django
if dbstring.startswith('dbname='):
  DATABASE_NAME=dbstring[7:]
else:
  # let's try that in case it works by pure chance...
  DATABASE_NAME=dbstring
