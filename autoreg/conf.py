#
# $Id$

import os

autoregdir='/usr/local/autoreg'
confdir=os.path.join(autoregdir, 'conf')
msgdir=confdir
zones_auth=os.path.join(confdir,'zones-auth')
DOREJECT_PATH=os.path.join(autoregdir, 'bin', 'doreject')

FROMADDR='noreply@eu.org'
# for debug purposes
MAILBCC="pb@eu.org"

dbstring=os.getenv('AUTOREG_DBSTRING') or 'dbname=eu.org'

# export database name in a form suitable for Django
if dbstring.startswith('dbname='):
  DATABASE_NAME=dbstring[7:]
else:
  # let's try that in case it works by pure chance...
  DATABASE_NAME=dbstring
