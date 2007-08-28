#
# $Id$

import os

autoregdir='/usr/local/autoreg'
confdir=os.path.join(autoregdir, 'conf')
msgdir=confdir
zones_auth=os.path.join(confdir,'zones-auth')
dbstring=os.getenv('AUTOREG_DBSTRING') or 'dbname=eu.org'
