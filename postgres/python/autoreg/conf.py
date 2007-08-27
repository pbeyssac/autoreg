#
# $Id$

import os

msgdir='/usr/local/dns-manager/conf'
zones_auth='/usr/local/dns-manager/conf/zones-auth'
dbstring=os.getenv('AUTOREG_DBSTRING') or 'dbname=eu.org'
