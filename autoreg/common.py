# bits common to DNS and whois

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import io

import autoreg.conf


def domain_delete(dd, fqdn, whoisdb, out,
                  grace_days=autoreg.conf.DEFAULT_GRACE_DAYS):
  """Delete domain: put in hold if grace_days is not 0,
  delete from zone and whois if grace_days is 0.
  """
  allnow = (grace_days == 0)
  fqdn = fqdn.upper()

  dd.delete(fqdn, None, grace_days=grace_days)

  print("Delete done\n", file=out)

  if allnow:
    inwhois = ['domain: '+fqdn, 'delete: autoreg']
    outwhois = io.StringIO()
    if not whoisdb.parsefile(inwhois, None, outfile=outwhois):
      print(outwhois.getvalue(), file=out)
      return False

    print(outwhois.getvalue(), file=out)
  return True


def expiremain():
  import sys

  import psycopg2

  import autoreg.dns.db
  import autoreg.whois.db


  dbh = psycopg2.connect(autoreg.conf.dbstring)
  dbh.set_isolation_level(1)

  dbc = dbh.cursor()
  dd = autoreg.dns.db.db(dbc=dbc)
  dd.login('autoreg')

  whoisdb = autoreg.whois.db.Main(dbc=dbc)

  for dom, zone, dateexp in dd.expired(now=True):
    print('%s %s.%s' % (dateexp, dom, zone))
    fqdn = dom + '.' + zone
    r = domain_delete(dd, fqdn, whoisdb, out=sys.stdout, grace_days=0)
    if r:
      dbh.commit()
    else:
      dbh.rollback()


def fqdn_to_idna(fqdn):
  fqdn = fqdn.lower()
  try:
    idna = fqdn.encode('ascii').decode('idna')
  except UnicodeDecodeError:
    idna = fqdn
  except UnicodeError:
    idna = fqdn
  return idna


if __name__ == "__main__":
  expiremain()
