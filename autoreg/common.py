# bits common to DNS and whois

from __future__ import print_function

import io

import autoreg.conf


def domain_delete(dd, fqdn, whoisdb, out,
                  grace_days=autoreg.conf.DEFAULT_GRACE_DAYS):
  """Delete domain: put in hold if grace_days is not 0,
  delete from zone and whois if grace_days is 0.
  """
  allnow = (grace_days == 0)
  fqdn = fqdn.upper()

  dd.delete(fqdn, None, commit=not allnow, grace_days=grace_days)

  print(u"Delete done\n", file=out)

  if allnow:
    inwhois = ['domain: '+fqdn, 'delete: autoreg']
    outwhois = io.StringIO()
    if not whoisdb.parsefile(inwhois, None, commit=True, outfile=outwhois):
      print(outwhois.getvalue(), file=out)
      return False

    print(outwhois.getvalue(), file=out)
  return True
