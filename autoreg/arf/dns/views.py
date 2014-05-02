import psycopg2

from django.core.exceptions import SuspiciousOperation
from django.core.urlresolvers import reverse, reverse_lazy
from django.db import connection
from django.http import HttpResponseRedirect, HttpResponseNotFound, \
  HttpResponseForbidden, StreamingHttpResponse
from django.shortcuts import render_to_response

import autoreg.conf
import autoreg.dns.check
import autoreg.dns.db
import autoreg.dns.dnssec
from autoreg.whois.db import admin_login, check_handle_domain_auth

from models import Domains, Rrs

URILOGIN = reverse_lazy('autoreg.arf.whois.views.login')

def _gen_checksoa(domain):
  soac = autoreg.dns.check.SOAChecker(domain, {}, {})

  for ok, out in soac.main():
    yield out + '\n'

def checksoa(request, domain):
  if request.method != 'GET':
    raise SuspiciousOperation
  if domain != domain.lower():
    return HttpResponseRedirect(reverse(checksoa, args=[domain.lower()]))
  return StreamingHttpResponse(_gen_checksoa(domain),
                               content_type="text/plain")

def domainds(request, fqdn):
  """Show/edit DNSSEC DS record(s) for domain"""
  if fqdn != fqdn.lower():
    return HttpResponseRedirect(reverse(domainds, args=[fqdn.lower()]))
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  if not check_handle_domain_auth(connection.cursor(),
                                  request.user.username, fqdn) \
      and not admin_login(connection.cursor(), request.user.username):
    return HttpResponseForbidden("Unauthorized")

  dbh = psycopg2.connect(autoreg.conf.dbstring)
  dd = autoreg.dns.db.db(dbh)
  dd.login('autoreg')

  fqdn = fqdn.upper()

  try:
    dsok, elerr = dd.checkds(fqdn, None)
  except autoreg.dns.db.DomainError:
    return HttpResponseNotFound("Domain not found")

  nslist = [ rr[1] for rr in dd.queryrr(fqdn, None, '', 'NS') ]

  if dsok:
    # get current DNSKEYs from domain servers
    # calculate corresponding DS records
    dsdnskeys = autoreg.dns.dnssec.make_ds_dnskeys_ns(fqdn, nslist)
    dsserved = []
    for dslist, dnskey in dsdnskeys:
      dsserved.extend(dslist)
    dsserved.sort()

    # get current DS list in our database
    dscur = dd.queryrr(fqdn, None, '', 'DS')
    dscur = [ rr[1].split(' ', 3) for rr in dscur ]
    dscur = [ (int(rr[0]), int(rr[1]), int(rr[2]), rr[3]) for rr in dscur ]
    dscur.sort()
  else:
    dsserved = []
    dscur = []

  rr = ''
  dserrs = []
  dsdup, dsnew = [], []

  if request.method == 'POST':
    rr = request.POST.get('rr', '')
    act = request.POST.get('act', '')
    value = request.POST.get('ds', '')

    if act == 'del' and value:
      if dd.delrr(fqdn, None, '', 'DS', value) < 1:
        dserrs.append('Cannot delete DS record')
      else:
        # Refresh dscur
        rrv = value.split(' ', 3)
        rrv = (int(rrv[0]), int(rrv[1]), int(rrv[2]), rrv[3])
        dscur.remove(rrv)
    else:
      ok, r = autoreg.dns.dnssec.make_ds(rr, fqdn)
      if ok:
        dsnew = r
        dsnew.sort()
      else:
        dserrs.append(r)
        dsnew = []
      dsnokey = [ ds for ds in dsnew if ds not in dsserved ]
      dsdup = [ ds for ds in dsnew if ds in dscur ]
      dsnew = [ ds for ds in dsnew if ds in dsserved and ds not in dscur ]
      if dsdup and not dsnew:
        dserrs.append("Requested DS already in zone")
      if dsnokey:
        dserrs.append("Requested DS does not match any published DNSKEY in zone")
      if dsok and not dserrs:
        for ds in dsnew:
          dd.addrr(fqdn, None, '', None, 'DS', '%d %d %d %s' % ds,
                   _commit=False)
          dscur.append(ds)
        dd.commit()
        rr = ""
        dscur.sort()

  elif request.method != "GET":
    raise SuspiciousOperation

  return render_to_response('dns/dsedit.html',
     { 'domain': fqdn, 'dserrs': dserrs, 'rr': rr,
       'dscur': dscur, 'dsserved': dsserved, 'dsok': dsok, 'elerr': elerr })
