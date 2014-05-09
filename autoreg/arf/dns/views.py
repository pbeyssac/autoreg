import cStringIO

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

from autoreg.arf.whois.models import Contacts
from models import Domains, Rrs

URILOGIN = reverse_lazy('autoreg.arf.whois.views.login')

def _gen_checksoa(domain, nsiplist=None, doit=False, dnsdb=None, soac=None):
  """Generator returning SOA checks output, line by line."""
  if soac is None:
    soac = autoreg.dns.check.SOAChecker(domain, {}, {})
  errs = 0

  for ok, out in soac.main(nsiplist=nsiplist):
    if not ok:
      errs += 1
    yield out + '\n'

  if not errs and doit:
    yield "No error, applying changes...\n"
    rec = []
    for ns in soac.nslist:
      rec.append("\tNS\t%s." % ns)
    gluelist = soac.manualip.keys()
    gluelist.sort()
    for ns in gluelist:
      iplist = soac.manualip[ns]
      if ns.endswith('.' + domain.upper()):
        ns = ns[:-len(domain)-1]
      for ip in iplist:
        if ':' in ip:
          rec.append("%s\tAAAA\t%s" % (ns, ip))
        else:
          rec.append("%s\tA\t%s" % (ns, ip))
    rec = '\n'.join(rec)
    rec += '\n'
    rrfile = cStringIO.StringIO(rec)
    err = None
    try:
      dnsdb.modify(domain, None, 'NS', rrfile)
    except autoreg.dns.db.DomainError, e:
      err = e.args[0]
    except autoreg.dns.db.AccessError, e:
      err = e.args[0]
    if err:
      yield err + '\n'
    else:
      yield "\nDone\n"

def _gen_checksoa_log(domain, handle, nsiplist=None, doit=False, dnsdb=None):
  """Same as _gen_checksoa(), and keep a log of the output."""
  soac = autoreg.dns.check.SOAChecker(domain, {}, {})
  rec = []
  dbc = connection.cursor()
  contact_id = Contacts.objects.get(handle=handle.upper()).id
  for line in _gen_checksoa(domain, nsiplist, doit, dnsdb, soac):
    rec.append(line)
    yield line
  dbc.execute("INSERT INTO requests_log"
              " (fqdn, contact_id, output, errors, warnings)"
              " VALUES (%s, %s, %s, %s, %s)",
              (domain, contact_id, ''.join(rec), soac.errs, soac.warns))
  assert dbc.rowcount == 1

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

  nslist = [ rr[3] for rr in dd.queryrr(fqdn, None, '', 'NS') ]

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
    dscur = [ rr[3].split(' ', 3) for rr in dscur ]
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

def domainns(request, fqdn):
  """Show/edit record(s) for domain"""
  if fqdn != fqdn.lower():
    return HttpResponseRedirect(reverse(domainns, args=[fqdn.lower()]))
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  if not check_handle_domain_auth(connection.cursor(),
                                  request.user.username, fqdn) \
      and not admin_login(connection.cursor(), request.user.username):
    return HttpResponseForbidden("Unauthorized")

  dbh = psycopg2.connect(autoreg.conf.dbstring)
  dd = autoreg.dns.db.db(dbh)
  dd.login('autoreg')

  rrerrs = []

  if request.method == 'POST':
    nsiplist = []
    for n in range(1, 9):
      f = 'f%d' % n
      i = 'i%d' % n
      if f not in request.POST or i not in request.POST:
        break
      fp = request.POST.get(f).strip()
      if not fp:
        continue
      nsiplist.append((fp, request.POST.get(i).strip()))
    return StreamingHttpResponse(_gen_checksoa_log(fqdn, request.user.username,
                                   nsiplist, doit=True, dnsdb=dd),
                                 content_type="text/plain")
  elif request.method != "GET":
    raise SuspiciousOperation

  nsdict = {}
  rrlist = dd.queryrr(fqdn, None, None, None)
  rrlist = [(r[0], '' if r[1] is None else r[1], r[2], r[3])
            for r in rrlist]
  for label, ttl, rrtype, value in rrlist:
    if rrtype == 'NS':
      ns = value.rstrip('.').lower()
      if ns not in nsdict:
        nsdict[ns] = []
  for label, ttl, rrtype, value in rrlist:
    if rrtype in ['A', 'AAAA']:
      hfqdn = label.lower() + '.' + fqdn
      if hfqdn in nsdict:
        nsdict[hfqdn].append(value.lower())

  nslist = []
  for ns, iplist in nsdict.iteritems():
    if iplist:
      for ip in iplist:
        nslist.append((ns, ip))
    else:
      nslist.append((ns, ''))

  nslist.sort(key=lambda x: x[0])
  nslist.append(('', ''))

  while len(nslist) < 10:
    nslist.append(('', ''))

  return render_to_response('dns/nsedit.html',
     { 'domain': fqdn, 'rrlist': rrlist, 'errs': rrerrs, 'nsdict': nsdict,
       'nslist': nslist })
