import io

import psycopg2

from django.core.exceptions import SuspiciousOperation
from django.core.urlresolvers import reverse, reverse_lazy
from django.db import connection
import django.forms as forms
from django.http import HttpResponseRedirect, HttpResponseNotFound, \
  HttpResponseForbidden, StreamingHttpResponse
from django.shortcuts import render_to_response
from django.template import RequestContext

import autoreg.conf
import autoreg.dns.check
import autoreg.dns.db
import autoreg.dns.dnssec
from autoreg.whois.db import check_handle_domain_auth, \
  suffixadd, suffixstrip, HANDLESUFFIX

from autoreg.arf.requests.models import Requests, rq_make_id
from autoreg.arf.whois.models import Contacts, check_is_admin
from autoreg.arf.whois.views import registrant_form
from models import Domains, Rrs

URILOGIN = reverse_lazy('autoreg.arf.whois.views.login')


class newdomain_form(registrant_form):
  th = forms.CharField(max_length=10, initial=HANDLESUFFIX,
                       help_text='Technical Contact', required=True)


def _gen_checksoa(domain, nsiplist=None, doit=False, dnsdb=None, soac=None,
                  contact=None, newdomain=False, form=None):
  """Generator returning SOA checks output, line by line."""
  if soac is None:
    soac = autoreg.dns.check.SOAChecker(domain, {}, {})
  errs = 0

  for ok, out in soac.main(nsiplist=nsiplist):
    if not ok:
      errs += 1
    yield out + '\n'

  if not errs and doit:
    if newdomain:
      yield "No error, storing for validation...\n"
    else:
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
    rrfile = io.StringIO(rec)
    err = None
    if newdomain:
      rqid = rq_make_id()
      ad = []
      for i in ['pn1', 'ad1', 'ad2', 'ad3', 'ad4', 'ad5', 'ad6']:
        a = form.cleaned_data.get(i, None)
        if a is not None and a != '':
          ad.append('address: ' + a)
      private = form.cleaned_data['private']

      whoisrecord = '\n'.join(["domain:  %s" % domain.upper(),
                               '\n'.join(ad),
                               "admin-c: " + suffixadd(contact.handle),
                               "tech-c:  " + form.cleaned_data['th']])
      zonerecord = rec
      rql = Requests.objects.filter(action='N', contact_id=contact.id,
                                    fqdn=domain.upper(), state='Open')
      if rql.count() > 0:
        yield "IGNORED: you already have a pending request " \
              + rql[0].id + " for that domain.\n"
        return
      req = Requests(id=rqid, action='N', language='en',
                     email=contact.email, fqdn=domain.upper(), state='Open',
                     contact=contact,
                     zonerecord=zonerecord,
                     whoisrecord=whoisrecord, private=private)
      req.save()
      yield "Saved as request " + rqid + "\n"
    else:
      try:
        dnsdb.modify(domain, None, 'NS', rrfile)
      except autoreg.dns.db.DomainError as e:
        err = e.args[0]
      except autoreg.dns.db.AccessError as e:
        err = e.args[0]
    if err:
      yield err + '\n'
    else:
      yield "\nDone\n"

def _gen_checksoa_log(domain, handle, nsiplist=None, doit=False,
                      newdomain=False, form=None, dnsdb=None,
                      level=autoreg.dns.check.LEVEL_NS):
  """Same as _gen_checksoa(), and keep a log of the output."""
  soac = autoreg.dns.check.SOAChecker(domain, {}, {})
  soac.set_level(level)
  rec = []
  dbc = connection.cursor()
  contact = Contacts.objects.get(handle=handle.upper())
  for line in _gen_checksoa(domain, nsiplist, doit, dnsdb, soac, contact,
                            newdomain, form):
    rec.append(line)
    yield line
  dbc.execute("INSERT INTO requests_log"
              " (fqdn, contact_id, output, errors, warnings)"
              " VALUES (%s, %s, %s, %s, %s)",
              (domain, contact.id, ''.join(rec), soac.errs, soac.warns))
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
  is_admin = check_is_admin(request.user.username)
  if not check_handle_domain_auth(connection.cursor(),
                                  request.user.username, fqdn) \
      and not is_admin:
    return HttpResponseForbidden("Unauthorized")
  handle = request.user.username.upper()
  verbose = False

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
    if request.method == 'POST' or verbose:
      # get current DNSKEYs from domain servers
      # calculate corresponding DS records
      dsdnskeys = autoreg.dns.dnssec.make_ds_dnskeys_ns(fqdn, nslist)
      dsserved = []
      for dslist, dnskey in dsdnskeys:
        dsserved.extend(dslist)
      dsserved.sort()
    else:
      dsserved = []

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

  vars = RequestContext(request,
     { 'domain': fqdn, 'dserrs': dserrs, 'rr': rr,
       'verbose': verbose, 'is_admin': is_admin,
       'dscur': dscur, 'dsserved': dsserved, 'dsok': dsok, 'elerr': elerr })
  return render_to_response('dns/dsedit.html', vars)

def _get_rr_nsip(dd, fqdn):
  rrlist = dd.queryrr(fqdn, None, None, None)
  rrlist = [(r[0], '' if r[1] is None else r[1], r[2], r[3])
            for r in rrlist]
  #          if r[2] in ['NS', 'AAAA', 'A']]
  form = None

  nsdict = {}
  nsiplist = []

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

  for ns, iplist in nsdict.iteritems():
    if iplist:
      for ip in iplist:
        nsiplist.append((ns, ip))
    else:
      nsiplist.append((ns, ''))
  nsiplist.sort(key=lambda x: x[0])
  return rrlist, nsiplist

def domainns(request, fqdn=None):
  """Show/edit record(s) for domain"""
  if fqdn and fqdn != fqdn.lower():
    return HttpResponseRedirect(reverse(domainns, args=[fqdn.lower()]))
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  handle = request.user.username.upper()
  is_admin = check_is_admin(request.user.username)
  if fqdn and not check_handle_domain_auth(connection.cursor(),
                                  handle, fqdn) \
      and not is_admin:
    return HttpResponseForbidden("Unauthorized")

  newdomain = (fqdn is None)

  dbh = psycopg2.connect(autoreg.conf.dbstring)
  dd = autoreg.dns.db.db(dbh)
  dd.login('autoreg')

  errors = {}

  if request.method == 'POST':
    nsiplist = []
    for n in range(1, 10):
      f = 'f%d' % n
      i = 'i%d' % n
      if f not in request.POST or i not in request.POST:
        break
      fp = request.POST.get(f).strip()
      ip = request.POST.get(i).strip()
      e = []
      if fp and not autoreg.dns.check.checkfqdn(fp):
        e.append('Invalid name')
      if ip and not autoreg.dns.check.checkip(ip):
        e.append('Invalid IP address')
      if e:
        errors['nsip%d' % n] = e
      nsiplist.append((fp, ip))

    level = request.POST.get('level', '3')
    if len(level) != 1 or level < '1' or level > '3':
      raise SuspiciousOperation
    level = int(level)

    if newdomain:
      form = newdomain_form(request.POST)
      fqdn = request.POST.get('fqdn').strip().lower()
      # help the user (somewhat)
      # remove leading http:// or https://
      if fqdn.startswith('http://'):
        fqdn = fqdn[7:]
      elif fqdn.startswith('https://'):
        fqdn = fqdn[8:]
      # remove trailing '.'
      if fqdn.endswith('.'):
        fqdn = fqdn[:-1]
      th = request.POST.get('th').strip().upper()

      ah = suffixadd(handle)
      if th == '':
        th = ah
      therrors = []
      tcl = Contacts.objects.filter(handle=suffixstrip(th))
      if tcl.count() != 1:
        errors['th'] = ['Contact does not exist']
      if not nsiplist:
        errors['nsip1'] = ['NS list is empty']
      dbh2 = psycopg2.connect(autoreg.conf.dbstring)
      ddro = autoreg.dns.db.db(dbh2, nowrite=True)
      ddro.login('autoreg')
      try:
        # don't really create (read-only session)
        ddro.new(fqdn, None, 'NS', file=io.StringIO())
      except autoreg.dns.db.DomainError as e:
        errors['fqdn'] = [unicode(e)]
      except autoreg.dns.db.AccessError as e:
        errors['fqdn'] = [unicode(e)]

      # release the write lock on the zone record
      dbh2.rollback()
      rrlist = []
    else:
      th, ah, form = None, None, None
      rrlist, dummy = _get_rr_nsip(dd, fqdn)

    if not errors and (not form or form.is_valid()):
      # Everything seems ok in the form, proceed to DNS checks
      #
      # Cleanup possible empty lines
      # Can't be cleaned in case of error as it breaks error messages
      # in the form.
      nsiplist = [ (f, i) for f, i in nsiplist if f ]

      return StreamingHttpResponse(_gen_checksoa_log(fqdn, handle,
                                     nsiplist, doit=True,
                                     newdomain=newdomain, form=form, dnsdb=dd,
                                     level=level),
                                   content_type="text/plain")

    # Fall through to GET handling

  elif request.method != "GET":
    raise SuspiciousOperation


  if newdomain:
    rrlist = []
    if request.method == "GET":
      nsiplist = []
      contact = Contacts.objects.get(handle=handle)
      # be nice: default country is set to current contact
      form = newdomain_form(initial={'ad6': contact.country})
      ah = suffixadd(handle)
      th = ah
  else:
    rrlist, newnsiplist = _get_rr_nsip(dd, fqdn)
    if request.method == "GET":
      nsiplist = newnsiplist
    ah, th, form = None, None, None


  while len(nsiplist) < 9:
    nsiplist.append(('', ''))

  vars = RequestContext(request,
     { 'newdomain': newdomain,
       'is_admin': is_admin,
       'fqdn': fqdn or '', 'rrlist': rrlist,
       'th': th, 'ah': ah,
       'errors': errors,
       'form': form,
       'nsiplist': nsiplist })
  return render_to_response('dns/nsedit.html', vars)
