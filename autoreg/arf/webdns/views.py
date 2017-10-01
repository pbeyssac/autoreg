from __future__ import absolute_import
from __future__ import unicode_literals

import io

import psycopg2

from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import SuspiciousOperation
from django.core.urlresolvers import reverse, reverse_lazy
from django.db import connection
import django.forms as forms
from django.http import HttpResponseRedirect, HttpResponseNotFound, \
  HttpResponseForbidden, StreamingHttpResponse
from django.shortcuts import render
from django.utils import translation
from django.utils.translation import ugettext_lazy, ugettext as _

import autoreg.arf.whois.views as whois_views
from autoreg.conf import dbstring, HANDLESUFFIX, PREEMPTHANDLE
import autoreg.dns.check
import autoreg.dns.db
import autoreg.dns.dnssec
from autoreg.whois.db import check_handle_domain_auth, \
  suffixadd, suffixstrip


from ..requests.models import Requests, rq_make_id
from ..whois.models import Contacts, Whoisdomains, check_is_admin
from ..whois.views import registrant_form, login
from .models import Zones, is_orphan, preempt

URILOGIN = reverse_lazy(login)


class newdomain_form(registrant_form):
  th = forms.CharField(max_length=10, initial=HANDLESUFFIX,
                       help_text='Technical Contact', required=True)
  orphan = forms.BooleanField(required=False)


class special_form(forms.Form):
  domains = forms.CharField(max_length=200000, initial='.eu.org',
                            help_text=ugettext_lazy('Domain List'),
                            widget=forms.Textarea,
                            required=True)
  action = forms.ChoiceField(choices=[('none', ugettext_lazy('None')),
                                      ('lock1', ugettext_lazy('Lock')),
                                      ('lock0', ugettext_lazy('Unlock')),
                                      ('hold1', ugettext_lazy('Hold')),
                                      ('hold0', ugettext_lazy('Unhold')),
                                      ('preempt',
                             ugettext_lazy('Preempt to %(preempthandle)s')
                               % {'preempthandle': suffixadd(PREEMPTHANDLE)})],
                             required=True, widget=forms.RadioSelect)


class special2_form(forms.Form):
  handle = forms.CharField(max_length=10, initial=HANDLESUFFIX,
                            help_text=ugettext_lazy('Contact Handle'),
                            required=True)
  action = forms.ChoiceField(choices=[
    ('none', ugettext_lazy('None')),
    ('fill', ugettext_lazy('Copy contact domain list above')),
    ('showdom', ugettext_lazy('Go to domain list')),
    ('block1', ugettext_lazy('Block')),
    ('block0', ugettext_lazy('Unblock'))],
    required=True, widget=forms.RadioSelect)


def _whoisrecord_from_form(domain, form, handle):
  """Make whois record from domain name, form and handle."""
  whoisrecord = ["domain:  %s" % domain.upper()]
  for i in ['pn1', 'ad1', 'ad2', 'ad3', 'ad4', 'ad5', 'ad6']:
    a = form.cleaned_data.get(i, None)
    if a is not None and a != '':
      whoisrecord.append('address: ' + a)

  whoisrecord.extend(["admin-c: " + suffixadd(handle),
                      "tech-c:  " + suffixadd(form.cleaned_data['th'])])

  if form.cleaned_data['private']:
    whoisrecord.append(u"private: true")
  return whoisrecord


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
      yield _("No error, storing for validation...\n")
    else:
      yield _("No error, applying changes...\n")
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
      whoisrecord = _whoisrecord_from_form(domain, form, contact.handle)
      whoisrecord = '\n'.join(whoisrecord)
      zonerecord = rec
      rql = Requests.objects.filter(action='N', contact_id=contact.id,
                                    fqdn=domain.upper(), state='Open')
      if rql.count() > 0:
        yield _("IGNORED: you already have a pending request %(rqid)s"
                " for that domain.\n") % {'rqid': rql[0].id}
        return
      rql = Requests.objects.filter(action='N',
                                    fqdn=domain.upper(), state='Open')
      if rql.count() > 0:
        yield _("IGNORED: we already have pending request(s)"
                " for that domain.\n")
        return
      zone = Zones.objects.get(name=domain.split('.', 1)[1].upper())
      req = Requests(id=rqid, action='N', language=translation.get_language(),
                     email=contact.email, fqdn=domain.upper(), zone=zone,
                     state='Open',
                     contact=contact,
                     zonerecord=zonerecord,
                     whoisrecord=whoisrecord)
      req.save()
      yield _("Saved as request %(rqid)s\n") % {'rqid': rqid}
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
  if not request.user.is_authenticated() or not request.user.is_active:
    return HttpResponseRedirect(URILOGIN + '?next=%s' % request.path)
  is_admin = check_is_admin(request.user.username)
  if not check_handle_domain_auth(connection.cursor(),
                                  request.user.username, fqdn) \
      and not is_admin:
    return HttpResponseForbidden(_("Unauthorized"))
  handle = request.user.username.upper()
  verbose = False

  dbh = psycopg2.connect(dbstring)
  dd = autoreg.dns.db.db(dbh)
  dd.login('autoreg')

  fqdn = fqdn.upper()

  try:
    dsok, elerr = dd.checkds(fqdn, None)
  except autoreg.dns.db.DomainError:
    return HttpResponseNotFound(_("Domain not found"))

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
        dserrs.append(_('Cannot delete DS record'))
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
        dserrs.append(_("Requested DS already in zone"))
      if dsnokey:
        dserrs.append(_("Requested DS does not match any published DNSKEY in zone"))
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

  vars = { 'domain': fqdn, 'dserrs': dserrs, 'rr': rr,
           'verbose': verbose,
           'dscur': dscur, 'dsserved': dsserved, 'dsok': dsok, 'elerr': elerr }
  return render(request, 'dns/dsedit.html', vars)

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


def _adopt_orphan(request, dbh, fqdn, form):
  vars = {'fqdn': fqdn.upper()}
  ok, errmsg = is_orphan(fqdn)
  if ok:
    inwhois = _whoisrecord_from_form(fqdn, form, request.user.username)
    w = autoreg.whois.db.Main(dbh)
    whoisout = io.StringIO()
    inwhois.append(u'changed: ' + suffixadd(request.user.username))
    w.parsefile(inwhois, None, commit=True, outfile=whoisout)
    vars['whoisin'] = inwhois
    vars['whoisout'] = whoisout.getvalue()
  else:
    vars['msg'] = errmsg
  return render(request, "dns/orphan.html", vars)

def domainns(request, fqdn=None):
  """Show/edit record(s) for domain"""
  if fqdn and fqdn != fqdn.lower():
    return HttpResponseRedirect(reverse(domainns, args=[fqdn.lower()]))
  if not request.user.is_authenticated() or not request.user.is_active:
    return HttpResponseRedirect(URILOGIN + '?next=%s' % request.path)
  handle = request.user.username.upper()
  is_admin = check_is_admin(request.user.username)
  if fqdn and not check_handle_domain_auth(connection.cursor(),
                                  handle, fqdn) \
      and not is_admin:
    return HttpResponseForbidden(_("Unauthorized"))

  newdomain = (fqdn is None)
  contact = Contacts.objects.get(handle=handle)
  captcha = newdomain and hasattr(settings, 'RECAPTCHA_PRIVATE_KEY') and \
    (Whoisdomains.objects.filter(domaincontact__contact_id=contact.id)
                 .distinct().count() > settings.RECAPTCHA_DOMAINS_MIN
      or
     Requests.objects.filter(contact_id=contact.id,
                             action='N', state='Open').count()
                             > settings.RECAPTCHA_REQUESTS_MIN)

  dbh = psycopg2.connect(dbstring)
  dd = autoreg.dns.db.db(dbh)
  dd.login('autoreg')

  errors = {}

  if request.method == 'POST':
    nsiplist = []
    if captcha:
      captcha_response = request.POST.get('g-recaptcha-response', None)
    for n in range(1, 10):
      f = 'f%d' % n
      i = 'i%d' % n
      if f not in request.POST or i not in request.POST:
        break
      fp = request.POST.get(f).strip()
      ip = request.POST.get(i).strip()
      e = []
      if fp and not autoreg.dns.check.checkfqdn(fp):
        e.append(_('Invalid name'))
      if ip and not autoreg.dns.check.checkip(ip):
        e.append(_('Invalid IP address'))
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

      fqdn = fqdn.lower().encode('idna')

      th = request.POST.get('th').strip().upper()

      ah = suffixadd(handle)
      if th == '':
        th = ah
      therrors = []
      tcl = Contacts.objects.filter(handle=suffixstrip(th))
      if tcl.count() != 1:
        errors['th'] = [_('Contact does not exist')]
      if not nsiplist:
        errors['nsip1'] = [_('NS list is empty')]
      dbh2 = psycopg2.connect(dbstring)
      ddro = autoreg.dns.db.db(dbh2, nowrite=True)
      ddro.login('autoreg')

      if is_admin and form.is_valid() and form.cleaned_data['orphan']:
        return _adopt_orphan(request, dbh, fqdn, form)

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

    if captcha:
      import json
      import requests

      if captcha_response:
        args = {'secret': settings.RECAPTCHA_PRIVATE_KEY,
                'response': captcha_response}

        r = requests.post(settings.RECAPTCHA_API_URL, args)
        j = json.loads(r.text)
        captcha_success = j['success']
      else:
        captcha_success = False
    else:
      captcha_success = True

    if not errors and (not form or form.is_valid()) and captcha_success:
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
      # be nice: pre-fill registrant with current contact details
      form = newdomain_form(initial=contact.initial_form())
      ah = suffixadd(handle)
      th = ah
  else:
    rrlist, newnsiplist = _get_rr_nsip(dd, fqdn)
    if request.method == "GET":
      nsiplist = newnsiplist
    ah, th, form = None, None, None


  while len(nsiplist) < 9:
    nsiplist.append(('', ''))

  vars = { 'newdomain': newdomain,
           'captcha': captcha, 'captcha_key': settings.RECAPTCHA_PUBLIC_KEY,
           'fqdn': fqdn or '', 'rrlist': rrlist,
           'th': th, 'ah': ah,
           'errors': errors,
           'form': form,
           'nsiplist': nsiplist }
  return render(request, 'dns/nsedit.html', vars)


def special(request):
  """Special actions on domain"""
  if not request.user.is_authenticated() or not request.user.is_active:
    return HttpResponseRedirect(URILOGIN + '?next=%s' % request.path)
  handle = request.user.username.upper()
  is_admin = check_is_admin(request.user.username)
  if not is_admin:
    return HttpResponseForbidden(_("Unauthorized"))

  msg = ''
  msglist = []
  contact = None

  if request.method == 'POST':
    action = ''
    if 'submit2' in request.POST:
      form = special_form()
      form2 = special2_form(request.POST)
      if form2.is_valid():
        action = form2.cleaned_data['action']
        handle = suffixstrip(form2.cleaned_data['handle']).upper()
        contactlist = Contacts.objects.filter(handle=handle)
        if not contactlist:
          msg = _('Contact %s not found') % suffixadd(handle)
          contact = None
        else:
          contact = contactlist[0]

    elif 'submit' in request.POST:
      form = special_form(request.POST)
      form2 = special2_form()
      if form.is_valid():
        action = form.cleaned_data['action']
        domainlist = form.cleaned_data['domains'].split()
    else:
      raise SuspiciousOperation

    if action.startswith('hold') or action.startswith('lock'):
      dbh = psycopg2.connect(dbstring)
      dd = autoreg.dns.db.db(dbh)
      dd.login('autoreg')
      for domain in domainlist:
        domain = domain.strip().upper()
        if action.startswith('hold'):
          dd.set_registry_hold(domain, None, action[4] == '1')
        elif action.startswith('lock'):
          dd.set_registry_lock(domain, None, action[4] == '1')
      dmsg = {'hold0': _('Unheld %d domain(s)'),
              'hold1': _('Held %d domain(s)'),
              'lock0': _('Unlocked %d domain(s)'),
              'lock1': _('Locked %d domain(s)')}
      if action not in dmsg:
        raise SuspiciousOperation
      msg = dmsg[action] % len(domainlist)
    elif action.startswith('block'):
      u = User.objects.get(username=handle)
      if u.is_active != (action == 'block0'):
        u.is_active = (action == 'block0')
        u.save()
      if action == 'block0':
        msg = _('Unblocked %s' % suffixadd(handle))
      elif action == 'block1':
        msg = _('Blocked %s' % suffixadd(handle))
      else:
        raise SuspiciousOperation
    elif action == 'fill':
      if contact:
        domainlist = [d.fqdn
                        for d in Whoisdomains.objects.filter(
                          domaincontact__contact__handle=handle)
                          .order_by('fqdn').distinct()]
        msg = _('Copied %(ndom)d domain(s) from contact %(handle)s'
                % {'ndom': len(domainlist), 'handle': suffixadd(handle)})
        v = {'domains': '\n'.join(domainlist)}
        form = special_form(v)
      else:
        form = special_form()
    elif action == 'showdom':
      if contact:
        return HttpResponseRedirect(reverse(whois_views.domainlist,
                                    args=[handle]))
    elif action == 'preempt':
      for domain in domainlist:
        domain = domain.strip().upper()
        ok, err = preempt(request.user.username, domain)
        if ok:
          msglist.append(_('Domain %s has been preempted') % domain)
        else:
          msglist.append(_('Domain %(domain)s has not been preempted: %(err)s')
                            % {'domain': domain, 'err': err})
    elif action:
      raise SuspiciousOperation
    # no action: do nothing, just redisplay the page
  elif request.method == "GET":
    form = special_form()
    form2 = special2_form()
  else:
    raise SuspiciousOperation

  vars = { 'form': form,
           'form2': form2,
           'msglist': msglist,
           'msg': msg }
  return render(request, 'dns/special.html', vars)
