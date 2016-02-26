# $Id$

from __future__ import absolute_import
from __future__ import print_function

import io
import re
import subprocess
import sys

import psycopg2

from ..whois.models import check_is_admin, Whoisdomains
import autoreg.conf
import autoreg.dns.db
from autoreg.whois.db import admin_login, country_from_iso
import autoreg.whois.query as query
import autoreg.zauth

from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.core.urlresolvers import reverse, reverse_lazy
from django.db import connection, transaction, IntegrityError
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render
from django.template import RequestContext
from django.utils import translation
from django.utils.translation import ugettext as _

from . import models


URILOGIN = reverse_lazy('autoreg.arf.whois.views.login')

_l3match = re.compile('^[^\.]+\.[^\.]+\.[^\.]+\..+$')
_attrval = re.compile('^([a-z0-9A-Z-]+):\s*(.*[^\s]+|)\s*$')
_rqid = re.compile('^([0-9]{14,14}-\w+-\d+)$')
_hidden_rqid = re.compile('^h([0-9]{14,14}-\w+-\d+)$')

#
# 'view' functions called from urls.py and friends
#

#
# private helper functions
#

def _rq_list_dom(domain):
  domain = domain.upper()
  return models.rq_list().filter(fqdn=domain)

def _rq_list_email(email):
  return models.rq_list().filter(email=email)

def _rq_num():
  """Return the number of pending requests"""
  return models.rq_list_unordered().count()

def _rq_ndom(fqdn):
  """Return the number of pending requests for fqdn"""
  return models.rq_list_unordered().filter(fqdn=fqdn).count()

def _rq_nemail(fqdn):
  """Return the number of distinct emails in the pending requests for fqdn"""
  return models.rq_list_unordered().filter(fqdn=fqdn) \
         .order_by('email').distinct('email').count()

def _rq_decorate(r):
  """Add attributes rclass, ndom, nemail to request"""
  if r.action == 'D':
    rclass = 'del'
    r.ndom = 0
    r.nemail = 0
  else:
    r.ndom = _rq_ndom(r.fqdn)
    if r.ndom > 1:
      r.nemail = _rq_nemail(r.fqdn)
      if r.nemail > 1:
        rclass = "dup2"
      else:
        rclass = "dup"
    else:
      r.nemail = 1
      if _l3match.match(r.fqdn):
        rclass = "l3"
      else:
        rclass = None
  r.rclass = rclass

def _rq1(request, r):
  wlist = []
  if r.action != 'N':
    wlist.append(r.fqdn)
  if r.action == 'D':
    err = None
    dbh = psycopg2.connect(autoreg.conf.dbstring)
    dd = autoreg.dns.db.db(dbh, True)
    dd.login('autoreg')
    oldout = sys.stdout
    sys.stdout = io.StringIO()
    try:
      dd.show(r.fqdn, None)
    except autoreg.dns.db.DomainError as e:
      if e.args[0] == autoreg.dns.db.DomainError.DNOTFOUND:
        err = _("Domain not found")
      elif e.args[0] == autoreg.dns.db.DomainError.ZNOTFOUND:
        err = _("Domain not found")
      else:
        raise

    if err:
      r.azout = err
    else:
      r.azout = sys.stdout.getvalue()
    sys.stdout = oldout

  w = []
  lastaddr = None
  if r.whoisrecord:
    for line in r.whoisrecord.split('\n'):
      m = _attrval.match(line)
      if not m:
        w.append(line)
      elif m.group(1) in ['tech-c', 'zone-c', 'admin-c']:
        if m.group(2) not in wlist:
          wlist.append(m.group(2))
        w.append(line)
      elif m.group(1) in ['changed', 'mnt-by', 'source']:
        continue
      elif m.group(1) == 'address' and len(m.group(2)) == 2:
        lastaddr = len(w)
        countryaddr = m.group(2)
        w.append(line)
      else:
        w.append(line)
    if lastaddr is not None:
      c = country_from_iso(countryaddr, connection.cursor())
      if c is not None:
        w[lastaddr] = 'address: ' + c
  w = '\n'.join(w)

  wlistout = []
  for k in wlist:
    wout = io.StringIO()
    query.query('-R ' + k, autoreg.conf.dbstring,
                wout, encoding=None, remote=False)
    wlistout.append((k, wout.getvalue().encode('UTF-8', 'xmlcharrefreplace')))
  r.whoisfiltered = w
  r.wlistout = wlistout
  return r

#
# public pages
#

def rqedit(request, rqid):
  if not request.user.is_authenticated():
    return HttpResponseRedirect(URILOGIN + '?next=%s' % request.path)
  login = admin_login(connection.cursor(), request.user.username)
  if not login:
    raise PermissionDenied
  r = models.Requests.objects.filter(id=rqid)
  if r.count() < 1:
    vars = RequestContext(request, {'msg': _('Request not found')})
    return render(request, 'requests/rqmsg.html', vars)
  r = r[0]
  if not autoreg.zauth.ZAuth(connection.cursor()).checkparent(r.fqdn, login):
    raise PermissionDenied
  if request.method == "GET":
    vars = RequestContext(request,
                          {'r': r,
                           'numdom': Whoisdomains.objects.all().count(),
                           'is_admin': check_is_admin(request.user.username)})
    return render(request, 'requests/rqedit.html', vars)
  elif request.method == 'POST':
    whoisrecord = request.POST.get('whois', '').strip('\n')
    r.tags = request.POST.get('tags', '').strip()
    if r.tags == '':
      r.tags = None
    if r.whoisrecord is not None:
      # Can only edit whois record when it is already existing
      r.whoisrecord = whoisrecord
    r.save()
    return HttpResponseRedirect(reverse(rq, args=[rqid]))
  else:
    raise SuspiciousOperation

def rq(request, rqid=None):
  if request.method != "GET" and request.method != "POST":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect(URILOGIN + '?next=%s' % request.path)
  login = admin_login(connection.cursor(), request.user.username)
  if not login:
    raise PermissionDenied

  if 'submitall' in request.POST:
    _rq = _hidden_rqid
  else:
    _rq = _rqid

  if request.method == 'POST':
    page = request.POST.get('page', '')
  else:
    page = request.GET.get('page', '')

  if rqid is not None:
    rqidlist = [rqid]
  else:
    rqidlist = []
    for c in request.POST.iterkeys():
      m = _rq.match(c)
      if m:
        rqidlist.append(m.group(1))
    rqidlist.sort()

  rlist = []
  i = 1
  for id in rqidlist:
    rset = models.Requests.objects.filter(id=id)
    if rset.count() < 1:
      if rqid is not None:
        # special case when called to display a single request
        raise Http404("")
      continue
    r = rset[0]
    if not autoreg.zauth.ZAuth(connection.cursor()).checkparent(r.fqdn, login):
      raise PermissionDenied
    _rq1(request, r)
    r.suffix = i
    if _rq_ndom(r.fqdn) == 1:
      r.default = "accept"
    else:
      r.default = "none"
    i += 1
    rlist.append(r)

  vars = RequestContext(request,
                        {'rlist': rlist, 'goto': page,
                         'numdom': Whoisdomains.objects.all().count(),
                         'is_admin': check_is_admin(request.user.username)})
  return render(request, 'requests/rqdisplay.html', vars)
  
def rqdom(request, domain):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect(URILOGIN + '?next=%s' % request.path)
  login = admin_login(connection.cursor(), request.user.username)
  if not login:
    raise PermissionDenied
  if domain.upper() != domain:
    return HttpResponseRedirect(reverse(rqlistdom, args=[domain.upper()]))

  rlist = _rq_list_dom(domain)
  i = 1
  for r in rlist:
    _rq1(request, r)
    r.suffix = i
    i += 1
  vars = RequestContext(request,
                {'rlist': rlist,
                 'goto': request.GET.get('page', ''),
                 'numdom': Whoisdomains.objects.all().count(),
                 'is_admin': check_is_admin(request.user.username)})
  return render(request, 'requests/rqdisplay.html', vars)

def rqdisplaychecked(request):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect(URILOGIN + '?next=%s' % request.path)
  login = admin_login(connection.cursor(), request.user.username)
  if not login:
    raise PermissionDenied

  rlist = _rq_list_dom(domain)
  i = 1
  for r in rlist:
    _rq1(request, r)
    r.suffix = i
    i += 1
  vars = RequestContext(request,
                {'rlist': rlist,
                 'goto': request.GET.get('page', ''),
                 'numdom': Whoisdomains.objects.all().count(),
                 'is_admin': check_is_admin(request.user.username)})
  return render(request, 'requests/rqdisplay.html', vars)

def rqlistdom(request, domain=None):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect(URILOGIN + '?next=%s' % request.path)
  login = admin_login(connection.cursor(), request.user.username)
  if not login:
    raise PermissionDenied
  if domain is None:
    # domain not in URL, provided by "?domain=..." argument (search form)
    domain = request.GET.get('domain', '').upper()
  elif domain.upper() != domain:
    return HttpResponseRedirect(reverse(rqlistdom, args=[domain.upper()]))

  z = autoreg.zauth.ZAuth(connection.cursor())

  rlist = _rq_list_dom(domain)
  for r in rlist:
    if not z.checkparent(r.fqdn, login):
      continue
    _rq_decorate(r)

  vars = RequestContext(request, {'rlist': rlist, 'fqdn': domain,
                                  'goto': request.GET.get('page', '') })
  return render(request, 'requests/rqlistdom.html', vars)

def rqlist(request, page='0'):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect(URILOGIN + '?next=%s' % request.path)
  login = admin_login(connection.cursor(), request.user.username)
  if not login:
    raise PermissionDenied

  email = request.GET.get('email', None)
  if email:
    rlist = _rq_list_email(email)
    nbypage = len(rlist)
    page = '1'
    cpage = request.GET.get('cpage', None)
  else:
    rlist = models.rq_list()
    nbypage = 100
    cpage = None
  num = len(rlist)

  npages = (num+nbypage-1) // nbypage
  if npages == 0:
    npages = 1
  page = int(page)
  if page > npages or page <= 0:
    return HttpResponseRedirect(reverse(rqlist, args=[str(npages)]))

  numdom = Whoisdomains.objects.all().count()

  z = autoreg.zauth.ZAuth(connection.cursor())

  rql = []
  for r in rlist[(page-1)*nbypage:page*nbypage]:
    if not z.checkparent(r.fqdn, login):
      continue
    _rq_decorate(r)
    rql.append(r)

  v = { 'cpage': cpage or page,
        'pages': range(1, npages+1),
        'rlist': rql,
        'numdom': numdom,
        'is_admin': check_is_admin(request.user.username)}
  if page != 1:
    v['prev'] = page-1
  if page < npages:
    v['next'] = page+1

  v = RequestContext(request, v)
  return render(request, 'requests/rqlist.html', v)

def _rqexec(rq, out, za, login, email, action, reasonfield):
  if not models.Requests.objects.filter(id=rq).exists():
    print(_("Request not found: %(rqid)s") % {'rqid': rq}, file=out)
    return
  r = models.Requests.objects.get(id=rq)
  if not za.checkparent(r.fqdn, login):
    print(_("Permission denied on %(rqid)s") % {'rqid': rq}, file=out)
    return

  if action == 'rejectcust':
    ok = r.reject(login, '', reasonfield)
    print(_("Rejected %(rqid)s (queued)") % {'rqid': rq}, file=out)
  elif action == 'rejectdup':
    with translation.override(r.language):
      reason = _('Duplicate request')
    ok = r.reject(login, reason, reasonfield)
    print(_("Rejected %(rqid)s (queued)") % {'rqid': rq}, file=out)
  elif action == 'rejectbog':
    with translation.override(r.language):
      reason = _('Bogus address information')
    ok = r.reject(login, reason, reasonfield)
    print(_("Rejected %(rqid)s (queued)") % {'rqid': rq}, file=out)
  elif action == 'rejectful':
    with translation.override(r.language):
      reason = _('Please provide a full name')
    ok = r.reject(login, reason, reasonfield)
    print(_("Rejected %(rqid)s (queued)") % {'rqid': rq}, file=out)
  elif action == 'rejectnok':
    with translation.override(r.language):
      reason = _('Sorry, this domain is already allocated')
    ok = r.reject(login, reason, reasonfield)
    print(_("Rejected %(rqid)s (queued)") % {'rqid': rq}, file=out)
  elif action == 'accept':
    ok = r.accept(login, email, reasonfield)
    print(_("Accepted %(rqid)s (queued)") % {'rqid': rq}, file=out)
  else:
    if action == 'delete':
      r.remove('DelQuiet');
      print(_("Deleted %(rqid)s") % {'rqid': rq}, file=out)
    elif action == 'none':
      print(_("Nothing done on %(rqid)s") % {'rqid': rq}, file=out)
    else:
      print(_("What? On rq=%(rqid)s action=%(action)s reason=%(reason)s") \
              % (rq, action, reason),
            file=out)

@transaction.non_atomic_requests
def rqval(request):
  if request.method != "POST":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    raise PermissionDenied
  login, email = admin_login(connection.cursor(), request.user.username,
                             get_email=True)
  if not login:
    raise PermissionDenied

  za = autoreg.zauth.ZAuth(connection.cursor())
  out = io.StringIO()

  i = 1
  allok = True
  while 'action' + str(i) in request.POST:
    action = request.POST['action' + str(i)]
    rq = request.POST['rq' + str(i)]
    reason = request.POST['reason' + str(i)].strip()
    print(_("Processing %(rqid)s...") % {'rqid': rq}, file=out)

    with transaction.atomic():
      try:
        _rqexec(rq, out, za, login, email, action, reason)
      except IntegrityError as e:
        print(unicode(e), file=out)
        allok = False

    i += 1

  if 'goto' in request.POST and request.POST['goto']:
    goto = reverse(rqlist, args=[request.POST['goto']])
  else:
    goto = ''

  if allok and goto:
    return HttpResponseRedirect(goto)

  vars = RequestContext(request,
                {'out': out.getvalue(), 'goto': goto,
                 'numdom': Whoisdomains.objects.all().count(),
                 'is_admin': check_is_admin(request.user.username)})
  page = render(request, 'requests/rqval.html', vars)
  return page

def rqloglist(request):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    raise PermissionDenied
  is_admin = check_is_admin(request.user.username)
  if not is_admin:
    raise PermissionDenied
  log = models.RequestsLog.objects.all().order_by('-date')
  paginator = Paginator(log, 100)

  page = request.GET.get('page')
  try:
    logpage = paginator.page(page)
  except PageNotAnInteger:
    logpage = paginator.page(1)
  except EmptyPage:
    logpage = paginator.page(paginator.num_pages)

  vars = RequestContext(request, {'is_admin': is_admin, 'list': logpage,
                                  'numdom': Whoisdomains.objects.all().count()})
  return render(request, 'requests/rqloglist.html', vars)

def rqlogdisplay(request, id):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    raise PermissionDenied
  is_admin = check_is_admin(request.user.username)
  if not is_admin:
    raise PermissionDenied
  rql = models.RequestsLog.objects.get(id=id)
  vars = RequestContext(request, {'is_admin': is_admin, 'rql': rql,
                                  'numdom': Whoisdomains.objects.all().count()})
  return render(request, 'requests/rqlogdisplay.html', vars)
