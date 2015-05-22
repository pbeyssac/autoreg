# $Id$

from __future__ import print_function

import io
import re
import subprocess
import sys

import psycopg2

import autoreg.conf
import autoreg.dns.db
from autoreg.whois.db import admin_login, country_from_iso
import autoreg.whois.query as query
import autoreg.zauth

from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.core.urlresolvers import reverse, reverse_lazy
from django.db import connection, transaction, IntegrityError
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext

import models


URILOGIN = reverse_lazy('autoreg.arf.whois.views.login')

_l3match = re.compile('^[^\.]+\.[^\.]+\.[^\.]+\..+$')
_attrval = re.compile('^([a-z0-9A-Z-]+):\s*(.*[^\s]+|)\s*$')

#
# 'view' functions called from urls.py and friends
#

#
# private helper functions
#

def _rq_list_unordered():
  return models.Requests.objects.exclude(state='WaitAck')

def _rq_list():
  return _rq_list_unordered().order_by('id')

def _rq_list_dom(domain):
  domain = domain.upper()
  return _rq_list().filter(fqdn=domain)

def _rq_list_email(email):
  return _rq_list().filter(email=email)

def _rq_num():
  """Return the number of pending requests"""
  return _rq_list_unordered().count()

def _rq_ndom(fqdn):
  """Return the number of pending requests for fqdn"""
  return _rq_list_unordered().filter(fqdn=fqdn).count()

def _rq_nemail(fqdn):
  """Return the number of distinct emails in the pending requests for fqdn"""
  return _rq_list_unordered().filter(fqdn=fqdn) \
         .order_by('email').distinct('email').count()

def _rq_remove(rqid, state):
  r = models.Requests.objects.get(id=rqid)
  r.state = state
  r.save()
  r.delete()

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
        err = "Domain not found"
      elif e.args[0] == autoreg.dns.db.DomainError.ZNOTFOUND:
        err = "Domain not found"
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
      w[lastaddr] = 'address: ' + country_from_iso(countryaddr,
                                                   connection.cursor())
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
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  login = admin_login(connection.cursor(), request.user.username)
  if not login:
    raise PermissionDenied
  r = models.Requests.objects.filter(id=rqid)
  if r.count() < 1:
    vars = RequestContext(request, {'msg': 'Request not found'})
    return render_to_response('requests/rqmsg.html', vars)
  r = r[0]
  if not autoreg.zauth.ZAuth(connection.cursor()).checkparent(r.fqdn, login):
    raise PermissionDenied
  if request.method == "GET":
    vars = RequestContext(request, {'r': r})
    return render_to_response('requests/rqedit.html', vars)
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

def rq(request, rqid):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  login = admin_login(connection.cursor(), request.user.username)
  if not login:
    raise PermissionDenied
  r = models.Requests.objects.filter(id=rqid)
  if r.count() < 1:
    vars = RequestContext(request, {'msg': 'Request not found'})
    return render_to_response('requests/rqmsg.html', vars)
  r = r[0]
  if not autoreg.zauth.ZAuth(connection.cursor()).checkparent(r.fqdn, login):
    raise PermissionDenied
  _rq1(request, r)
  r.suffix = 1
  vars = RequestContext(request, {'rlist': [r]})
  return render_to_response('requests/rqdisplay.html', vars)
  
def rqdom(request, domain):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
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
  vars = RequestContext(request, {'rlist': rlist})
  return render_to_response('requests/rqdisplay.html', vars)

def rqlistdom(request, domain=None):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
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

  vars = RequestContext(request, {'rlist': rlist, 'fqdn': domain})
  return render_to_response('requests/rqlistdom.html', vars)

def rqlistemail(request, email):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  login = admin_login(connection.cursor(), request.user.username)
  if not login:
    raise PermissionDenied

  z = autoreg.zauth.ZAuth(connection.cursor())

  rlist = _rq_list_email(email)
  for r in rlist:
    if not z.checkparent(r.fqdn, login):
      continue
    _rq_decorate(r)

  vars = RequestContext(request, {'rlist': rlist, 'email': email})
  return render_to_response('requests/rqlistemail.html', vars)

def rqlist(request, page='0'):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  login = admin_login(connection.cursor(), request.user.username)
  if not login:
    raise PermissionDenied

  nbypage = 100
  num = _rq_num()
  npages = (num+nbypage-1) // nbypage
  if npages == 0:
    npages = 1
  page = int(page)
  if page > npages or page <= 0:
    return HttpResponseRedirect(reverse(rqlist, args=[str(npages)]))

  z = autoreg.zauth.ZAuth(connection.cursor())

  rql = []
  for r in _rq_list()[(page-1)*nbypage:page*nbypage]:
    if not z.checkparent(r.fqdn, login):
      continue
    _rq_decorate(r)
    rql.append(r)

  v = { 'cpage': page,
        'pages': range(1, npages+1),
        'rlist': rql }
  if page != 1:
    v['prev'] = page-1
  if page < npages:
    v['next'] = page+1

  v = RequestContext(request, v)
  return render_to_response('requests/rqlist.html', v)

def _rqexec(rq, out, za, login, email, action, reasonfield):
  if not models.Requests.objects.filter(id=rq).exists():
    print("Request not found: %s" % rq, file=out)
    return
  r = models.Requests.objects.get(id=rq)
  if not za.checkparent(r.fqdn, login):
    print("Permission denied on %s" % rq, file=out)
    return

  has_transaction = True
  if action == 'rejectcust':
    ok = models.rq_reject(out, rq, login, '', reasonfield)
  elif action == 'rejectdup':
    ok = models.rq_reject(out, rq, login, 'Duplicate request', reasonfield)
  elif action == 'rejectbog':
    ok = models.rq_reject(out, rq, login,
                          'Bogus address information', reasonfield)
  elif action == 'rejectful':
    ok = models.rq_reject(out, rq, login,
                          'Please provide a full name', reasonfield)
  elif action == 'rejectnok':
    ok = models.rq_reject(out, rq, login,
                          'Sorry, this domain is already allocated',
                          reasonfield)
  elif action == 'accept':
    ok = models.rq_accept(out, rq, login, email, reasonfield)
  else:
    if action == 'delete':
      _rq_remove(rq, 'DelQuiet');
      print("Deleted %s" % rq, file=out)
    elif action == 'none':
      print("Nothing done on %s" % rq, file=out)
    else:
      print("What? On rq=%s action=%s reason=%s" % (rq, action, reason),
            file=out)
    has_transaction = False

  if has_transaction:
    if ok:
      print(u"Status: committed", file=out)
    else:
      print(u"Status: cancelled", file=out)
      # raise to force a transaction rollback by Django
      raise IntegrityError("")

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
  while 'action' + str(i) in request.POST:
    action = request.POST['action' + str(i)]
    rq = request.POST['rq' + str(i)]
    reason = request.POST['reason' + str(i)]
    print("Processing %s..." % rq, file=out)

    with transaction.atomic():
      try:
        _rqexec(rq, out, za, login, email, action, reason)
      except IntegrityError as e:
        print(unicode(e), file=out)

    i += 1

  vars = RequestContext(request, {'out': out.getvalue()})
  page = render_to_response('requests/rqval.html', vars)
  return page
