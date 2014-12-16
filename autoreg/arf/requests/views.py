# $Id$

from __future__ import print_function

import io
import re
import subprocess
import sys

import psycopg2

import autoreg.conf
import autoreg.dns.db
from autoreg.whois.db import admin_login
import autoreg.whois.query as query
import autoreg.zauth

from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.core.urlresolvers import reverse, reverse_lazy
from django.db import connection, transaction
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response

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
      else:
        w.append(line)
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
    return render_to_response('requests/rqmsg.html',
                              {'msg': 'Request not found'})
  r = r[0]
  if not autoreg.zauth.ZAuth().checkparent(r.fqdn, login):
    raise PermissionDenied
  if request.method == "GET":
    return render_to_response('requests/rqedit.html',
                              { 'r': r })
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
    return render_to_response('requests/rqmsg.html',
                              {'msg': 'Request not found'})
  r = r[0]
  if not autoreg.zauth.ZAuth().checkparent(r.fqdn, login):
    raise PermissionDenied
  _rq1(request, r)
  r.suffix = 1
  return render_to_response('requests/rqdisplay.html',
                            { 'rlist': [r] })
  
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
  return render_to_response('requests/rqdisplay.html',
                            { 'rlist': rlist })

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

  z = autoreg.zauth.ZAuth()

  rlist = _rq_list_dom(domain)
  for r in rlist:
    if not z.checkparent(r.fqdn, login):
      continue
    _rq_decorate(r)

  return render_to_response('requests/rqlistdom.html',
                            { 'rlist': rlist, 'fqdn': domain })

def rqlistemail(request, email):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect((URILOGIN + '?next=%s') % request.path)
  login = admin_login(connection.cursor(), request.user.username)
  if not login:
    raise PermissionDenied

  z = autoreg.zauth.ZAuth()

  rlist = _rq_list_email(email)
  for r in rlist:
    if not z.checkparent(r.fqdn, login):
      continue
    _rq_decorate(r)

  return render_to_response('requests/rqlistemail.html',
                            { 'rlist': rlist, 'email': email })

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

  z = autoreg.zauth.ZAuth()

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

  return render_to_response('requests/rqlist.html', v)

def _doaccept(out, rqid, login):
  output = subprocess.check_output([autoreg.conf.DOACCEPT_PATH, rqid, login])
  out.write(output.decode('UTF-8'))

def _doreject(out, rqid, login, creason, csubmit):
  output = subprocess.check_output([autoreg.conf.DOREJECT_PATH, rqid, login,
                                   creason.encode('UTF-8'),
                                   csubmit.encode('UTF-8')])
  out.write(output.decode('UTF-8'))

def _rqexec(rq, out, za, login, action, reason):

  if action == 'rejectcust':
    _doreject(out, rq, login, reason, reason)
  elif action == 'rejectdup':
    _doreject(out, rq, login, reason, 'Duplicate request')
  elif action == 'rejectbog':
    _doreject(out, rq, login, reason, 'Bogus address information')
  elif action == 'rejectful':
    _doreject(out, rq, login, reason, 'Please provide a full name')
  elif action == 'rejectnok':
    _doreject(out, rq, login, reason, 'Sorry, this domain is already allocated')
  elif action == 'accept':
    _doaccept(out, rq, login)
  else:
    if not models.Requests.objects.filter(id=rq).exists():
      print("Request not found: %s<P>" % rq, file=out)
      return
    r = models.Requests.objects.get(id=rq)
    if not za.checkparent(r.fqdn, login):
      print("Permission denied on %s<P>" % rq, file=out)
      return
    if action == 'delete':
      _rq_remove(rq, 'DelQuiet');
      print("Deleted %s<P>" % rq, file=out)
    elif action == 'none':
      print("Nothing done on %s<P>" % rq, file=out)
    else:
      print("What? On rq=%s action=%s reason=%s<P>" % (rq, action, reason),
            file=out)

@transaction.commit_manually
def rqval(request):
  if request.method != "POST":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    raise PermissionDenied
  login = admin_login(connection.cursor(), request.user.username)
  if not login:
    raise PermissionDenied

  za = autoreg.zauth.ZAuth()
  out = io.StringIO()

  # get our current transaction out of the way
  # (has a lock on the user's row in the "contacts" table due to the above)
  # to avoid deadlocking subprocesses
  transaction.commit()

  i = 1
  while 'action' + str(i) in request.POST:
    action = request.POST['action' + str(i)]
    rq = request.POST['rq' + str(i)]
    reason = request.POST['reason' + str(i)]
    print("Processing %s...<P>" % rq, file=out)
    _rqexec(rq, out, za, login, action, reason)
    i += 1

  page = render_to_response('requests/rqval.html', { 'out': out.getvalue() })
  # the above may yield a SELECT to the ISO countries table, so
  # we need to put the last commit right there below.
  transaction.commit()
  return page
