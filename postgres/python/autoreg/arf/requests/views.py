# $Id$

import re
import StringIO
import sys

import psycopg2

import autoreg.arf.requests.models
import autoreg.conf
import autoreg.dns.db
import autoreg.whois.query as query
import autoreg.zauth

from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.core.urlresolvers import reverse, reverse_lazy
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response

URILOGIN = reverse_lazy('autoreg.arf.whois.views.login')

_l3match = re.compile('^[^\.]+\.[^\.]+\.[^\.]+\..+$')
_attrval = re.compile('^([a-z0-9A-Z-]+):\s*(.*[^\s]+|)$')

#
# 'view' functions called from urls.py and friends
#

#
# private helper functions
#

def _rq_list_unordered():
  return autoreg.arf.requests.models.Requests.objects \
         .exclude(state='WaitAck')

def _rq_list():
  return _rq_list_unordered().order_by('id')

def _rq_list_dom(domain):
  domain = domain.upper()
  return _rq_list().filter(fqdn=domain)

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

def _is_admin(user):
  """Return True if the current user is in the admins table"""
  return autoreg.arf.requests.models.Admins.objects \
         .filter(contact__handle=user.username).exists()

def _get_login(user):
  """Get the Unix login of the given user from the admins table"""
  return autoreg.arf.requests.models.Admins.objects \
         .filter(contact__handle=user.username)[0].login

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
    dbh = psycopg2.connect(autoreg.conf.dbstring)
    dd = autoreg.dns.db.db(dbh, True)
    dd.login('autoreg')
    oldout = sys.stdout
    sys.stdout = StringIO.StringIO()
    dd.show(r.fqdn, None)
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
    wout = StringIO.StringIO('')
    query.query('-R ' + k, autoreg.conf.dbstring,
                wout, encoding='UTF-8', remote=False)
    wlistout.append((k, wout.getvalue()))
  r.whoisfiltered = w
  r.wlistout = wlistout
  return r

#
# public pages
#

def rqedit(request, rqid):
  if not request.user.is_authenticated():
    return HttpResponseRedirect(URILOGIN)
  if not _is_admin(request.user):
    raise PermissionDenied
  r = autoreg.arf.requests.models.Requests.objects.get(id=rqid)
  if not autoreg.zauth.ZAuth().checkparent(r.fqdn, _get_login(request.user)):
    raise PermissionDenied
  if request.method == "GET":
    return render_to_response('requests/rqedit.html',
                              { 'r': r })
  elif request.method == 'POST':
    whoisrecord = request.POST['whois'].strip('\n')
    r.whoisrecord = whoisrecord
    r.save()
    return HttpResponseRedirect(reverse('autoreg.arf.requests.views.rq',
                                        args=[rqid]))
  else:
    raise SuspiciousOperation

def rq(request, rqid):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect(URILOGIN)
  if not _is_admin(request.user):
    raise PermissionDenied
  r = autoreg.arf.requests.models.Requests.objects.get(id=rqid)
  if not autoreg.zauth.ZAuth().checkparent(r.fqdn, _get_login(request.user)):
    raise PermissionDenied
  _rq1(request, r)
  r.suffix = 1
  return render_to_response('requests/rqdisplay.html',
                            { 'rlist': [r] })
  
def rqdom(request, domain):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect(URILOGIN)
  if not _is_admin(request.user):
    raise PermissionDenied
  if domain.upper() != domain:
    return HttpResponseRedirect(reverse('autoreg.arf.requests.views.rqlistdom',
                                        args=[domain.upper()]))

  rlist = _rq_list_dom(domain)
  i = 1
  for r in rlist:
    _rq1(request, r)
    r.suffix = i
    i += 1
  return render_to_response('requests/rqdisplay.html',
                            { 'rlist': rlist })

def rqlistdom(request, domain):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect(URILOGIN)
  if not _is_admin(request.user):
    raise PermissionDenied
  if domain.upper() != domain:
    return HttpResponseRedirect(reverse('autoreg.arf.requests.views.rqlistdom',
                                        args=[domain.upper()]))

  z = autoreg.zauth.ZAuth()
  login =  _get_login(request.user)

  rlist = _rq_list_dom(domain)
  for r in rlist:
    if not z.checkparent(r.fqdn, login):
      continue
    _rq_decorate(r)

  return render_to_response('requests/rqlistdom.html',
                            { 'rlist': rlist, 'fqdn': domain })

def rqlist(request, page=None):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    return HttpResponseRedirect(URILOGIN)
  if not _is_admin(request.user):
    raise PermissionDenied

  nbypage = 100
  num = _rq_num()
  npages = (num+nbypage-1) // nbypage
  if page is None:
    page = npages-1
  else:
    page = int(page)

  z = autoreg.zauth.ZAuth()
  login =  _get_login(request.user)

  rql = []
  for r in _rq_list()[page*nbypage:(page+1)*nbypage]:
    if not z.checkparent(r.fqdn, login):
      continue
    _rq_decorate(r)
    rql.append(r)

  v = { 'cpage': page,
        'pages': range(npages),
        'rlist': rql }
  if page != 0:
    v['prev'] = page-1
  if page < npages-1:
    v['next'] = page+1

  return render_to_response('requests/rqlist.html', v)

