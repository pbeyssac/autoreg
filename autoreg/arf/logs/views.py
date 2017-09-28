# $Id$

from django.core.exceptions import SuspiciousOperation, PermissionDenied
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import render
from django.utils.translation import ugettext_lazy, ugettext as _

from autoreg.conf import HANDLESUFFIX, SITENAME

from models import Log
from ..whois.models import Whoisdomains, check_is_admin


def loglist(request):
  if request.method != "GET":
    raise SuspiciousOperation
  if not request.user.is_authenticated():
    raise PermissionDenied
  is_admin = check_is_admin(request.user.username)
  if not is_admin:
    raise PermissionDenied
  log = Log.objects.all().order_by('-date')
  paginator = Paginator(log, 100)

  page = request.GET.get('page')
  try:
    logpage = paginator.page(page)
  except PageNotAnInteger:
    logpage = paginator.page(1)
  except EmptyPage:
    logpage = paginator.page(paginator.num_pages)

  vars = {'is_admin': is_admin, 'list': logpage,
          'suffix': HANDLESUFFIX,
          'sitename': SITENAME,
          'numdom': Whoisdomains.objects.all().count()}

  return render(request, 'logs/log.html', vars)
