# $Id$

from django.core.exceptions import SuspiciousOperation, PermissionDenied
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import render
from django.template import RequestContext
from django.utils.translation import ugettext_lazy, ugettext as _

from autoreg.whois.db import HANDLESUFFIX

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
  log = Log.objects.select_related('contact__handle').all().order_by('-date')
  paginator = Paginator(log, 100)

  page = request.GET.get('page')
  try:
    logpage = paginator.page(page)
  except PageNotAnInteger:
    logpage = paginator.page(1)
  except EmptyPage:
    logpage = paginator.page(paginator.num_pages)

  vars = RequestContext(request, {'is_admin': is_admin, 'log': logpage,
                                  'suffix': HANDLESUFFIX,
                                  'numdom': Whoisdomains.objects.all().count()})

  return render(request, 'logs/log.html', vars)