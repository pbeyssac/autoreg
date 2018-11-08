# $Id$

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


from django.core.exceptions import SuspiciousOperation
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import render


from .models import Log
from ..whois.decorators import login_active_required, admin_required


@login_active_required
@admin_required
def loglist(request):
  if request.method != "GET":
    raise SuspiciousOperation
  log = Log.objects.all().order_by('-date')
  paginator = Paginator(log, 100)

  page = request.GET.get('page')
  try:
    logpage = paginator.page(page)
  except PageNotAnInteger:
    logpage = paginator.page(1)
  except EmptyPage:
    logpage = paginator.page(paginator.num_pages)

  vars = {'list': logpage }

  return render(request, 'logs/log.html', vars)
