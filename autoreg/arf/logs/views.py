# $Id$

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import render
from django.views.decorators.http import require_http_methods


from .models import Log
from ..whois.decorators import login_active_required, admin_required


@require_http_methods(["GET"])
@login_active_required
@admin_required
def loglist(request):
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
