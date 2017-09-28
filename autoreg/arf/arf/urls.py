# $Id$

from django.conf.urls import include, url
from django.conf.urls.i18n import i18n_patterns

import autoreg.arf.arf.urlsubs


urlpatterns = i18n_patterns(
    url(r'^', include(autoreg.arf.arf.urlsubs.urlpatterns))
)
