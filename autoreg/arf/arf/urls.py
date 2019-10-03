# $Id$

from django.conf.urls.i18n import i18n_patterns
from django.urls import include, path


urlpatterns = i18n_patterns(
    path('', include('autoreg.arf.arf.urlsubs'))
)
