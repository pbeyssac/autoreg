# $Id$

from django.conf.urls import patterns, include, url
from django.conf.urls.i18n import i18n_patterns

urlpatterns = i18n_patterns('autoreg.arf.whois.views',
    #url(r'^whois/(?P<fqdn>[A-Za-z0-9.-]+)$', 'domain'),
    #url(r'^whois/(?P<id>\d+)$', include('domain')),
    #url(r'^contact/(?P<handle>[A-Z0-9]+)$', 'contact'),
    #url(r'^contact/(?P<handle>[A-Z0-9]+)/$', 'contact'),
    url(r'^', include('autoreg.arf.arf.urlsubs')),
)

)
