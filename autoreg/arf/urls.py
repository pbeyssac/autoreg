# $Id$

from django.conf.urls.defaults import *

urlpatterns = patterns('autoreg.arf.whois.views',
    #(r'^whois/(?P<fqdn>[A-Za-z0-9.-]+)$', 'domain'),
    #(r'^whois/(?P<id>\d+)$', include('domain')),
    #(r'^contact/(?P<handle>[A-Z0-9]+)$', 'contact'),
    #(r'^contact/(?P<handle>[A-Z0-9]+)/$', 'contact'),
    (r'^', include('autoreg.arf.urlsubs')),
)

urlpatterns += patterns('',
    # Uncomment this for admin:
#    (r'^admin/', include('django.contrib.admin.urls')),
)
