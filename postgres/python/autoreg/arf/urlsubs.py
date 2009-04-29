# $Id$

from django.conf.urls.defaults import *

urlpatterns = patterns('autoreg.arf.whois.views',
    (r'^$', 'index'),
    (r'^login/$', 'login'),
    (r'^logout/$', 'logout'),
    (r'^contact/change/$', 'contactchange'),
    (r'^contact/changemail/$', 'changemail'),
    (r'^contact/chpass/$', 'chpass'),
    (r'^contact/domains/$', 'domainlist'),
    # The following are special for lost password handling;
    # putting these under /contact/... is not quite correct as they are
    # not private.
    (r'^contact/create/$', 'contactcreate'),
    (r'^contact/reset/$', 'makeresettoken'),
    (r'^contact/doreset/(?P<handle>[A-Z0-9]+)/$', 'resetpass2'),
    (r'^contact/validate/(?P<handle>[A-Z0-9]+)/(?P<valtoken>[a-zA-Z0-9]+)/$', 'contactvalidate'),
)
