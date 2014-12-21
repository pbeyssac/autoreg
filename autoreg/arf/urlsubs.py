# $Id$

from django.conf.urls import patterns, include

urlpatterns = patterns('autoreg.arf.whois.views',
    (r'^$', 'index'),
    (r'^login/$', 'login'),
    (r'^logout/$', 'logout'),
    (r'^contact/change/$', 'contactchange'),
    (r'^contact/changemail/$', 'changemail'),
    (r'^contact/chpass/$', 'chpass'),
    (r'^contact/domains/$', 'domainlist'),
    (r'^domain/edit/(?P<fqdn>[A-Z0-9\.-]+)/$', 'domainedit'),
    (r'^domain/edit/confirm/(?P<fqdn>[A-Z0-9\.-]+)/$', 'domaineditconfirm'),
    (r'^registrant/edit/(?P<registrantdomain>[A-Z0-9\.-]+)/$', 'contactchange'),
    # The following are special for lost password handling;
    # putting these under /contact/... is not quite correct as they are
    # not private.
    (r'^contact/create/$', 'contactcreate'),
    (r'^contact/reset/$', 'makeresettoken'),
    (r'^contact/reset/(?P<handle>[A-Z0-9]+)$', 'makeresettoken'),
    (r'^contact/doreset/(?P<handle>[A-Z0-9]+)/$', 'resetpass2'),
    (r'^contact/validate/(?P<handle>[A-Z0-9]+)/(?P<valtoken>[a-zA-Z0-9]+)/$', 'contactvalidate'),
    (r'^contact/bydom$', 'contactbydomain'),
    (r'^contact/bydom/(?P<fqdn>[A-Z0-9\.-]+)$', 'contactbydomain'),
)
urlpatterns += patterns('autoreg.arf.requests.views',
    (r'^rq/(?P<rqid>[a-z0-9-]+)$', 'rq'),
    (r'^rqe/(?P<rqid>[a-z0-9-]+)$', 'rqedit'),
    (r'^rqd/(?P<domain>[a-z0-9\.A-Z-]+)$', 'rqdom'),
    (r'^r/$', 'rqlist'),
    (r'^r/(?P<page>[0-9]+)$', 'rqlist'),
    (r'^rd$', 'rqlistdom'),
    (r'^rd/(?P<domain>[a-z0-9\.A-Z-]+)$', 'rqlistdom'),
    (r'^re/(?P<email>.+@[a-zA-Z0-9\.-]+)$', 'rqlistemail'),
    (r'^val$', 'rqval'),
)
urlpatterns += patterns('autoreg.arf.dns.views',
    (r'^soa/(?P<domain>[a-z0-9\.A-Z-]+)$', 'checksoa'),
    (r'^ds/(?P<fqdn>[a-z0-9\.A-Z-]+)/$', 'domainds'),
    (r'^ns/(?P<fqdn>[a-z0-9\.A-Z-]+)/$', 'domainns'),
    (r'^domain/new/$', 'domainns'),
)
