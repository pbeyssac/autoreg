# $Id$

from django.conf.urls import patterns, include, url

urlpatterns = patterns('autoreg.arf.whois.views',
    url(r'^$', 'domainlist'),
    url(r'^login/$', 'login'),
    url(r'^logout/$', 'logout'),
    url(r'^contact/change/$', 'contactchange'),
    url(r'^contact/changemail/$', 'changemail'),
    url(r'^contact/chpass/$', 'chpass'),
    url(r'^domain/edit/(?P<fqdn>[a-zA-Z0-9\.-]+)/$', 'domainedit'),
    url(r'^domain/edit/confirm/(?P<fqdn>[a-zA-Z0-9\.-]+)/$', 'domaineditconfirm'),
    url(r'^domain/del/(?P<fqdn>[a-z0-9\.-]+)/$', 'domaindelete'),
    url(r'^domain/undel/(?P<fqdn>[a-z0-9\.-]+)/$', 'domainundelete'),
    url(r'^registrant/edit/(?P<registrantdomain>[a-zA-Z0-9\.-]+)/$', 'contactchange'),
    # The following are special for lost password handling;
    # putting these under /contact/... is not quite correct as they are
    # not private.
    url(r'^contact/create/$', 'contactcreate'),
    url(r'^contact/reset/$', 'makeresettoken'),
    url(r'^contact/reset/(?P<handle>[A-Z0-9]+)$', 'makeresettoken'),
    url(r'^contact/doreset/(?P<handle>[A-Z0-9]+)/$', 'resetpass2'),
    url(r'^contact/validate/(?P<handle>[A-Z0-9]+)/(?P<valtoken>[a-zA-Z0-9]+)/$', 'contactvalidate'),
    url(r'^contact/bydom$', 'contactbydomain'),
    url(r'^contact/bydom/(?P<fqdn>[a-zA-Z0-9\.-]+)$', 'contactbydomain'),
)
urlpatterns += patterns('autoreg.arf.requests.views',
    url(r'^rq/(?P<rqid>[a-z0-9-]+)$', 'rq'),
    url(r'^rqe/(?P<rqid>[a-z0-9-]+)$', 'rqedit'),
    url(r'^rqd/(?P<domain>[a-z0-9\.A-Z-]+)$', 'rqdom'),
    url(r'^r/$', 'rqlist'),
    url(r'^r/(?P<page>[0-9]+)$', 'rqlist'),
    url(r'^rd$', 'rqlistdom'),
    url(r'^rd/(?P<domain>[a-z0-9\.A-Z-]+)$', 'rqlistdom'),
    url(r'^re/(?P<email>.+@[a-zA-Z0-9\.-]+)$', 'rqlistemail'),
    url(r'^rl$', 'rqloglist'),
    url(r'^rl/(?P<id>[0-9]+)$', 'rqlogdisplay'),
    url(r'^val$', 'rqval'),
)
urlpatterns += patterns('autoreg.arf.dns.views',
    url(r'^soa/(?P<domain>[a-z0-9\.A-Z-]+)$', 'checksoa'),
    url(r'^ds/(?P<fqdn>[a-z0-9\.A-Z-]+)/$', 'domainds'),
    url(r'^ns/(?P<fqdn>[a-z0-9\.A-Z-]+)/$', 'domainns'),
    url(r'^domain/new/$', 'domainns'),
)
