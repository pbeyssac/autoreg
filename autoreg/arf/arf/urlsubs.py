# $Id$

from django.conf.urls import include, url
from django.contrib import admin

import autoreg.arf.logs.views as logs_views
import autoreg.arf.requests.views as requests_views
import autoreg.arf.webdns.views as webdns_views
import autoreg.arf.whois.views as whois_views


urlpatterns = [
  url(r'^$', whois_views.domainlist),
  url(r'^login/$', whois_views.login),
  url(r'^logout/$', whois_views.logout),
  url(r'^contact/change/$', whois_views.contactchange),
  url(r'^contact/changemail/$', whois_views.changemail),
  url(r'^contact/chpass/$', whois_views.chpass),
  url(r'^domain/list/(?P<handle>[A-Z0-9]+)$', whois_views.domainlist),
  url(r'^domain/edit/(?P<fqdn>[a-zA-Z0-9\.-]+)/$', whois_views.domainedit),
  url(r'^domain/edit/confirm/(?P<fqdn>[a-zA-Z0-9\.-]+)/$',
        whois_views.domaineditconfirm),
  url(r'^domain/del/(?P<fqdn>[a-z0-9\.-]+)/$',
        whois_views.domaindelete),
  url(r'^domain/undel/(?P<fqdn>[a-z0-9\.-]+)/$',
        whois_views.domainundelete),
  url(r'^registrant/edit/(?P<registrantdomain>[a-zA-Z0-9\.-]+)/$',
        whois_views.contactchange),
  # The following are special for lost password handling;
  # putting these under /contact/... is not quite correct as they are
  # not private.
  url(r'^contact/create/$', whois_views.contactcreate),
  url(r'^contact/reset/$', whois_views.makeresettoken),
  url(r'^contact/reset/(?P<handle>[A-Z0-9]+)$',
        whois_views.makeresettoken),
  url(r'^contact/doreset/(?P<handle>[A-Z0-9]+)/$', whois_views.resetpass2),
  url(r'^contact/validate/(?P<handle>[A-Z0-9]+)/(?P<valtoken>[a-zA-Z0-9]+)/$',
        whois_views.contactvalidate),
  url(r'^contact/bydom$', whois_views.contactbydomain),
  url(r'^contact/bydom/(?P<fqdn>[a-zA-Z0-9\.-]+)$',
        whois_views.contactbydomain)
]
urlpatterns += [
  url(r'^log$', logs_views.loglist)
]
urlpatterns += [
  url(r'^rq/(?P<rqid>[a-z0-9-]+)$', requests_views.rq),
  url(r'^rq$', requests_views.rq),
  url(r'^rqe/(?P<rqid>[a-z0-9-]+)$', requests_views.rqedit),
  url(r'^rqd/(?P<domain>[a-z0-9\.A-Z-]+)$', requests_views.rqdom),
  url(r'^r/$', requests_views.rqlist),
  url(r'^r/(?P<page>[0-9]+)$', requests_views.rqlist),
  url(r'^rd$', requests_views.rqlistdom),
  url(r'^rd/(?P<domain>[a-z0-9\.A-Z-]+)$', requests_views.rqlistdom),
  url(r'^rl$', requests_views.rqloglist),
  url(r'^rl/(?P<id>[0-9]+)$', requests_views.rqlogdisplay),
  url(r'^val$', requests_views.rqval)
]
urlpatterns += [
  url(r'^soa/(?P<domain>)$', webdns_views.checksoa),
  url(r'^soa/(?P<domain>[a-z0-9\.A-Z-]+)$', webdns_views.checksoa),
  url(r'^ds/(?P<fqdn>[a-z0-9\.A-Z-]+)/$', webdns_views.domainds),
  url(r'^ns/(?P<fqdn>[a-z0-9\.A-Z-]+)/$', webdns_views.domainns),
  url(r'^domain/new/$', webdns_views.domainns),
  url(r'^special/$', webdns_views.special),
]
urlpatterns += [
  # Uncomment this for admin:
  url(r'^admin/', include(admin.site.urls))
]
