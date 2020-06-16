# $Id$

from django.contrib import admin
from django.urls import path, re_path

import autoreg.arf.logs.views as logs_views
import autoreg.arf.requests.views as requests_views
import autoreg.arf.webdns.views as webdns_views
import autoreg.arf.whois.otp_views as otp_views
import autoreg.arf.whois.views as whois_views


urlpatterns = [
  path('', whois_views.domainlist, name='domainlist'),
  path('login/', whois_views.login, name='login'),
  path('logout/', whois_views.logout, name='logout'),
  path('contact/change/', whois_views.contactchange, name='contactchange'),
  path('contact/changemail/', whois_views.changemail),
  path('contact/chpass/', whois_views.chpass, name='chpass'),
  path('2fa/login/', otp_views.totplogin, name='login2fa'),
  path('2fa/', otp_views.totp, name='2fa'),
  path('2fa/set/1', otp_views.totpsetup1, name='2fa-setup1'),
  path('2fa/set/2', otp_views.totpsetup2, name='2fa-setup2'),
  path('2fa/clear', otp_views.totpclear, name='2fa-clear'),
  path('2fa/newrecovery', otp_views.totpnewrecovery, name='2fa-newrecovery'),
  re_path(r'^domain/list/(?P<handle>[A-Z0-9]+)$', whois_views.domainlist,
        name='domainlist'),
  re_path(r'^domain/edit/(?P<fqdn>[a-zA-Z0-9\.-]+)/$', whois_views.domainedit,
        name='domainedit'),
  re_path(r'^domain/edit/confirm/(?P<fqdn>[a-zA-Z0-9\.-]+)/$',
        whois_views.domaineditconfirm),
  re_path(r'^domain/del/(?P<fqdn>[a-z0-9\.-]+)/$',
        whois_views.domaindelete,
        name='domaindelete'),
  re_path(r'^domain/undel/(?P<fqdn>[a-z0-9\.-]+)/$',
        whois_views.domainundelete,
        name='domainundelete'),
  re_path(r'^registrant/edit/(?P<fqdn>[a-zA-Z0-9\.-]+)/$',
        whois_views.contactchange,
        name='contactchange'),
  # The following are special for lost password handling;
  # putting these under /contact/... is not quite correct as they are
  # not private.
  path('contact/create/', whois_views.contactcreate, name='contactcreate'),
  path('contact/reset/', whois_views.makeresettoken,
        name='makeresettoken'),
  re_path(r'^contact/reset/(?P<handle>[A-Z0-9]+)$', whois_views.makeresettoken,
        name='makeresettoken'),
  re_path(r'^contact/doreset/(?P<handle>[A-Z0-9]+)/$', whois_views.resetpass2),
  re_path(r'^contact/validate/(?P<handle>[A-Z0-9]+)/(?P<valtoken>[a-zA-Z0-9]+)/$',
        whois_views.contactvalidate),
  path('contact/bydom', whois_views.contactbydomain,
        name='contactbydomain'),
  re_path(r'^contact/bydom/(?P<fqdn>[a-zA-Z0-9\.-]+)$',
        whois_views.contactbydomain)
]
urlpatterns += [
  path('log', logs_views.loglist, name='loglist')
]
urlpatterns += [
  re_path(r'^rq/(?P<rqid>[a-z0-9-]+)$', requests_views.rq, name='rq'),
  path('rq', requests_views.rq, name='rq'),
  re_path(r'^rqe/(?P<rqid>[a-z0-9-]+)$', requests_views.rqedit, name='rqedit'),
  re_path(r'^rqd/(?P<domain>[a-z0-9\.A-Z-]+)$', requests_views.rqdom,
        name='rqdom'),
  path('r/', requests_views.rqlist, name='rqlist'),
  path('r/<int:page>', requests_views.rqlist, name='rqlist'),
  path('rd', requests_views.rqlistdom),
  re_path(r'^rd/(?P<domain>[a-z0-9\.A-Z-]+)$', requests_views.rqlistdom),
  path('rl', requests_views.rqloglist, name='rqloglist'),
  re_path(r'^rl/(?P<id>[a-z0-9-]+)$', requests_views.rqlogdisplay, name='rqlogdisplay'),
  path('val', requests_views.rqval, name='rqval')
]
urlpatterns += [
  # first line for empty domain (root zone)
  re_path(r'^soa/(?P<domain>)$', webdns_views.checksoa),
  re_path(r'^soa/(?P<domain>[a-z0-9\.A-Z-]+)$', webdns_views.checksoa),
  re_path(r'^ds/(?P<fqdn>[a-z0-9\.A-Z-]+)/$', webdns_views.domainds,
        name='domainds'),
  re_path(r'^ns/(?P<fqdn>[a-z0-9\.A-Z-]+)/$', webdns_views.domainns,
        name='domainns'),
  path('domain/new/', webdns_views.domainns,
        name='domainns'),
  re_path(r'^domain/hist/(?P<fqdn>[a-z0-9\.-]+)$', webdns_views.domainhist,
        name='domainhist'),
  re_path(r'^domain/diff/(?P<fqdn>[a-z0-9\.-]+)$', webdns_views.domaindiff,
        name='domaindiff'),
  re_path(r'^domain/histclear/(?P<fqdn>[a-z0-9\.-]+)$', webdns_views.domainhistclear,
        name='domainhistclear'),
  re_path(r'^domain/histclear/confirm/(?P<fqdn>[a-z0-9\.-]+)$', webdns_views.domainhistclearconfirm,
        name='domainhistclearconfirm'),
  path('special/', webdns_views.special, name='special'),
]
urlpatterns += [
  # Uncomment this for admin:
  path('admin/', admin.site.urls)
]
