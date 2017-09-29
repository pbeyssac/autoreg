#

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


from autoreg.conf import FROMADDR, HANDLESUFFIX, PREEMPTHANDLE, SITENAME
from autoreg.whois.db import suffixadd
from .models import check_is_admin, Whoisdomains


# Context processor

def site(request):
  is_admin = check_is_admin(request.user.username)
  v  = { 'preempthandle': suffixadd(PREEMPTHANDLE),
         'from': FROMADDR,
         'sitename': SITENAME,
         'suffix': HANDLESUFFIX,
         'is_admin': is_admin }
  if is_admin:
    v['numdom'] = Whoisdomains.objects.all().count()
  return v
