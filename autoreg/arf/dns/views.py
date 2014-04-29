
import autoreg.dns.check

from django.core.exceptions import SuspiciousOperation
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, StreamingHttpResponse


def _gen_checksoa(domain):
  soac = autoreg.dns.check.SOAChecker(domain, {}, {})

  for ok, out in soac.main():
    yield out + '\n'

def checksoa(request, domain):
  if request.method != 'GET':
    raise SuspiciousOperation
  if domain != domain.lower():
    return HttpResponseRedirect(reverse(checksoa, args=[domain.lower()]))
  return StreamingHttpResponse(_gen_checksoa(domain),
                               content_type="text/plain")
