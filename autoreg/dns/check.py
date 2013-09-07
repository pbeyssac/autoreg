#
# DNS checks
#

import re
import socket

import dns
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

def sendquery(q, server):
  """Send DNS query q, in UDP then TCP, to server"""
  trytcp = False
  try:
    r = dns.query.udp(q, server, timeout=10)
  except dns.query.BadResponse:
    return None, "BadResponse"
  except dns.query.UnexpectedSource:
    return None, "UnexpectedSource"
  except dns.exception.Timeout:
    trytcp = True
  except socket.error, e:
    return None, e

  if not trytcp:
    return True, r

  try:
    r = dns.query.tcp(q, server, timeout=10)
  except dns.query.BadResponse:
    return None, "BadResponse"
  except dns.query.UnexpectedSource:
    return None, "UnexpectedSource"
  except EOFError:
    return None, "Dropped connection"
  except dns.exception.Timeout:
    return None, "Timeout"
  except socket.error, e:
    return None, e

  return True, r

def undot_list(fqdnlist):
  return [fqdn.rstrip('.') for fqdn in fqdnlist]

class SOAChecker(object):
  def __init__(self, domain, manualip={}, nat={}):
    self.res = dns.resolver.Resolver()
    self.domain = domain
    qsoa = dns.message.make_query(domain+'.', 'SOA')
    qsoa.flags = 0
    self.qsoa = qsoa
    qns = dns.message.make_query(domain+'.', 'NS')
    qns.flags = 0
    self.qns = qns
    self.mastername = None
    self.manualip = manualip
    self.nat = nat

  def getsoa(self, server):
    """Send SOA query to server and wait for reply.
       Return master name and serial.
    """
    ok, r = sendquery(self.qsoa, server)
    if not ok:
      return None, r
    if (r.flags & dns.flags.AA) == 0:
      return None, "Answer not authoritative"
    if len(r.answer) == 0:
      return None, "Empty answer"
    if len(r.answer) != 1:
      return None, "Unexpected answer length"
    if len(r.answer[0].items) != 1:
      return None, "Unexpected number of items"
    if r.answer[0].items[0].rdtype != dns.rdatatype.SOA:
      return None, "Answer type mismatch"
    mastername = str(r.answer[0].items[0].mname).upper()
    serial = r.answer[0].items[0].serial
    return True, (mastername, serial)

  def getnslist(self, server):
    """Send NS query to server and wait for reply.
       Return NS list.
    """
    ok, r = sendquery(self.qns, server)
    if not ok:
      return None, r
    if (r.flags & dns.flags.AA) == 0:
      return None, "Answer not authoritative"
    if len(r.answer) == 0:
      return None, "Empty answer"
    if len(r.answer) != 1:
      return None, "Unexpected answer length"
    nslist = [a.to_text().upper() for a in r.answer[0].items]
    nslist = undot_list(nslist)
    nslist.sort()
    return True, nslist

  def setnslist(self, server):
    """Fetch NS list from server"""
    ok, r = self.getnslist(server)
    if not ok:
      return None, r
    self.nslist = undot_list(nslist)
    nslist.sort()
    return True, self.nslist

  def setnslist_public(self):
    """Fetch NS list from resolver"""
    tcp = False
    nslist = []
    try:
      ans = self.res.query(self.domain+'.', 'NS', tcp=tcp)
    except dns.resolver.NXDOMAIN:
      return None, "Error: Domain not found"
    except dns.exception.Timeout:
      return None, "Error: Timeout"
    except dns.resolver.NoAnswer:
      return None, "Error: No answer"
    except dns.resolver.NoNameservers:
      return None, "Error: No name servers"
    for i in ans.rrset.items:
      fqdn = i.to_text().upper()
      nslist.append(fqdn)
    nslist.sort()
    self.nslist = undot_list(nslist)
    return True, self.nslist

  def setnslist_file(self, file):
    """Fetch NS list from file"""
    fqdnip = re.compile('^([a-zA-Z0-9\.-]+)(?:\s+(\S+))?\s*$')
    errlist = []
    warnlist = []
    nslist = []
    for l in file:
      l = l[:-1]
      m = fqdnip.match(l)
      if not m:
        errlist.append("Error: Invalid line")
        continue
      fqdn, ip = m.groups()
      if ip is not None:
        ip = ip.upper()

        try:
          if ':' in ip:
            socket.inet_pton(socket.AF_INET6, ip)
          else:
            socket.inet_pton(socket.AF_INET, ip)
        except socket.error:
          errlist.append("Error: Invalid IP address %s" % ip)
          ip = None

      if ip is not None:
        if fqdn.endswith('.'+self.domain) or fqdn == self.domain:
          self.manualip[fqdn] = ip
        else:
          warnlist.append("ignoring IP %s"
                          " for %s (not in %s)" % (ip, fqdn, self.domain))

      fqdn = fqdn.upper()
      nslist.append(fqdn)
    if nslist:
      self.mastername = nslist[0]
    self.nslist = undot_list(nslist)
    self.nslist.sort()
    return errlist, warnlist

  def gen_ips(self):
    """Resolve ips from self.nslist.
    Take manualip and nat tables into account.
    """
    tcp = False
    for fqdn in self.nslist:
      if fqdn in self.manualip:
        yield True, (False, fqdn, [self.manualip[fqdn]])
        continue
      n = 0
      for t in ['A', 'AAAA']:
        try:
          aip = self.res.query(fqdn, t, tcp=tcp)
        except dns.resolver.NoAnswer:
          continue
        except dns.resolver.NXDOMAIN:
          continue
        except dns.exception.Timeout:
          continue
        except dns.resolver.NoNameservers:
          continue
        iplist = [ip.to_text() for ip in aip.rrset.items]
        natlist = []
        for ip in iplist:
          if ip in self.nat:
            natlist.append(self.nat[ip])
          else:
            natlist.append(ip)
        yield True, (True, fqdn, natlist)
        n += 1
      if n == 0:
        yield None, (None, fqdn, [])

  def gen_soa(self):
    """Get SOA in turn from each IP in self.ips."""
    for resolved, fqdn, iplist in self.ips:
      for i in iplist:
        ok, r = self.getsoa(i)
        yield ok, fqdn, i, r

  def gen_ns(self):
    """Get NS records in turn from each IP in self.ips."""
    for resolved, fqdn, iplist in self.ips:
      for i in iplist:
        ok, r = self.getnslist(i)
        yield ok, fqdn, i, r

  def resolve_ips(self):
    """Resolve IPs, storing the result in self.ips."""
    ips = []
    for ok, resolved_fqdn_ip in self.gen_ips():
      resolved, fqdn, ip = resolved_fqdn_ip
      ips.append(resolved_fqdn_ip)
      if not ok:
        yield None, "Getting IP for %s: FAILED" % fqdn,
      elif resolved:
        yield True, "Getting IP for %s: %s" % (fqdn, ' '.join(ip))
      else:
        yield True, "Accepted IP for %s: %s" % (fqdn, ' '.join(ip))
    self.ips = ips

  def print_checks(self):
    """Run gen_soa() and gen_ns(), displaying messages as we go."""
    for ok, fqdn, i, r in self.gen_soa():
      if not ok:
        yield None, "SOA from %s at %s: Error: %s" % (fqdn, i, r)
      else:
        yield True, "SOA from %s at %s: serial %s" % (fqdn, i, r[1])
    for ok, fqdn, i, r in self.gen_ns():
      if not ok:
        yield None, "NS from %s at %s: Error: %s" % (fqdn, i, r)
      elif r != self.nslist:
        yield None, "NS from %s at %s: Error: Bad NS list: %s" % (fqdn, i,
                    ' '.join(r))
      else:
        yield True, "NS from %s at %s: ok" % (fqdn, i)

  def main(self, file=None):
    """Main processing to check a list of servers for a given zone.
    Checks:
    1)    IP addresses of servers not in domain
    2)    primary and secondaries are authoritative for the domain
    3)    NS records for domain on all listed server match the provided list.
    """
    errs = 0
    warns = 0

    yield True, "---- Servers and domain names check"
    yield True, ""

    if not self.domain:
      yield None, "Error: no domain specified"
      return

    if self.domain.startswith('.'):
      self.domain = self.domain[1:]
    if self.domain.endswith('.'):
      self.domain = self.domain[:-1]

    if not file:
      #
      # Fetch NS list from public DNS
      #
      ok, r = self.setnslist_public()
      if not ok:
        yield None, "Querying NS list for %s... %s" % (self.domain, r)
        yield None, r
        return
      yield True, "Querying NS list for %s... %d records" \
            % (self.domain, len(self.nslist))
      yield True, ""

    else:
      #
      # Fetch NS list from file
      #
      errlist, warnlist = self.setnslist_file(file)

      for e in errlist:
        yield None, "Error: %s" % e
      errs += len(errlist)
      for e in warnlist:
        yield True, "Warning: %s" % e
      warns += len(warnlist)

    if not self.nslist:
      yield True, "Error: empty name server list"
      errs += 1

    if errs:
      yield None, "%s errors(s)" % errs
      return

    #
    # Build IP address list
    #

    for ok, msg in self.resolve_ips():
      yield True, msg
      if not ok:
        errs += 1

    if errs:
      yield None, "%d errors(s)" % errs
      return

    yield True, ""
    yield True, "---- Checking SOA & NS records for %s" % self.domain
    yield True, ""

    for ok, msg in self.print_checks():
      yield True, msg
      if not ok:
        errs += 1

    if errs or warns:
      yield True, ""
    if errs:
      yield None, "%d errors(s)" % errs
    if warns:
      yield True, "%d warning(s)" % warns,
    yield True, ""
    return
