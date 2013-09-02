#!/usr/local/bin/python

import re
import socket
import sys

import dns
import dns.ipv6
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

def sendquery(q, server):
  try:
    r = dns.query.udp(q, server, timeout=10)
  except dns.query.BadResponse:
    print "BadResponse"
    return False
  except dns.query.UnexpectedSource:
    print "UnexpectedSource"
    return False
  except dns.exception.Timeout:
    print "Timeout"
    return False
  except socket.error, e:
    print "socket error", e.val
    return False
  return r

def checksoa(qsoa, server):
  """Send SOA query to server and wait for reply.
     Return master name and serial.
  """
  r = sendquery(qsoa, server)
  if not r:
    return False
  if (r.flags & dns.flags.AA) == 0:
    print "Answer not authoritative"
    return False
  if len(r.answer) == 0:
    print "Empty answer"
    return False
  if len(r.answer) != 1:
    print "Unexpected answer length"
    return False
  if len(r.answer[0].items) != 1:
    print "Unexpected number of items"
    return False
  if r.answer[0].items[0].rdtype != dns.rdatatype.SOA:
    print "Answer type mismatch"
    return False
  mname = r.answer[0].items[0].mname.__str__().upper()
  serial = r.answer[0].items[0].serial
  return mname, serial

def getnslist(domain, server):
  qns = dns.message.make_query(domain, 'NS')
  qns.flags = 0
  r = sendquery(qns, server)
  if not r:
    return False
  if (r.flags & dns.flags.AA) == 0:
    print "Answer not authoritative"
    return False
  if len(r.answer) == 0:
    print "Empty answer"
    return False
  if len(r.answer) != 1:
    print "Unexpected answer length"
    return False
  nslist = []
  for a in r.answer[0].items:
    v = a.to_text().upper()
    if v.endswith('.'):
      v = v[:-1]
    nslist.append(v)
  nslist.sort()
  return nslist

def main():
  tcp=False
  fqdnlist = []
  r = dns.resolver.Resolver()

  print "---- Servers and domain names check"

  if len(sys.argv) == 2:
    domain = sys.argv[1].upper()
    #
    # Fetch NS list from public DNS
    #
    print "Querying NS list for", domain
    try:
      ans = r.query(domain, 'NS', tcp=tcp)
    except dns.resolver.NXDOMAIN:
      print "Domain not found"
      sys.exit(1)
    except dns.exception.Timeout:
      print "Timeout"
      sys.exit(1)
    except dns.resolver.NoAnswer:
      print "NoAnswer"
      sys.exit(1)
    except dns.resolver.NoNameservers:
      print "NoNameservers"
      sys.exit(1)
    print "Got", len(ans.rrset.items), "answers"
    for i in ans.rrset.items:
      fqdn = i.to_text().upper()
      if fqdn.endswith('.'):
        fqdn = fqdn[:-1]
      fqdnlist.append(fqdn)
  else:
    fqdnip = re.compile('^([a-zA-Z0-9\.-]+)(?:\s+(\S+))?\s*$')
    domain = sys.stdin.readline()
    domain = domain[:-1].upper()
    for l in sys.stdin:
      l = l[:-1]
      m = fqdnip.match(l)
      if not m:
        print "Invalid line"
        continue
      fqdn, ip = m.groups()
      if ip != None:
        ip = ip.upper()
      fqdn = fqdn.upper()
      print "fqdn", fqdn, "ip", ip
      fqdnlist.append(fqdn)
  
  fqdnlist.sort()
  print fqdnlist

  if not domain.endswith('.'):
    domain += '.'
  if domain.startswith('.'):
    domain = domain[1:]
  
  #
  # Build IP address list
  #
  ips = []
  for fqdn in fqdnlist:
    if fqdn.endswith('.'):
      fqdn = fqdn[:-1]
    print "Getting IP for %s..." % fqdn,
    n = 0
    for t in ['A', 'AAAA']:
      try:
        aip = r.query(fqdn, t, tcp=tcp)
      except dns.resolver.NXDOMAIN:
        continue
      except dns.exception.Timeout:
        continue
      except dns.resolver.NoAnswer:
        continue
      except dns.resolver.NoNameservers:
        continue
      for iprr in aip.rrset.items:
        print iprr.to_text(),
        ips.append((fqdn, t, iprr.to_text()))
        n += 1
    if n == 0:
      print "failed",
    print
  
  qsoa = dns.message.make_query(domain, 'SOA')
  qsoa.flags = 0
  mname = None
  serial = None
  for fqdnip in ips:
    fqdn, t, i = fqdnip
    #if t == 'AAAA':
    #  continue
    print "Querying", fqdn, "at", i
    soa = checksoa(qsoa, i)
    print "SOA:", soa
    nslist = getnslist(domain, i)
    if nslist == False:
      fail = True
    elif nslist != fqdnlist:
      print "Bad NS list:", nslist
      fail = True
  
  sys.exit(0)
  
  qns = dns.message.make_query(domain, 'NS')
  qns.flags = 0
  print "Fetching NS list from", mname
  try:
    rns = dns.query.udp(qns, mname, timeout=10)
  except dns.query.BadResponse:
    print "BadResponse"
  except dns.query.UnexpectedSource:
    print "UnexpectedSource"
  except dns.exception.Timeout:
    print "Timeout"
  except socket.error, e:
    print "socket error", e.val
  else:
    if (rns.flags & dns.flags.AA) == 0:
      print "Answer not authoritative"
    elif len(rns.answer) == 0:
      print "Empty answer"
    else:
      for a in rns.answer:
        print a.to_text()

if __name__ == "__main__":
  main()
