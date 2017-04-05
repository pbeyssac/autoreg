from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import base64
import hashlib
import re
import struct

from . import check
from . import parser

def compute_keytag_wirekey(flags, protocol, algorithm, key):
  """Compute key tag and wire key."""
  wirekey = struct.pack(">HBB", flags, protocol, algorithm) + key

  wk = wirekey
  if len(wk) % 2:
    wk += chr(0)
  tag = 0
  while wk:
    h, = struct.unpack('>H', wk[:2])
    tag += h
    wk = wk[2:]
  tag = (tag + (tag >> 16)) & 0xffff
  return tag, wirekey

def compute_keytag(flags, protocol, algorithm, key):
  """Compute key tag."""
  return compute_keytag_wirekey(flags, protocol, algorithm, key)[0]

def compute_ds(domain, flags, protocol, algorithm, key, digesttypelist=[1, 2, 4]):
  """Compute DS/DLV records from DNSKEY data"""
  domain = str(domain.lower())
  if domain[-1] != '.':
    domain += '.'
  wire = ''
  for d in domain.split('.'):
    wire += struct.pack('B', len(d)) + d
  tag, wirekey = compute_keytag_wirekey(flags, protocol, algorithm, key)
  wire += wirekey

  dslist = []
  for digesttype in digesttypelist:
    if digesttype == 1:
      dslist.append((tag, algorithm, 1, hashlib.sha1(wire).hexdigest()))
    elif digesttype == 2:
      dslist.append((tag, algorithm, 2, hashlib.sha256(wire).hexdigest()))
    else:
      dslist.append((tag, algorithm, 4, hashlib.sha384(wire).hexdigest()))
  return dslist

def make_ds(rr, domain):
  """Parse and analyze a DS/DLV/DNSKEY record;
  Generate a matching DS record.
  """
  if domain and domain[-1] != '.': domain += '.'
  domain = domain.lower()
  p = parser.DnsParser()
  try:
    label, ttl, rrtype, value = p.parse1line(rr, ['DS', 'DLV', 'DNSKEY'])
  except parser.ParseError as e:
    return False, ' '.join(e)

  if rrtype == 'DNSKEY':
    if label and label.lower() != domain:
      return False, "Domain doesn't match record"
    flags, protocol, algorithm, b64key = value.split(' ', 3)
    flags, protocol, algorithm = int(flags), int(protocol), int(algorithm)
    if flags & 257 != 257:
      return False, \
        "Flags field should be 257 (key-signing key, security entry point)"
    if protocol != 3:
      return False, "Protocol field should be 3"
    key = base64.b64decode(b64key)
    return True, compute_ds(domain, flags, protocol, algorithm, key, [2, 4])
  elif rrtype in ['DS', 'DLV']:
    keytag, algorithm, digesttype, hexhash = value.split(' ', 3)
    if label and label.lower() != domain:
      return False, "Domain doesn't match record"
    hexhash = hexhash.replace(' ', '').replace('\t', '').lower()
    keytag, algorithm, digesttype = int(keytag), int(algorithm), int(digesttype)
    dslist = [(keytag, algorithm, digesttype, hexhash)]
    return True, dslist

  return False, "Can't analyze record"

def make_ds_dnskeys_ns(domain, nslist):
  """Fetch DNSKEY records from servers then generate associated DS records."""
  r = check.DNSKEYChecker(domain, nslist)
  answers = r.getalldnskey()
  return [ (compute_ds(domain, a.flags, a.protocol, a.algorithm, a.key),
            (a.flags, a.protocol, a.algorithm, a.key))
           for a in answers if a.flags & 257 == 257 ]
