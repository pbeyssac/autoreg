#!/usr/local/bin/python
# $Id$

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


import base64
import re
import socket

class ParseError(Exception):
    pass

class DnsParser:
    """Handle minimal zonefile-style line parsing."""
    #
    # Zone file regexps
    #
    # a comment or empty line
    _comment_re = re.compile('^\s*(;.*|)$')
    # simplified expression for a regular line
    # (does not handle trailing comments, difficult because of string quoting)
    _label_re = re.compile(
	'^(\S+)?\s+(?:(\d+)\s+)?(?:[Ii][Nn]\s+)?([A-Za-z]\S*)\s+(\S|\S.*\S)\s*$')
    # right-hand side for a MX record
    _mx_re = re.compile('^(\d+)\s+(\S+)$')
    # right-hand side for a DS/DLV record
    _dsdlv_re = re.compile('^(\d+)\s+(\d+)\s+(\d+)\s+([0-9a-fA-F \t]+)$')
    # right-hand side for a DNSKEY record, with Base64 string
    _dnskey_re = re.compile('^(\d+)\s+(\d+)\s+(\d+)\s+(\S+.*\S+)$')
    # right-hand side for a SRV record
    _mx_srv = re.compile('^(\d+)\s+(\d+)\s+(\d+)\s+(\S+)$')
    # host FQDN (no underscore)
    _hfqdn_re = re.compile('^(?:[A-Z0-9-]+\.)+[A-Z][A-Z0-9]+\.$',
                           re.IGNORECASE)
    # lines such as $TTL ...
    _dollar_re = re.compile('^\$(\S+)\s+(\d+)\s*$')
    # SOA lines
    _soa_begin_re = re.compile('^.*\(\s*(?:;.*)?$')
    _soa_end_re = re.compile('^\s+\d+\s*\)\s*(?:;.*)?$')

    def __init__(self):
        self.insoa = False
    def normalizeline(self, label, ttl, typ, value, rrfilter=None):
	if label is None:
	    label = ''
	else:
	    label = label.upper()
	typ = typ.upper()
	# Do some quick & dirty checking and canonicalization
        if rrfilter is not None and typ not in rrfilter:
            raise ParseError('Not an allowed resource record type', typ)
        if typ == 'AAAA':
            # RFC 5952 mandates lower case
	    value = value.lower()
            try:
                dummy = socket.inet_pton(socket.AF_INET6, value)
            except socket.error:
                raise ParseError('Bad IPv6 address', value)
	elif typ == 'A':
            try:
                dummy = socket.inet_pton(socket.AF_INET, value)
            except socket.error:
                raise ParseError('Bad IPv4 address', value)
        elif typ in ['CNAME', 'DNAME', 'NS', 'PTR']:
	    m = self._hfqdn_re.search(value)
	    if not m: raise ParseError('Bad value for %s record' % typ, value)
	    value = value.upper()
	elif typ == 'SRV':
	    m = self._mx_srv.search(value)
	    if not m: raise ParseError('Bad value for SRV record', value)
            pri, weight, port, fqdn = m.groups()
	    m = self._hfqdn_re.search(fqdn)
	    if not m: raise ParseError('Bad host for SRV record', fqdn)
            pri, weight, port = int(pri), int(weight), int(port)
	    if pri > 65535:
              raise ParseError('Bad priority for SRV record', pri)
	    if weight > 65535:
              raise ParseError('Bad weight for SRV record', weight)
	    if port > 65535:
              raise ParseError('Bad port for SRV record', port)
	    value = "%d %d %d %s" % (pri, weight, port, fqdn.upper())
	elif typ == 'MX':
	    m = self._mx_re.search(value)
	    if not m: raise ParseError('Bad value for MX record', value)
	    pri, fqdn = m.groups()
	    m = self._hfqdn_re.search(fqdn)
	    if not m: raise ParseError('Bad host name for MX record', fqdn)
	    pri = int(pri)
	    if pri > 65535: raise ParseError('Bad priority for MX record', pri)
	    value = "%d %s" % (pri, fqdn.upper())
	elif typ in ['DS', 'DLV']:
	    m = self._dsdlv_re.search(value)
	    if not m: raise ParseError('Bad value for DS/DLV record', value)
            keytag, algo, digesttype, hexhash = m.groups()
            keytag, algo, digesttype = int(keytag), int(algo), int(digesttype)
            if keytag > 65535:
                raise ParseError('Bad keytag for DS/DLV record', keytag)
            if algo > 255:
                raise ParseError('Bad algorithm for DS/DLV record', algo)
            if digesttype > 255:
                raise ParseError('Bad digest type for DS/DLV record',
                                 digesttype)
            hexhash = hexhash.replace(' ', '').replace('\t', '').lower()
            if digesttype == 1 and len(hexhash) != 40:
                raise ParseError('Wrong hash length in DS/DLV record', hexhash)
            if digesttype == 2 and len(hexhash) != 64:
                raise ParseError('Wrong hash length in DS/DLV record', hexhash)
            if digesttype == 4 and len(hexhash) != 96:
                raise ParseError('Wrong hash length in DS/DLV record', hexhash)
            if digesttype not in [1, 2, 4] and len(hexhash) % 1:
                raise ParseError('Wrong hash length in DS/DLV record', hexhash)
            value = "%d %d %d %s" % (keytag, algo, digesttype, hexhash)
	elif typ == 'DNSKEY':
	    m = self._dnskey_re.search(value)
	    if not m: raise ParseError('Bad value for DNSKEY record', value)
            flags, protocol, algo, key = m.groups()
            flags, protocol, algo = int(flags), int(protocol), int(algo)
            if flags > 65535:
                raise ParseError('Bad flags for DNSKEY record: %d' % flags)
            if protocol > 255:
                raise ParseError('Bad protocol for DNSKEY record: %d'
                                 % protocol)
            if algo > 255:
                raise ParseError('Bad algorithm for DNSKEY record: %d' % algo)
            try:
                base64.b64decode(key)
            except TypeError as e:
                raise ParseError('Bad key in DNSKEY record:' + e, key)
            key = key.replace(' ', '').replace('\t', '')
            value = "%d %d %d %s" % (flags, protocol, algo, key)
        elif typ in ['TXT', 'RRSIG', 'HINFO', 'SPF', 'SSHFP', 'TLSA']:
	    pass
	elif typ == 'SOA':
	    pass
	else:
	    raise ParseError('Illegal record type', typ)
	return label, ttl, typ, value
    def splitline(self, l):
	m = self._label_re.search(l)
	if not m:
            raise ParseError('Unable to parse line', l)
	return m.groups()
    def parseline(self, l):
	if self._comment_re.search(l): return None
	if self._dollar_re.search(l): return None
        if self.insoa:
            if self._soa_end_re.search(l):
                self.insoa = False
            return None
	label, ttl, typ, value = self.splitline(l)
        if typ.upper() == 'SOA':
            if self._soa_begin_re.search(value.strip()):
                self.insoa = True
            return None
	return self.normalizeline(label, ttl, typ, value)
    def parse1line(self, l, rrfilter=None):
	label, ttl, typ, value = self.splitline(l)
	return self.normalizeline(label, ttl, typ, value, rrfilter)
