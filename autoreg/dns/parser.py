#!/usr/local/bin/python
# $Id$

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
	'^(\S+)?\s+(?:(\d+)\s+)?(?:[Ii][Nn]\s+)?(\S+)\s+(\S|\S.*\S)\s*$')
    # right-hand side for a MX record
    _mx_re = re.compile('^(\d+)\s+(\S+)$')
    # right-hand side for a DS/DLV record
    _dsdlv_re = re.compile('^(\d+)\s+(\d+)\s+(\d+)\s+([0-9a-fA-F \t]+)$')
    # lines such as $TTL ...
    _dollar_re = re.compile('^\$(\S+)\s+(\d+)\s*$')
    # SOA lines
    _soa_begin_re = re.compile('^.*\(\s*(?:;.*)?$')
    _soa_end_re = re.compile('^\s+\d+\s*\)\s*(?:;.*)?$')

    def __init__(self):
        self.insoa = False
    def normalizeline(self, label, ttl, typ, value):
	if label is None:
	    label = ''
	else:
	    label = label.upper()
	typ = typ.upper()
	# Do some quick & dirty checking and canonicalization
        if typ == 'AAAA':
	    value = value.upper()
            try:
                dummy = socket.inet_pton(socket.AF_INET6, value)
            except socket.error:
                raise ParseError('Bad IPv6 address', value)
	elif typ == 'A':
            try:
                dummy = socket.inet_pton(socket.AF_INET, value)
            except socket.error:
                raise ParseError('Bad IPv4 address', value)
        elif typ in ['CNAME', 'DNAME', 'NS', 'SRV']:
	    value = value.upper()
	elif typ == 'MX':
	    m = self._mx_re.search(value)
	    if not m: raise ParseError('Bad value for MX record', value)
	    pri, fqdn = m.groups()
	    pri = int(pri)
	    if pri > 255: raise ParseError('Bad priority for MX record', pri)
	    value = "%d %s" % (pri, fqdn.upper())
	elif typ in ['DS', 'DLV']:
	    m = self._dsdlv_re.search(value)
	    if not m: raise ParseError('Bad value for DS/DLV record', value)
            keytag, algo, dtype, hexhash = m.groups()
            keytag, algo, dtype = int(keytag), int(algo), int(dtype)
            if keytag > 65535:
                raise ParseError('Bad keytag for DS/DLV record', keytag)
            if algo > 255:
                raise ParseError('Bad algorithm for DS/DLV record', algo)
            if dtype > 255:
                raise ParseError('Bad digest type for DS/DLV record', dtype)
            hexhash = hexhash.replace(' ', '').replace('\t', '').lower()
            value = "%d %d %d %s" % (keytag, algo, dtype, hexhash)
        elif typ in ['TXT', 'PTR', 'DNSKEY', 'RRSIG', 'DLV',
                     'HINFO', 'SSHFP', 'TLSA']:
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
    def parse1line(self, l):
	label, ttl, typ, value = self.splitline(l)
	return self.normalizeline(label, ttl, typ, value)
