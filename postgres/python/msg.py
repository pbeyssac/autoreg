# $Id$
import os
import sre

import conf

class MsgError(Exception):
    pass

class Msg:
    path=conf.msgdir

    com_re=sre.compile("^\s*}?(#|$)")
    lang_re=sre.compile("LANG.*eq\s+\'(.+)\'")
    lang_default_re=sre.compile("^\s*\}\s*else\s*\{\s*$")
    msg_re=sre.compile("^\s*\$(\S+)=\"(.*)\";\s*$")

    def __init__(self, file, curlang=''):
	self.m = {}
	self.curlang = curlang
	lang = ''
	for l in open(os.path.join(self.path, file)):
	    if self.com_re.search(l): continue
	    m = self.msg_re.search(l)
	    if m:
		msgid, st = m.groups()
		st = self.unquote(st)
		if msgid in self.m[lang]:
		    raise MsgError('Duplicate key', msgid)
		self.m[lang][msgid] = st
		continue
	    m = self.lang_re.search(l)
	    if m:
		lang, = m.groups()
		if not lang in self.m:
		    self.m[lang] = {}
		continue
	    m = self.lang_default_re.search(l)
	    if m:
		lang = ''
		if not lang in self.m:
		    self.m[lang] = {}
		continue
	    raise MsgError('Bad line', l)
    def unquote(self, str):
	"""Unquote C-source style string. """
	m = str.find('\\')
	while m >= 0:
	    b = str[:m]
	    c = str[m+1]
	    e = str[m+2:]
	    if c == 'n': c = '\n'
	    elif c == 'r': c = '\r'
	    elif c == 't': c = '\t'
	    s = b + c + e
	    m = s.find('\\', m)
	return s
    def f(self, id, args):
	if not self.curlang in self.m:
	  return self.m[''][id] % args
	return self.m[self.curlang][id] % args
