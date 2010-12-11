#!/usr/local/bin/python
# $Id$

"""Usage:
Client mode:
whois.py request

Server mode:
whois.py [-D database-string] [-l request log] [-e stderr log] [-u user] [-d]
"""

import errno
import getopt
import os
import pwd
import signal
import socket
import sys
import time

import psycopg2

import autoreg.conf
import autoreg.whois.db as whoisdb

USERID = 'whois'
RQLOG = '/var/log/whoisd.log'
ERRLOG = '/var/log/whoisd.err'
PORT = 43

class SocketError(Exception):
    pass

class socketwrapper:
  def __init__(self, sock):
    self.s = sock
  def write(self, buf):
    while buf:
      r = self.s.send(buf)
      if r < 0:
	raise SocketError('send')
      buf = buf[r:]

class server:
  maxforks = 5
  maxtime = 60
  delay = 1
  def __init__(self, dbstring, rqlog, errlog, port=PORT, runas=USERID):
    self.logf = open(rqlog, 'a')
    sys.stderr = open(errlog, 'a')
    self.dbstring = dbstring

    s = socket.socket(socket.AF_INET6)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.bind(('::', port))
    s.listen(255)

    p = pwd.getpwnam(runas)
    gid = p.pw_gid
    uid = p.pw_uid
    os.setgid(gid)
    os.setuid(uid)
    pidinfo = {}

    nfree = self.maxforks
    while True:
      while nfree < self.maxforks:
        if nfree > 0:
          # don't block
          r = os.waitpid(-1, os.WNOHANG)
        else:
          # block: anyway we can't process any request until a process exits.
          r = os.waitpid(-1, 0)
        pid, status = r
        if pid == 0:
          break
        if pid in pidinfo:
          del pidinfo[pid]
        else:
          self.log("WARNING: reaped an unknown process")
        nfree += 1

      now = time.time()
      for pid in pidinfo:
        # kill hung processes
        t, a = pidinfo[pid]
        ip, cport, flowinfo, scopeid = a
        if t + self.maxtime < now:
          try:
            self.log("WARNING: killing hung process %d (%s)" % (pid, ip))
            os.kill(pid, signal.SIGTERM)
          except OSError, e:
            if e.errno != errno.ESRCH:
              raise e

      if nfree > 0:
        try:
          c, a = s.accept()
        except socket.error:
          c = None
        if c is None:
          continue
        try:
          f = os.fork()
        except OSError, e:
          self.log("ERROR: cannot fork, %s" % e)
          f = -1
        if f == 0:
          # in child process
          s.close()
          bkpipe = False
          try:
            self.handleclient(c, a)
          except socket.error, se:
            if len(se) != 2 or se.args[0] != errno.EPIPE:
              raise
            bkpipe = True
          if bkpipe:
            self.log("WARNING: EPIPE on process %d (%s)" % (pid, ip))
  	  # crude rate control
          time.sleep(self.delay)
          sys.exit(0)
        elif f > 0:
          # in parent process
          c.close() # prevent descriptor leak
          pidinfo[f] = (time.time(), a)
          nfree -= 1
          if nfree == 0:
            self.log("WARNING: maxforks (%d) reached" % self.maxforks)

  def handleclient(self, c, a):
    w = socketwrapper(c)
    sys.stdout = w
    ip, cport, flowinfo, scopeid = a
    c.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    q = ''
    r = c.recv(256)
    while r:
      q += r
      i = q.find('\r\n')
      if i >= 0:
	q = q[:i]
        if ip.startswith('::ffff:'):
              ip = ip[7:]
	self.log("%s %s" % (ip, q))
        # XXX: the 192.168.0.* check is a terrible hack until the
        # Perl query interface is rewritten.
	query(q, self.dbstring, w,
              remote = (ip != '127.0.0.1' and ip != '::1'
                        and not ip.startswith('192.168.0.')))
	c.shutdown(socket.SHUT_WR)
	break
      r = c.recv(256)
    c.close()
  def log(self, msg):
    (year, month, day, hh, mm, ss, d1, d2, d3) = time.localtime(time.time())
    print >>self.logf, "%04d%02d%02d %02d%02d%02d %s" % \
		       (year, month, day, hh, mm, ss, msg)
    self.logf.flush()

def query(a, dbstring, out, encoding='ISO-8859-1', remote=True):
  if not isinstance(a, unicode):
    a = a.decode(encoding)
  dbh = psycopg2.connect(dbstring)
  l = whoisdb.Lookup(dbh.cursor())

  if not a:
    return

  real_email = False
  try:
    opts, args = getopt.getopt(a.split(), "UR")
  except getopt.GetoptError:
    return

  for optval, aval in opts:                                                    
    if optval == '-R' and not remote:
      real_email = True
    elif optval == '-U':                                                       
      encoding = 'utf-8'

  if len(args) > 1:
    return

  a = args[0]

  if a[0] == '/' and not remote:
    ld = l.domains_by_handle(a[1:])
    for d in ld:
      d.fetch()
      print d.__str__().encode(encoding, 'xmlcharrefreplace')
    return

  d = l.domain_by_name(a)
  if d is not None:
    dc = d.get_contacts()
    print d.__str__().encode(encoding, 'xmlcharrefreplace')
    pdone = []
    for k in ['technical', 'administrative', 'zone']:
      if k not in dc:
        continue
      for p in dc[k]:
        if real_email:
          p.fetch()
        else:
          p.fetch_obfuscated()
        if p.key not in pdone:
          print p.__str__().encode(encoding, 'xmlcharrefreplace')
          pdone.append(p.key)
    return

  lp = l.persons_by_handle(a)
  if not lp:
    lp = l.persons_by_name(a)
  if not lp and not remote and a.find('@') >= 0:
    lp = l.persons_by_email(a)
  if not lp:
    print >>out, "Key not found"
    return
  for p in lp:
    if real_email:
      p.fetch()
    else:
      p.fetch_obfuscated()
    print p.__str__().encode(encoding, 'xmlcharrefreplace')

def usage():
  print >>sys.stderr, __doc__

def command(argv):
  whoiserrlog, whoisrqlog, runas, port = ERRLOG, RQLOG, USERID, PORT
  dbstring = autoreg.conf.dbstring
  detach = True

  try:
    opts, args = getopt.getopt(argv[1:], "dD:e:l:p:u:")
  except getopt.GetoptError:
    usage()
    return 1

  for o, a in opts:
    if o == '-d':
      detach = False
    elif o == '-D':
      dbstring = a
    elif o == '-e':
      whoiserrlog = a
    elif o == '-l':
      whoisrqlog = a
    elif o == '-p':
      port = int(a)
    elif o == '-u':
      runas = a

  if len(args) > 1:
    usage()
    return 1

  if len(args) == 0:
    if not detach:
      server(dbstring, whoisrqlog, whoiserrlog, port, runas)
    r = os.fork()
    if r == 0:
      server(dbstring, whoisrqlog, whoiserrlog, port, runas)
    elif r == -1:
      print >>sys.stderr, "Daemon start failed"
      return 1
    else:
      print >>sys.stderr, "Daemon started"
  else:
    query(args[0], dbstring, sys.stdout, remote=False)
  return 0

if __name__ == "__main__":
  sys.exit(command(sys.argv))
