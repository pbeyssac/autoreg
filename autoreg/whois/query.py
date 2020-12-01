#!/usr/local/bin/python
# $Id$

"""Usage:
Client mode:
whoisdb request

Server mode:
whoisdb [-D database-string] [-l request log] [-e stderr log] [-u user] [-d]
"""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


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
  def flush(self):
    return


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
          except OSError as e:
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
        except OSError as e:
          self.log("ERROR: cannot fork, %s" % e)
          f = -1
        if f == 0:
          # in child process
          s.close()
          bkpipe = False
          try:
            self.handleclient(c, a)
          except socket.error as se:
            if se.errno != errno.EPIPE:
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
    encoding = 'iso8859-15'
    w = socketwrapper(c)
    sys.stdout = w
    ip, cport, flowinfo, scopeid = a
    c.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    q = ''
    r = c.recv(256)
    r = str(r, encoding)
    dbh = psycopg2.connect(self.dbstring)
    dbc = dbh.cursor()
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
        query(q, dbc, w, encoding=encoding,
              remote = (ip != '127.0.0.1' and ip != '::1'
                        and not ip.startswith('192.168.0.')))
        c.shutdown(socket.SHUT_WR)
        break
      r = c.recv(256)
      r = str(r, encoding)
    c.close()
  def log(self, msg):
    (year, month, day, hh, mm, ss, d1, d2, d3) = time.localtime(time.time())
    print("%04d%02d%02d %02d%02d%02d %s"
          % (year, month, day, hh, mm, ss, msg), file=self.logf)
    self.logf.flush()

def query(a, dbc, out, encoding='iso8859-15', remote=True):
  l = whoisdb.Lookup(dbc)

  if not a:
    return

  real_info = False
  try:
    opts, args = getopt.getopt(a.split(), "UR")
  except getopt.GetoptError:
    return

  for optval, aval in opts:
    if optval == '-R' and not remote:
      real_info = True
    elif optval == '-U':
      encoding = 'utf-8'

  a = ' '.join(args)
  if not isinstance(a, str):
    a = a.decode(encoding)

  if a[0] == '/' and not remote:
    ld = l.domains_by_handle(a[1:])
    for d in ld:
      if real_info:
        d.fetch()
      else:
        d.fetch_obfuscated()
      if encoding is not None:
        out.write(str(d).encode(encoding, 'xmlcharrefreplace')+b'\n')
      else:
        print(d, file=out)
    return

  d = l.domain_by_name(a)
  if d is not None:
    dc = d.get_contacts()
    if real_info:
      d.fetch()
    else:
      d.fetch_obfuscated()
    if encoding is not None:
      out.write(str(d).encode(encoding, 'xmlcharrefreplace')+b'\n')
    else:
      print(d, file=out)
    pdone = []
    for k in ['technical', 'administrative', 'zone']:
      if k not in dc:
        continue
      for p in dc[k]:
        if real_info:
          p.fetch()
        else:
          p.fetch_obfuscated()
        if p.key not in pdone:
          if encoding is not None:
            out.write(str(p).encode(encoding, 'xmlcharrefreplace')+b'\n')
          else:
            print(p, file=out)
          pdone.append(p.key)
    return

  lp = l.persons_by_handle(a)
  if not lp:
    lp = l.persons_by_name(a)
  if not lp and not remote and a.find('@') >= 0:
    lp = l.persons_by_email(a)
  if not lp:
    d = "Key not found"
    if encoding is not None:
      out.write(str(d).encode(encoding, 'xmlcharrefreplace')+b'\n')
    else:
      print(d, file=out)
    return
  for p in lp:
    if real_info:
      p.fetch()
    else:
      p.fetch_obfuscated()
    if encoding is not None:
      out.write(str(p).encode(encoding, 'xmlcharrefreplace')+b'\n')
    else:
      print(p, file=out)

def usage():
  print(__doc__, file=sys.stderr)

def command(argv):
  whoiserrlog, whoisrqlog, runas, port = ERRLOG, RQLOG, USERID, PORT
  dbstr = autoreg.conf.dbstring
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
      dbstr = a
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
      server(dbstr, whoisrqlog, whoiserrlog, port, runas)
    r = os.fork()
    if r == 0:
      server(dbstr, whoisrqlog, whoiserrlog, port, runas)
    elif r == -1:
      print("Daemon start failed", file=sys.stderr)
      return 1
    else:
      print("Daemon started", file=sys.stderr)
  else:
    dbh = psycopg2.connect(dbstr)
    dbc = dbh.cursor()
    query(args[0], dbc, sys.stdout, remote=False)
  return 0

def whoisdbmain():
  sys.exit(command(sys.argv))

if __name__ == "__main__":
  whoisdbmain()
