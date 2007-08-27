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

import psycopg

import autoreg.conf
import autoreg.whois.db as whoisdb

runas = 'whois'
whoisrqlog = '/var/log/whoisd.log'
whoiserrlog = '/var/log/whoisd.err'
dbstring = autoreg.conf.dbstring

maxforks = 5
maxtime = 60
delay = 1
port = 43
logf = None

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

def log(msg):
  global logf
  (year, month, day, hh, mm, ss, d1, d2, d3) = time.localtime(time.time())
  print >>logf, "%04d%02d%02d %02d%02d%02d %s" % \
		 (year, month, day, hh, mm, ss, msg)
  logf.flush()

def daemon():
  global logf
  logf = open(whoisrqlog, 'a')
  sys.stderr = open(whoiserrlog, 'a')

  s = socket.socket()
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind(('0', port))
  s.listen(255)

  p = pwd.getpwnam(runas)
  gid = p.pw_gid
  uid = p.pw_uid
  os.setgid(gid)
  os.setuid(uid)
  pidinfo = {}

  nfree = maxforks
  while True:
    while nfree < maxforks:
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
        log("WARNING: reaped an unknown process")
      nfree += 1

    now = time.time()
    for pid in pidinfo:
      # kill hung processes
      t, a = pidinfo[pid]
      ip, cport = a
      if t + maxtime < now:
        try:
          log("WARNING: killing hung process %d (%s)" % (pid, ip))
          os.kill(pid, signal.SIGTERM)
        except OSError, e:
          if e.errno != errno.ESRCH:
            raise e

    if nfree > 0:
      c, a = s.accept()
      try:
        f = os.fork()
      except OSError, e:
        log("ERROR: cannot fork, %s" % e)
        f = -1
      if f == 0:
        # in child process
        s.close()
        handleclient(c, a)
	# crude rate control
        time.sleep(delay)
        sys.exit(0)
      elif f > 0:
        # in parent process
        pidinfo[f] = (time.time(), a)
        nfree -= 1
        if nfree == 0:
	  log("WARNING: maxforks (%d) reached" % maxforks)

def handleclient(c, a):
    w = socketwrapper(c)
    sys.stdout = w
    ip, cport = a
    c.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    q = ''
    r = c.recv(256)
    while r:
      q += r
      i = q.find('\r\n')
      if i >= 0:
	q = q[:i]
	log("%s %s" % (ip, q))
	query(q, w, remote = (ip != '127.0.0.1'))
	c.shutdown(socket.SHUT_WR)
	break
      r = c.recv(256)
    c.close()

def query(a, out, encoding='ISO-8859-1', remote=True):
  dbh = psycopg.connect(dbstring)
  l = whoisdb.Lookup(dbh.cursor())

  if a[0] == '/' and not remote:
    ld = l.domains_by_handle(a[1:])
    for d in ld:
      d.fetch()
      print d.__str__().encode(encoding, 'xmlcharrefreplace')
    return

  d = l.domain_by_name(a)
  if d != None:
    dc = d.get_contacts()
    print d.__str__().encode(encoding, 'xmlcharrefreplace')
    pdone = []
    for k in ['technical', 'administrative', 'zone']:
      if not k in dc:
        continue
      for p in dc[k]:
        p.fetch()
        if not p.key in pdone:
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
    p.fetch()
    print p.__str__().encode(encoding, 'xmlcharrefreplace')

def usage():
    print >>sys.stderr, __doc__

def main():
  global dbstring, whoiserrlog, whoisrqlog, port, runas
  detach = True

  try:
    opts, args = getopt.getopt(sys.argv[1:], "dD:e:l:p:u:")
  except getopt.GetoptError:
    usage()
    sys.exit(1)

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
    sys.exit(1)

  if len(args) == 0:
    if not detach:
      daemon()
    r = os.fork()
    if r == 0:
      daemon()
    elif r == -1:
      print >>sys.stderr, "Daemon start failed"
      sys.exit(1)
    else:
      print >>sys.stderr, "Daemon started"
  else:
    query(args[0], sys.stdout, remote=False)

if __name__ == "__main__":
  main()
