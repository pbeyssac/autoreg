#!/usr/local/bin/python
# $Id$

"""Usage:
Client mode:
whois.py request

Server mode:
whois.py [-D database-string] [-l request log] [-e stderr log] [-u user] [-d]
"""

import getopt
import os
import pwd
import socket
import sys
import time

import psycopg

import conf
import whoisdb

runas = 'whois'
whoisrqlog = '/var/log/whoisd.log'
whoiserrlog = '/var/log/whoisd.err'
dbstring = conf.dbstring

maxforks = 5
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

  nfree = maxforks
  while True:
    while nfree < maxforks:
      if nfree > 0:
        r = os.waitpid(-1, os.WNOHANG)
      else:
        r = os.waitpid(-1, 0)
      pid, status = r
      if pid == 0:
        break
      nfree += 1

    if nfree > 0:
      c, a = s.accept()
      f = os.fork()
      if f == 0:
        s.close()
        handleclient(c, a)
	# crude rate control
        time.sleep(delay)
        sys.exit(0)
      elif f > 0:
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
	query(q, w)
	c.shutdown(socket.SHUT_WR)
	break
      r = c.recv(256)
    c.close()

def query(a, out, encoding='ISO-8859-1', remote=True):
  dbh = psycopg.connect(dbstring)
  dbh.cursor().execute("SET client_encoding = '%s'" % encoding)
  l = whoisdb.Lookup(dbh.cursor())

  if a[0] == '/' and not remote:
    ld = l.domains_by_handle(a[1:])
    for d in ld:
      d.fetch()
      d.display()
    return

  d = l.domain_by_name(a)
  if d != None:
    dc = d.get_contacts()
    d.display()
    pdone = []
    for k in ['technical', 'administrative', 'zone']:
      if not k in dc:
        continue
      for p in dc[k]:
        p.fetch()
        if not p.key in pdone:
          p.display()
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
    p.display()

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
