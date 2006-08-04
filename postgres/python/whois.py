#!/usr/local/bin/python

import psycopg
import os
import socket
import sys
import time

import conf
import whoisdb

maxforks = 5
delay = 1
port = 4343

class socketwrapper:
  def __init__(self, sock):
    self.s = sock
  def write(self, buf):
    while buf:
      r = self.s.send(buf)
      if r < 0:
	raise Error
      buf = buf[r:]

def log(msg):
  (year, month, day, hh, mm, ss, d1, d2, d3) = time.localtime(time.time())
  print "%04d%02d%02d %02d%02d%02d %s" % (year, month, day, hh, mm, ss, msg)

def daemon():
  s = socket.socket()
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind(('0', port))
  s.listen(255)
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
        time.sleep(delay)
        sys.exit(0)
      elif f > 0:
        nfree -= 1
        if nfree == 0:
	  log("WARNING: maxforks (%d) reached" % maxforks)

def handleclient(c, a):
    w = socketwrapper(c)
    ip, port = a
    c.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    q = ''
    r = c.recv(256)
    while r:
      q += r
      i = q.find('\r\n')
      if i >= 0:
	q = q[:i]
	log("%s:%s %s" % (ip, port, q))
	query(q, w)
	c.shutdown(socket.SHUT_WR)
	break
      r = c.revc(256)
    c.close()

def query(a, out, encoding='ISO-8859-1'):
  dbh = psycopg.connect(conf.dbstring)
  dbh.cursor().execute("SET client_encoding = '%s'" % encoding)
  l = whoisdb.Lookup(dbh.cursor())
  d = l.domain_by_name(a)
  if d != None:
    dc = d.get_contacts()
    d.display(out)
    print >>out
    pdone = []
    for k in ['technical', 'administrative', 'zone']:
      if not k in dc:
        continue
      for p in dc[k]:
        p.fetch()
        if not p.key in pdone:
          p.display(out)
          pdone.append(p.key)
          print >>out
    return

  lp = l.persons_by_handle(a)
  if not lp:
    lp = l.persons_by_name(a)
  if not lp:
    print >>out, "Key not found"
    return
  for p in lp:
    p.fetch()
    p.display(out)
    print >>out

if len(sys.argv) > 2:
  print >>sys.stderr, "Usage: %s [-d | query]" % sys.argv[0]
  sys.exit(1)

if len(sys.argv) < 2:
  daemon()
elif sys.argv[1] == '-d':
  r = os.fork()
  if r == 0:
    daemon()
  elif r == -1:
    print >>sys.stderr, "Daemon start failed"
    sys.exit(1)
  else:
    print >>sys.stderr, "Daemon started"
else:
  query(sys.argv[1], sys.stdout)
