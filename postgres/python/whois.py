#!/usr/local/bin/python

import psycopg
import os
import socket
import sys

import conf
import whoisdb

class socketwrapper:
  def __init__(self, sock):
    self.s = sock
  def write(self, buf):
    while buf:
      r = self.s.send(buf)
      if r < 0:
	raise Error
      buf = buf[r:]

def daemon():
  s = socket.socket()
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind(('0', 4343))
  s.listen(255)
  while True:
    c, a = s.accept()
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
	print "FROM %s:%d GOT \"%s\"" % (ip, port, q)
	query(q, w)
	c.shutdown(socket.SHUT_WR)
	break
      r = c.revc(256)
    c.close()

def query(a, out):
  dbh = psycopg.connect(conf.dbstring)
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
        if not p.key in pdone:
          p.fetch()
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

if len(sys.argv) != 2:
  print >>sys.stderr, "Usage: %s [-d | query]" % sys.argv[0]
  sys.exit(1)

a = sys.argv[1]
if a == '-d':
  daemon()
else:
  query(a, sys.stdout)
