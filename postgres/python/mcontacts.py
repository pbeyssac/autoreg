#!/usr/local/bin/python

import psycopg
import os
import sys

import conf
import whoisdb

def reloaddb(dbh, file, encoding):
  w = whoisdb.Main(dbh)
  w.parsefile(file, encoding)

dbh = psycopg.connect(conf.dbstring)
reloaddb(dbh, sys.stdin, 'ISO-8859-1')
