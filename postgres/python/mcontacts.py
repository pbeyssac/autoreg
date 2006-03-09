#!/usr/local/bin/python

import psycopg
import os
import sys

import conf
import whoisdb

def reloaddb(dbh, file):
  w = whoisdb.Main(dbh)
  w.parsefile(file)

dbh = psycopg.connect(conf.dbstring)
reloaddb(dbh, sys.stdin)
