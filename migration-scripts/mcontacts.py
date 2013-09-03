#!/usr/local/bin/python

import psycopg

import conf
import whoisdb

def reloaddb(dbh, file, encoding):
  w = whoisdb.Main(dbh)
  w.parsefile(file, encoding)

def main():
  dbh = psycopg.connect(conf.dbstring)
  reloaddb(dbh, file('/local/dns-db/data/freenic/freenic.db'), 'ISO-8859-1')

if __name__ == "__main__":
  main()
