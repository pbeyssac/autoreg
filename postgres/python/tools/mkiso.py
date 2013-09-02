#!/usr/local/bin/python

f = open('/usr/share/misc/iso3166')

for l in f:
  l = l[:-1]
  if not l.startswith('#'):
    two, three, number, name = l.split('\t', 3)
    name = name.replace("'", "''")
    print "INSERT INTO iso3166_countries VALUES('%s', 'EN', '%s');" % (two.upper(), name)

f.close()
