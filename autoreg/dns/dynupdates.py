import select
import time


import psycopg2
import psycopg2.extensions


import autoreg.conf
import autoreg.dns.db


def dynupdates():
  dbh = psycopg2.connect(autoreg.conf.dbstring)
  dbc = dbh.cursor()

  # We can't set level to psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT because
  # we need explicit transactions. Instead, we commit when needed.
  #
  # LISTEN needs to be committed.
  # Then, notifications are only received between transactions.

  dd = autoreg.dns.db.db(dbc=dbc)
  dd.login('autoreg')
  dbc.execute("LISTEN dyn_transaction")
  dbh.commit()

  with open('/tmp/ddns.log', 'a+') as outfile, open('/tmp/ddns-fail.log', 'a+') as errout:

    while True:
      # Run updates, if any
      dd.updates(dbh=dbh, outfile=outfile, errout=errout)
      dbh.commit()
      outfile.flush()
      errout.flush()

      # All done, no transaction in progress, wait for notifications.
      # LISTEN/select/notification code from psycopg documentation http://initd.org/psycopg/docs/advanced.html

      select.select([dbh], [], [], None) == ([],[],[])
      dbh.poll()
      while dbh.notifies:
        notify = dbh.notifies.pop(0)
        #print("Got NOTIFY:", notify.pid, notify.channel, notify.payload, time.strftime('%Y%m%d-%H%M%S'))


if __name__ == "__main__":
  dynupdates()
