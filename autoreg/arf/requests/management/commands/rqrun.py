from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


import io

from django.core.management.base import BaseCommand, CommandError

from autoreg.arf.requests.models import rq_run


class Command(BaseCommand):
  help = 'Run pending requests'

  def handle(self, outfile=None, *args, **options):
    if outfile is None:
      outfile = self.stdout
    out = io.StringIO()
    rq_run(out)
    o = out.getvalue()
    if o:
      # don't output if empty, or write() will add a newline, which
      # messes up cron (useless mail).
      outfile.write(o.encode('utf-8'))
