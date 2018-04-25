from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

from django.test import TestCase

from . import util


class RenderMailTestCase(TestCase):
  def setUp(self):
    pass

  def test_render_to_mail(self):
    subject = "le møøse à l'école"
    msg = util._render_to_mail("base-varheaders.mail",
                               {'to': 'foobar2@local', 'subject': subject}, 'foobar@local',
                               ['foobar2@local'], request=None, language=None)
    self.assertEqual(msg, """From: foobar@local
To: foobar2@local
Subject: =?utf-8?Q?le=20m=C3=B8=C3=B8se=20=C3=A0=20l'=C3=A9cole?=
X-Origin: arf
Mime-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable


Best=20Regards,
The=20=20team
""")
  def test_render_to_mail2(self):
    self.maxDiff = None
    subject = "with dømains"
    c = {'to': 'foobar2@local', 'subject': subject,
         'rqid': '20180425111111-test-2222',
         'domain': 'TEST.EU.ORG',
         'reasonfield': "<REASØNFIELD> ""\'\'\n",
         'whoisrecord': "<WHØISRECORD> \"\"''", 'zonerecord': "<ZØNERECORD \"\"''>\n"}
    msg = util._render_to_mail("whois/domainnew.mail",
                               c, 'foobar@local',
                               ['foobar2@local'], request=None, language=None)
    self.assertEqual(msg, """From: foobar@local
To: foobar2@local
Subject: request [20180425111111-test-2222] (domain TEST.EU.ORG) accepted
X-Origin: arf
Mime-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable

Hello,

Your=20request=20[20180425111111-test-2222]=20for=20creation=20of=20domain=
=20TEST.EU.ORG
has=20been=20accepted.

The=20following=20records=20will=20be=20inserted=20in=20the=20zone=20file:
<Z=C3=98NERECORD=20""''>


The=20following=20records=20will=20be=20inserted=20in=20the=20WHOIS=20base:
<WH=C3=98ISRECORD>=20""''
Additional=20comment:

<REAS=C3=98NFIELD>=20''


Please=20allow=20about=20half=20a=20day=20for=20propagation.


Best=20Regards,
The=20=20team
""")
