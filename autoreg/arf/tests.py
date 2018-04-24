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
Subject: =?utf-8?Q?le=20m=C3=B8=C3=B8se=20=C3=A0=20l&#39;=C3=A9cole?=
X-Origin: arf
Mime-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable


Best=20Regards,
The=20=20team
""")
