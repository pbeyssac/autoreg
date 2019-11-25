#!/usr/local/bin/python3.6


import io
import os
import re
import unittest

import autoreg.dns.access


class TestAccessShowHistory(unittest.TestCase):
  def test_default(self):
    self.maxDiff = None
    out = io.StringIO()
    os.environ['USER'] = 'autoreg'
    autoreg.dns.access.main(['access-zone', '-ashowhist', 'H1.HISTORY.TESTS.EU.ORG'], outfile=out)
    v = out.getvalue()
    self.assertEqual("""; From 2018-06-21 16:50:17.330000 to ...
			600	A	192.168.2.6
			600	AAAA	2001:db8::1:4
; From 2018-06-21 16:50:09.050000 to 2018-06-21 16:50:17.330000
			600	A	192.168.2.6
; From 2018-06-21 11:55:51.750000 to 2018-06-21 16:50:09.050000
			600	A	192.168.2.6
			3600	AAAA	2001:db8::1:4
; From 2018-06-21 11:55:42.730000 to 2018-06-21 11:55:51.750000
			3600	AAAA	2001:db8::1:4
; From 2018-06-20 20:05:43.440000 to 2018-06-21 11:55:42.730000
			600	A	192.168.4.1
			3600	AAAA	2001:db8::1:4
; From 2018-06-20 20:05:35.430000 to 2018-06-20 20:05:43.440000
			3600	AAAA	2001:db8::1:4
; From 2018-06-06 11:19:43.950000 to 2018-06-20 20:05:35.430000
			3600	A	192.168.2.6
			3600	AAAA	2001:db8::1:4
; From 2018-02-01 12:25:39.160000 to 2018-06-06 11:19:43.950000
			3600	A	192.168.2.6
; From 2017-09-27 10:17:10.440000 to 2018-02-01 12:25:39.160000
			3600	A	192.168.2.6
			600	AAAA	2001:db8::1:4
; From 2016-10-02 13:19:22.750000 to 2017-09-27 10:17:10.440000
			3600	A	192.168.2.6
			3600	AAAA	2001:db8::1:4
; From 2016-10-01 09:43:33.990000 to 2016-10-02 13:19:22.750000
			3600	A	192.168.2.6
			3600	AAAA	2001:db8::1:4
			3600	AAAA	2001:db8::1:4
; From 2016-09-30 22:38:32.060000 to 2016-10-01 09:43:33.990000
			600	A	192.168.2.6
			600	AAAA	2001:db8::0:4
; From 2016-02-29 21:30:25.090000 to 2016-09-30 22:38:32.060000
			3600	A	192.168.2.6
			3600	AAAA	2001:db8::0:4
; From 2015-10-02 18:28:07.890000 to 2016-02-29 21:30:25.090000
				A	192.168.2.6
				AAAA	2001:db8::0:4
; From 2015-09-23 15:17:36.110000 to 2015-10-02 18:28:07.890000
				A	192.168.2.6
; From 2015-09-21 15:24:25.060000 to 2015-09-23 15:17:36.110000
				A	192.168.2.6
			600	AAAA	2001:db8::0:4
; From 2015-09-21 15:24:15.930000 to 2015-09-21 15:24:25.060000
				A	192.168.2.6
; From 2015-05-19 16:22:31.050000 to 2015-09-21 15:24:15.930000
				A	192.168.2.6
				AAAA	2001:db8::0:4
; From 2014-05-02 23:52:19.840000 to 2015-05-19 16:22:31.050000
				A	192.168.2.6
				AAAA	2001:db8::0:3
; From 2014-04-28 19:17:29.120000 to 2014-05-02 23:52:19.840000
			600	A	192.168.2.6
			600	AAAA	2001:db8::0:3
; From 2014-03-23 16:56:47.080000 to 2014-04-28 19:17:29.120000
			600	A	192.168.2.6
			600	AAAA	2001:db8::4:3
; From 2014-03-21 22:20:30.590000 to 2014-03-23 16:56:47.080000
			600	A	192.168.1.3
			600	AAAA	2001:db8::4:3
; From 2014-02-28 22:20:30.590000 to 2014-03-21 22:20:30.590000
			600	A	192.168.1.3
			7200	A	192.168.1.3
			600	AAAA	2001:db8::4:3
; From 2009-01-06 20:58:50.770000 to 2014-02-28 22:20:30.590000
			7200	A	192.168.1.3
			7200	AAAA	2001:db8::4:3
; From 2008-12-01 23:52:54.180000 to 2009-01-06 20:58:50.770000
			7200	A	192.168.1.3
			7200	AAAA	2001:db8:4::1:2
; From 2008-12-01 20:25:05.710000 to 2008-12-01 23:52:54.180000
			7200	A	192.168.1.3
; From 2008-11-29 23:26:13.730000 to 2008-12-01 20:25:05.710000
			7200	A	192.168.1.3
			60	AAAA	2001:db8:4::1:2
; From 2008-11-29 18:42:55.640000 to 2008-11-29 23:26:13.730000
			7200	A	192.168.1.3
			60	AAAA	2001:db8:4::1:f
; From 2008-11-29 18:32:30.540000 to 2008-11-29 18:42:55.640000
			7200	A	192.168.1.3
			600	AAAA	2001:db8:4::1:f
; From 2008-08-05 08:38:02.880000 to 2008-11-29 18:32:30.540000
			7200	A	192.168.1.3
			7200	AAAA	2001:db8:4::1:f
; From 2008-07-21 11:45:16.620000 to 2008-08-05 08:38:02.880000
			600	A	192.168.0.2
			60	AAAA	2001:db8:4::1:f
; From 2000-02-29 20:16:02.930000 to 2008-07-21 11:45:16.620000
				A	192.168.0.2
			60	AAAA	2001:db8:4::1:f
; From 1997-12-14 18:20:34.970000 to 2000-02-29 20:16:02.930000
				A	192.168.0.2
			3600	AAAA	2001:db8:4::1:f
; From 1997-10-14 08:42:24.870000 to 1997-12-14 18:20:34.970000
				A	192.168.0.2
				AAAA	2001:db8:4::1:f
; From 1997-01-06 14:11:38.940000 to 1997-10-14 08:42:24.870000
				A	192.168.0.2
""",
    v)

  def test_reverse(self):
    self.maxDiff = None
    out = io.StringIO()
    os.environ['USER'] = 'autoreg'
    autoreg.dns.access.main(['access-zone', '-ashowhist', '-r', 'H1.HISTORY.TESTS.EU.ORG'], outfile=out)
    v = out.getvalue()
    self.assertEqual("""; From 1997-01-06 14:11:38.940000 to 1997-10-14 08:42:24.870000
				A	192.168.0.2
; From 1997-10-14 08:42:24.870000 to 1997-12-14 18:20:34.970000
				A	192.168.0.2
				AAAA	2001:db8:4::1:f
; From 1997-12-14 18:20:34.970000 to 2000-02-29 20:16:02.930000
				A	192.168.0.2
			3600	AAAA	2001:db8:4::1:f
; From 2000-02-29 20:16:02.930000 to 2008-07-21 11:45:16.620000
				A	192.168.0.2
			60	AAAA	2001:db8:4::1:f
; From 2008-07-21 11:45:16.620000 to 2008-08-05 08:38:02.880000
			600	A	192.168.0.2
			60	AAAA	2001:db8:4::1:f
; From 2008-08-05 08:38:02.880000 to 2008-11-29 18:32:30.540000
			7200	A	192.168.1.3
			7200	AAAA	2001:db8:4::1:f
; From 2008-11-29 18:32:30.540000 to 2008-11-29 18:42:55.640000
			7200	A	192.168.1.3
			600	AAAA	2001:db8:4::1:f
; From 2008-11-29 18:42:55.640000 to 2008-11-29 23:26:13.730000
			7200	A	192.168.1.3
			60	AAAA	2001:db8:4::1:f
; From 2008-11-29 23:26:13.730000 to 2008-12-01 20:25:05.710000
			7200	A	192.168.1.3
			60	AAAA	2001:db8:4::1:2
; From 2008-12-01 20:25:05.710000 to 2008-12-01 23:52:54.180000
			7200	A	192.168.1.3
; From 2008-12-01 23:52:54.180000 to 2009-01-06 20:58:50.770000
			7200	A	192.168.1.3
			7200	AAAA	2001:db8:4::1:2
; From 2009-01-06 20:58:50.770000 to 2014-02-28 22:20:30.590000
			7200	A	192.168.1.3
			7200	AAAA	2001:db8::4:3
; From 2014-02-28 22:20:30.590000 to 2014-03-21 22:20:30.590000
			7200	A	192.168.1.3
			600	A	192.168.1.3
			600	AAAA	2001:db8::4:3
; From 2014-03-21 22:20:30.590000 to 2014-03-23 16:56:47.080000
			600	A	192.168.1.3
			600	AAAA	2001:db8::4:3
; From 2014-03-23 16:56:47.080000 to 2014-04-28 19:17:29.120000
			600	A	192.168.2.6
			600	AAAA	2001:db8::4:3
; From 2014-04-28 19:17:29.120000 to 2014-05-02 23:52:19.840000
			600	A	192.168.2.6
			600	AAAA	2001:db8::0:3
; From 2014-05-02 23:52:19.840000 to 2015-05-19 16:22:31.050000
				A	192.168.2.6
				AAAA	2001:db8::0:3
; From 2015-05-19 16:22:31.050000 to 2015-09-21 15:24:15.930000
				A	192.168.2.6
				AAAA	2001:db8::0:4
; From 2015-09-21 15:24:15.930000 to 2015-09-21 15:24:25.060000
				A	192.168.2.6
; From 2015-09-21 15:24:25.060000 to 2015-09-23 15:17:36.110000
				A	192.168.2.6
			600	AAAA	2001:db8::0:4
; From 2015-09-23 15:17:36.110000 to 2015-10-02 18:28:07.890000
				A	192.168.2.6
; From 2015-10-02 18:28:07.890000 to 2016-02-29 21:30:25.090000
				A	192.168.2.6
				AAAA	2001:db8::0:4
; From 2016-02-29 21:30:25.090000 to 2016-09-30 22:38:32.060000
			3600	A	192.168.2.6
			3600	AAAA	2001:db8::0:4
; From 2016-09-30 22:38:32.060000 to 2016-10-01 09:43:33.990000
			600	A	192.168.2.6
			600	AAAA	2001:db8::0:4
; From 2016-10-01 09:43:33.990000 to 2016-10-02 13:19:22.750000
			3600	A	192.168.2.6
			3600	AAAA	2001:db8::1:4
			3600	AAAA	2001:db8::1:4
; From 2016-10-02 13:19:22.750000 to 2017-09-27 10:17:10.440000
			3600	A	192.168.2.6
			3600	AAAA	2001:db8::1:4
; From 2017-09-27 10:17:10.440000 to 2018-02-01 12:25:39.160000
			3600	A	192.168.2.6
			600	AAAA	2001:db8::1:4
; From 2018-02-01 12:25:39.160000 to 2018-06-06 11:19:43.950000
			3600	A	192.168.2.6
; From 2018-06-06 11:19:43.950000 to 2018-06-20 20:05:35.430000
			3600	A	192.168.2.6
			3600	AAAA	2001:db8::1:4
; From 2018-06-20 20:05:35.430000 to 2018-06-20 20:05:43.440000
			3600	AAAA	2001:db8::1:4
; From 2018-06-20 20:05:43.440000 to 2018-06-21 11:55:42.730000
			600	A	192.168.4.1
			3600	AAAA	2001:db8::1:4
; From 2018-06-21 11:55:42.730000 to 2018-06-21 11:55:51.750000
			3600	AAAA	2001:db8::1:4
; From 2018-06-21 11:55:51.750000 to 2018-06-21 16:50:09.050000
			600	A	192.168.2.6
			3600	AAAA	2001:db8::1:4
; From 2018-06-21 16:50:09.050000 to 2018-06-21 16:50:17.330000
			600	A	192.168.2.6
; From 2018-06-21 16:50:17.330000 to ...
			600	A	192.168.2.6
			600	AAAA	2001:db8::1:4
""",
      v)
  def test_diff(self):
    self.maxDiff = None
    out = io.StringIO()
    os.environ['USER'] = 'autoreg'
    autoreg.dns.access.main(['access-zone', '-ashowhist', '-U', 'H1.HISTORY.TESTS.EU.ORG'], outfile=out)
    v = out.getvalue()
    self.assertEqual("""; At 2018-06-21 16:50:17.330000
                          600     A       192.168.2.6
+                         600     AAAA    2001:db8::1:4
; At 2018-06-21 16:50:09.050000
                          600     A       192.168.2.6
-                         3600    AAAA    2001:db8::1:4
; At 2018-06-21 11:55:51.750000
+                         600     A       192.168.2.6
                          3600    AAAA    2001:db8::1:4
; At 2018-06-21 11:55:42.730000
-                         600     A       192.168.4.1
                          3600    AAAA    2001:db8::1:4
; At 2018-06-20 20:05:43.440000
+                         600     A       192.168.4.1
                          3600    AAAA    2001:db8::1:4
; At 2018-06-20 20:05:35.430000
-                         3600    A       192.168.2.6
                          3600    AAAA    2001:db8::1:4
; At 2018-06-06 11:19:43.950000
                          3600    A       192.168.2.6
+                         3600    AAAA    2001:db8::1:4
; At 2018-02-01 12:25:39.160000
                          3600    A       192.168.2.6
-                         600     AAAA    2001:db8::1:4
; At 2017-09-27 10:17:10.440000
                          3600    A       192.168.2.6
-                         3600    AAAA    2001:db8::1:4
+                         600     AAAA    2001:db8::1:4
; At 2016-10-02 13:19:22.750000
                          3600    A       192.168.2.6
                          3600    AAAA    2001:db8::1:4
-                         3600    AAAA    2001:db8::1:4
; At 2016-10-01 09:43:33.990000
-                         600     A       192.168.2.6
+                         3600    A       192.168.2.6
-                         600     AAAA    2001:db8::0:4
+                         3600    AAAA    2001:db8::1:4
+                         3600    AAAA    2001:db8::1:4
; At 2016-09-30 22:38:32.060000
-                         3600    A       192.168.2.6
+                         600     A       192.168.2.6
-                         3600    AAAA    2001:db8::0:4
+                         600     AAAA    2001:db8::0:4
; At 2016-02-29 21:30:25.090000
-                                 A       192.168.2.6
+                         3600    A       192.168.2.6
-                                 AAAA    2001:db8::0:4
+                         3600    AAAA    2001:db8::0:4
; At 2015-10-02 18:28:07.890000
                                  A       192.168.2.6
+                                 AAAA    2001:db8::0:4
; At 2015-09-23 15:17:36.110000
                                  A       192.168.2.6
-                         600     AAAA    2001:db8::0:4
; At 2015-09-21 15:24:25.060000
                                  A       192.168.2.6
+                         600     AAAA    2001:db8::0:4
; At 2015-09-21 15:24:15.930000
                                  A       192.168.2.6
-                                 AAAA    2001:db8::0:4
; At 2015-05-19 16:22:31.050000
                                  A       192.168.2.6
-                                 AAAA    2001:db8::0:3
+                                 AAAA    2001:db8::0:4
; At 2014-05-02 23:52:19.840000
-                         600     A       192.168.2.6
+                                 A       192.168.2.6
-                         600     AAAA    2001:db8::0:3
+                                 AAAA    2001:db8::0:3
; At 2014-04-28 19:17:29.120000
                          600     A       192.168.2.6
-                         600     AAAA    2001:db8::4:3
+                         600     AAAA    2001:db8::0:3
; At 2014-03-23 16:56:47.080000
-                         600     A       192.168.1.3
+                         600     A       192.168.2.6
                          600     AAAA    2001:db8::4:3
; At 2014-03-21 22:20:30.590000
                          600     A       192.168.1.3
-                         7200    A       192.168.1.3
                          600     AAAA    2001:db8::4:3
; At 2014-02-28 22:20:30.590000
+                         600     A       192.168.1.3
                          7200    A       192.168.1.3
-                         7200    AAAA    2001:db8::4:3
+                         600     AAAA    2001:db8::4:3
; At 2009-01-06 20:58:50.770000
                          7200    A       192.168.1.3
-                         7200    AAAA    2001:db8:4::1:2
+                         7200    AAAA    2001:db8::4:3
; At 2008-12-01 23:52:54.180000
                          7200    A       192.168.1.3
+                         7200    AAAA    2001:db8:4::1:2
; At 2008-12-01 20:25:05.710000
                          7200    A       192.168.1.3
-                         60      AAAA    2001:db8:4::1:2
; At 2008-11-29 23:26:13.730000
                          7200    A       192.168.1.3
-                         60      AAAA    2001:db8:4::1:f
+                         60      AAAA    2001:db8:4::1:2
; At 2008-11-29 18:42:55.640000
                          7200    A       192.168.1.3
-                         600     AAAA    2001:db8:4::1:f
+                         60      AAAA    2001:db8:4::1:f
; At 2008-11-29 18:32:30.540000
                          7200    A       192.168.1.3
-                         7200    AAAA    2001:db8:4::1:f
+                         600     AAAA    2001:db8:4::1:f
; At 2008-08-05 08:38:02.880000
-                         600     A       192.168.0.2
+                         7200    A       192.168.1.3
-                         60      AAAA    2001:db8:4::1:f
+                         7200    AAAA    2001:db8:4::1:f
; At 2008-07-21 11:45:16.620000
-                                 A       192.168.0.2
+                         600     A       192.168.0.2
                          60      AAAA    2001:db8:4::1:f
; At 2000-02-29 20:16:02.930000
                                  A       192.168.0.2
-                         3600    AAAA    2001:db8:4::1:f
+                         60      AAAA    2001:db8:4::1:f
; At 1997-12-14 18:20:34.970000
                                  A       192.168.0.2
-                                 AAAA    2001:db8:4::1:f
+                         3600    AAAA    2001:db8:4::1:f
; At 1997-10-14 08:42:24.870000
                                  A       192.168.0.2
+                                 AAAA    2001:db8:4::1:f
; At 1997-01-06 14:11:38.940000
+                                 A       192.168.0.2
""",
    v)
  def test_diff_reverse(self):
    self.maxDiff = None
    out = io.StringIO()
    os.environ['USER'] = 'autoreg'
    autoreg.dns.access.main(['access-zone', '-ashowhist', '-rU', 'H1.HISTORY.TESTS.EU.ORG'], outfile=out)
    v = out.getvalue()
    self.assertEqual("""; At 1997-01-06 14:11:38.940000
+                                 A       192.168.0.2
; At 1997-10-14 08:42:24.870000
                                  A       192.168.0.2
+                                 AAAA    2001:db8:4::1:f
; At 1997-12-14 18:20:34.970000
                                  A       192.168.0.2
-                                 AAAA    2001:db8:4::1:f
+                         3600    AAAA    2001:db8:4::1:f
; At 2000-02-29 20:16:02.930000
                                  A       192.168.0.2
-                         3600    AAAA    2001:db8:4::1:f
+                         60      AAAA    2001:db8:4::1:f
; At 2008-07-21 11:45:16.620000
-                                 A       192.168.0.2
+                         600     A       192.168.0.2
                          60      AAAA    2001:db8:4::1:f
; At 2008-08-05 08:38:02.880000
-                         600     A       192.168.0.2
+                         7200    A       192.168.1.3
-                         60      AAAA    2001:db8:4::1:f
+                         7200    AAAA    2001:db8:4::1:f
; At 2008-11-29 18:32:30.540000
                          7200    A       192.168.1.3
-                         7200    AAAA    2001:db8:4::1:f
+                         600     AAAA    2001:db8:4::1:f
; At 2008-11-29 18:42:55.640000
                          7200    A       192.168.1.3
-                         600     AAAA    2001:db8:4::1:f
+                         60      AAAA    2001:db8:4::1:f
; At 2008-11-29 23:26:13.730000
                          7200    A       192.168.1.3
-                         60      AAAA    2001:db8:4::1:f
+                         60      AAAA    2001:db8:4::1:2
; At 2008-12-01 20:25:05.710000
                          7200    A       192.168.1.3
-                         60      AAAA    2001:db8:4::1:2
; At 2008-12-01 23:52:54.180000
                          7200    A       192.168.1.3
+                         7200    AAAA    2001:db8:4::1:2
; At 2009-01-06 20:58:50.770000
                          7200    A       192.168.1.3
-                         7200    AAAA    2001:db8:4::1:2
+                         7200    AAAA    2001:db8::4:3
; At 2014-02-28 22:20:30.590000
                          7200    A       192.168.1.3
+                         600     A       192.168.1.3
-                         7200    AAAA    2001:db8::4:3
+                         600     AAAA    2001:db8::4:3
; At 2014-03-21 22:20:30.590000
-                         7200    A       192.168.1.3
                          600     A       192.168.1.3
                          600     AAAA    2001:db8::4:3
; At 2014-03-23 16:56:47.080000
-                         600     A       192.168.1.3
+                         600     A       192.168.2.6
                          600     AAAA    2001:db8::4:3
; At 2014-04-28 19:17:29.120000
                          600     A       192.168.2.6
-                         600     AAAA    2001:db8::4:3
+                         600     AAAA    2001:db8::0:3
; At 2014-05-02 23:52:19.840000
-                         600     A       192.168.2.6
+                                 A       192.168.2.6
-                         600     AAAA    2001:db8::0:3
+                                 AAAA    2001:db8::0:3
; At 2015-05-19 16:22:31.050000
                                  A       192.168.2.6
-                                 AAAA    2001:db8::0:3
+                                 AAAA    2001:db8::0:4
; At 2015-09-21 15:24:15.930000
                                  A       192.168.2.6
-                                 AAAA    2001:db8::0:4
; At 2015-09-21 15:24:25.060000
                                  A       192.168.2.6
+                         600     AAAA    2001:db8::0:4
; At 2015-09-23 15:17:36.110000
                                  A       192.168.2.6
-                         600     AAAA    2001:db8::0:4
; At 2015-10-02 18:28:07.890000
                                  A       192.168.2.6
+                                 AAAA    2001:db8::0:4
; At 2016-02-29 21:30:25.090000
-                                 A       192.168.2.6
+                         3600    A       192.168.2.6
-                                 AAAA    2001:db8::0:4
+                         3600    AAAA    2001:db8::0:4
; At 2016-09-30 22:38:32.060000
-                         3600    A       192.168.2.6
+                         600     A       192.168.2.6
-                         3600    AAAA    2001:db8::0:4
+                         600     AAAA    2001:db8::0:4
; At 2016-10-01 09:43:33.990000
-                         600     A       192.168.2.6
+                         3600    A       192.168.2.6
-                         600     AAAA    2001:db8::0:4
+                         3600    AAAA    2001:db8::1:4
+                         3600    AAAA    2001:db8::1:4
; At 2016-10-02 13:19:22.750000
                          3600    A       192.168.2.6
                          3600    AAAA    2001:db8::1:4
-                         3600    AAAA    2001:db8::1:4
; At 2017-09-27 10:17:10.440000
                          3600    A       192.168.2.6
-                         3600    AAAA    2001:db8::1:4
+                         600     AAAA    2001:db8::1:4
; At 2018-02-01 12:25:39.160000
                          3600    A       192.168.2.6
-                         600     AAAA    2001:db8::1:4
; At 2018-06-06 11:19:43.950000
                          3600    A       192.168.2.6
+                         3600    AAAA    2001:db8::1:4
; At 2018-06-20 20:05:35.430000
-                         3600    A       192.168.2.6
                          3600    AAAA    2001:db8::1:4
; At 2018-06-20 20:05:43.440000
+                         600     A       192.168.4.1
                          3600    AAAA    2001:db8::1:4
; At 2018-06-21 11:55:42.730000
-                         600     A       192.168.4.1
                          3600    AAAA    2001:db8::1:4
; At 2018-06-21 11:55:51.750000
+                         600     A       192.168.2.6
                          3600    AAAA    2001:db8::1:4
; At 2018-06-21 16:50:09.050000
                          600     A       192.168.2.6
-                         3600    AAAA    2001:db8::1:4
; At 2018-06-21 16:50:17.330000
                          600     A       192.168.2.6
+                         600     AAAA    2001:db8::1:4
""",
    v)


class TestAccessCat(unittest.TestCase):
  def test_1(self):
    out = io.StringIO()
    os.environ['USER'] = 'autoreg'
    autoreg.dns.access.main(['access-zone', '-acat', 'HISTORY.TESTS.EU.ORG'], outfile=out)
    v = out.getvalue()
    self.assertEqual("""; zone name=HISTORY.TESTS.EU.ORG
$TTL 259200
@	SOA	NS.EU.ORG hostmaster.eu.org 2007110600 3600 1800 604800 259200
H1	600	A	192.168.2.6
	600	AAAA	2001:db8::1:4
""",
      v)
  def test_2(self):
    out = io.StringIO()
    os.environ['USER'] = 'autoreg'
    autoreg.dns.access.main(['access-zone', '-R', '-acat', 'HISTORY.TESTS.EU.ORG'], outfile=out)
    v = out.getvalue()
    self.assertEqual("""; zone name=HISTORY.TESTS.EU.ORG
HISTORY.TESTS.EU.ORG.	259200	IN	SOA	NS.EU.ORG hostmaster.eu.org 2007110600 3600 1800 604800 259200
H1.HISTORY.TESTS.EU.ORG.	600	IN	A	192.168.2.6
H1.HISTORY.TESTS.EU.ORG.	600	IN	AAAA	2001:db8::1:4
HISTORY.TESTS.EU.ORG.	259200	IN	SOA	NS.EU.ORG hostmaster.eu.org 2007110600 3600 1800 604800 259200
""",
      v)


class TestAccessShow(unittest.TestCase):
  def test_1(self):
    out = io.StringIO()
    os.environ['USER'] = 'autoreg'
    autoreg.dns.access.main(['access-zone', '-ashow', 'H1.HISTORY.TESTS.EU.ORG'], outfile=out)
    v = out.getvalue()
    self.assertEqual("""; zone HISTORY.TESTS.EU.ORG
; domain H1.HISTORY.TESTS.EU.ORG
H1			600	A	192.168.2.6
			600	AAAA	2001:db8::1:4
""",
      v)


# this should be executed last, hence the "Z" in the name
# (executed by alphabetic order)

class TestAccessZAddDelRR(unittest.TestCase):
  def test_1(self):
    os.environ['USER'] = 'autoreg'
    infile = io.StringIO("H1 NS NS.EU.ORG.\n")
    autoreg.dns.access.main(['access-zone', '-aaddrr', 'H1.HISTORY.TESTS.EU.ORG'], infile=infile)

    out = io.StringIO()
    autoreg.dns.access.main(['access-zone', '-ashow', 'H1.HISTORY.TESTS.EU.ORG'], outfile=out)
    v = out.getvalue()

    re_out = re.compile("; zone HISTORY\.TESTS\.EU\.ORG\n; domain H1\.HISTORY\.TESTS\.EU\.ORG\n"
                        "; updated: by autoreg, \d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+.\d\d:\d\d\n"
                        "H1			600	A	192\.168\.2\.6\n"
                        "			600	AAAA	2001:db8::1:4\n"
                        "				NS	NS\.EU\.ORG\.\n",
                        re.MULTILINE)
    self.assertNotEqual(None, re_out.match(v))
    autoreg.dns.access.main(['access-zone', '-adelrr', 'H1.HISTORY.TESTS.EU.ORG'], infile=infile)
    re_out = re.compile("; zone HISTORY\.TESTS\.EU\.ORG\n; domain H1\.HISTORY\.TESTS\.EU\.ORG\n"
                        "; updated: by autoreg, \d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+.\d\d:\d\d\n"
                        "H1			600	A	192\.168\.2\.6\n"
                        "			600	AAAA	2001:db8::1:4\n",
                        re.MULTILINE)
    self.assertNotEqual(None, re_out.match(v))
