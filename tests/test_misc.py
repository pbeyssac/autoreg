#!/usr/local/bin/python3.6


import io
import os
import unittest


import autoreg.dns.check
import autoreg.newsecret


class TestHandles(unittest.TestCase):
  def test1(self):
    autoreg.newsecret.new_handle_secret()
  def test2(self):
    os.environ['USER'] = 'autoreg'
    out = io.StringIO()
    autoreg.dns.check.main_checkallsoa(file=out)


if __name__ == '__main__':
  unittest.main()
