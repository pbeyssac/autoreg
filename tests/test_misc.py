#!/usr/local/bin/python3.6


import unittest


import autoreg.newsecret


class TestHandles(unittest.TestCase):
  def test1(self):
    autoreg.newsecret.new_handle_secret()
    
 
if __name__ == '__main__':
  unittest.main()
