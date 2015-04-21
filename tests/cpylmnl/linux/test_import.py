#! /usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import print_function

import unittest

class TestSuite(unittest.TestCase):
    def test_import_only(self):
        try:
            from cpylmnl.linux import genetlinkh
            from cpylmnl.linux import if_addrh
            from cpylmnl.linux import if_linkh
            from cpylmnl.linux import ifh
            from cpylmnl.linux import netfilterh
            from cpylmnl.linux import netlinkh
            from cpylmnl.linux import rtnetlinkh
        except Exception as e:
            self.fail("could not import: %r" % e)

if __name__ == '__main__':
    unittest.main()
