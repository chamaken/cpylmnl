#! /usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import print_function

import unittest

class TestSuite(unittest.TestCase):
    def test_import_only(self):
        try:
            from cpylmnl.linux.netfilter import nf_conntrack_commonh
            from cpylmnl.linux.netfilter import nf_conntrack_tcph
            from cpylmnl.linux.netfilter import nfnetlink_compath
            from cpylmnl.linux.netfilter import nfnetlink_conntrackh
            from cpylmnl.linux.netfilter import nfnetlink_logh
            from cpylmnl.linux.netfilter import nfnetlink_queueh
            from cpylmnl.linux.netfilter import nfnetlinkh
        except Exception as e:
            self.fail("could not import: %r" % e)

if __name__ == '__main__':
    unittest.main()
