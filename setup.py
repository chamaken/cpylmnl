#!/usr/bin/env python

from distutils.core import setup

readme = open("README.md", "r")

setup(name='cpylmnl',
      version='0.1',
      description='libmnl Python wrapper',
      author='Ken-ichirou MATSUZAWA',
      author_email='chamas@h4.dion.ne.jp',
      url='https://github.com/chamaken/cpylmnl',
      license='LGPLv2+',
      packages=['cpylmnl', 'cpylmnl.linux', 'cpylmnl.linux.netfilter',],
      classifiers=['License :: OSI Approved :: GNU Lesser General ' +
                   'Public License v2 or later (LGPLv2+)',
                   'Programming Language :: Python',
                   'Topic :: Software Development :: Libraries :: ' +
                   'Python Modules',
                   'Operating System :: Linux',
                   'Intended Audience :: Developers',
                   'Development Status :: 3 - Alpha Development Status'],
      long_description=readme.read(),
      test_suite = 'nose.collector',
)
