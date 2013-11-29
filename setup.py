#!/usr/bin/env python

from distutils.core import setup

readme = open("README.md", "r")

setup(name='cpylmnl',
      version='0.1',
      description='libmnl Python wrapping',
      author='Ken-ichirou MATSUZAWA',
      author_email='chamas@h4.dion.ne.jp',
      url='https://github.com/chamaken/cpylmnl',
      license='GPLv2+',
      packages=['cpylmnl',]
      classifiers=['License :: OSI Approved :: GNU General Public ' +
                   'License v2 or later (GPLv2+)',
                   'Programming Language :: Python',
                   'Topic :: Software Development :: Libraries :: ' +
                   'Python Modules',
                   'Operating System :: Linux',
                   'Intended Audience :: Developers',
                   'Development Status :: 2 - Pre-Alpha'],
      long_description=readme.read())
