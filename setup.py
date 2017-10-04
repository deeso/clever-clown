#!/usr/bin/env python
from setuptools import setup, find_packages
from setuptools.command.install import install
import sys
# configure the setup to install from specific repos and users

DEPENDENCY_LINKS = [
    'https://github.com/deeso/spoton-johny/tarball/master#egg=spoton-johny-1.0.0'
]

DESC ='Python DNS tap for query monitoring'
setup(name='clever-clown',
      version='1.0',
      description=DESC,
      author='adam pridgen',
      author_email='dso@thecoverofnight.com',
      install_requires=['toml', 'redis', 'kombu', 'spoton-johny', 'dnspython', 'googlesafebrowsing'],
      packages=find_packages('src'),
      package_dir={'': 'src'},
      dependency_links=DEPENDENCY_LINKS,
)
