#!/usr/bin/env python
from setuptools import setup, find_packages
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
      install_requires=['toml', 'redis', 'kombu', 'markerlib',
                        'distribute', 'spoton-johny', 'dnspython',
                        'gglsbl'],
      packages=find_packages('src'),
      package_dir={'': 'src'},
      dependency_links=DEPENDENCY_LINKS,
)
