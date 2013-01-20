#!/usr/bin/env python

# distribute
from distribute_setup import use_setuptools
use_setuptools()
from setuptools import setup

setup(name='DNS-LG',
      version='2013012003', 
      description='DNS Looking Glass',
      license='BSD',
      author='Stephane Bortzmeyer',
      author_email='bortzmeyer+dnslg@nic.fr',
      url='https://github.com/bortzmeyer/dns-lg',
      download_url='https://github.com/bortzmeyer/dns-lg/tarball/master',
      packages=['DNSLG',],
      provides=['DNSLG',],
      install_requires=[] # We require netaddr, simpletal and
                          # dnspython but Python cannot find them,
                          # even when installed :-( Packaging in
                          # Python is completely broken, anyway
      )

