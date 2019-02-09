#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='strelka',
    version='0.99',
    author='Target Brands, Inc.',
    description='strelka: scanning files at scale with python and gRPC(?)',
    license='Apache 2.0',
    packages=find_packages(),
    data_files=[('/etc/strelka', ['etc/strelka.yml', 'etc/scan.yml', 'etc/pylogging.ini', 'etc/passwords.txt']), ('/etc/strelka/taste/', ['etc/taste/taste.yara'])],
    zip_safe=False
)
