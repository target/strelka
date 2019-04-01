#!/usr/bin/env python3
import setuptools

setuptools.setup(
    name='strelka',
    version='0.0.0b1',
    author='Target Brands, Inc.',
    description='strelka: scanning files at scale with python and gRPC(?)',
    license='Apache 2.0',
    packages=setuptools.find_packages(),
    data_files=[('/usr/local/etc/strelka', ['cfg/backend.yaml', 'cfg/logging.yaml', 'cfg/passwords.txt']), ('/usr/local/etc/strelka/taste/', ['cfg/taste/taste.yara'])],
    scripts=['bin/strelka-backend']
)
