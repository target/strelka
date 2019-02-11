#!/usr/bin/env python3
import setuptools

setuptools.setup(
    name='strelka',
    version='0.99',
    author='Target Brands, Inc.',
    description='strelka: scanning files at scale with python and gRPC(?)',
    license='Apache 2.0',
    packages=['etc', 'server'],
    data_files=[('/etc/strelka', ['etc/strelka.yml', 'etc/scan.yml', 'etc/logging.yml', 'etc/passwords.txt']), ('/etc/strelka/taste/', ['etc/taste/taste.yara'])],
    scripts=['strelka.py', 'strelka_pb2.py', 'strelka_pb2_grpc.py'],
    zip_safe=False
)
