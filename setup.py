#!/usr/bin/env python3
import setuptools

setuptools.setup(
    name='strelka',
    version='1.0.0-beta.1',
    author='Target Brands, Inc.',
    description='strelka: scanning files at scale with python and gRPC(?)',
    license='Apache 2.0',
    packages=setuptools.find_packages(),
    data_files=[('/etc/strelka', ['etc/server.yaml', 'etc/scan.yaml', 'etc/logging.yaml', 'etc/passwords.txt']), ('/etc/strelka/taste/', ['etc/taste/taste.yara'])],
    scripts=['strelka.py', 'strelka_pb2.py', 'strelka_pb2_grpc.py'],
)
