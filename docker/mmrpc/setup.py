#!/usr/bin/env python3
import setuptools

setuptools.setup(
    name='strelka',
    version='0.0.0b2',
    author='Target Brands, Inc.',
    description='strelka: scanning files at scale with python and gRPC(?)',
    license='Apache 2.0',
    packages=setuptools.find_packages(),
    scripts=['bin/strelka-mmrpc']
)
