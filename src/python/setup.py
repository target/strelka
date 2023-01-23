#!/usr/bin/env python3
import setuptools

setuptools.setup(
    name='strelka',
    author='Target Brands, Inc.',
    description='strelka: container-based file analysis at scale',
    license='Apache 2.0',
    packages=setuptools.find_packages(),
    scripts=['bin/strelka-backend', 'bin/strelka-mmrpc'],
    zip_safe=True,
    entry_points={
        'console_scripts': [
            'strelka = strelka.__main__:main',
        ]
    }
)
