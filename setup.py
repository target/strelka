#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name="strelka",
    version="0.99",
    author="Target Brands, Inc.",
    description="strelka: scanning files at scale with python and zeromq",
    license="Apache 2.0",
    packages=find_packages(),
    data_files=[("/etc/strelka", ["etc/strelka/strelka.yml", "etc/strelka/pylogging.ini", "etc/strelka/taste.yara", "etc/dirstream/dirstream.yml"])],
    scripts=["strelka.py", "strelka_dirstream.py", "strelka_user_client.py", "generate_curve_certificates.py", "validate_yara.py"],
    zip_safe=False
)
