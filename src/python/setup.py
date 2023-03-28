#!/usr/bin/env python3
import setuptools

import strelka

setuptools.setup(
    name="strelka",
    version=strelka.__version__,
    author="Target Brands, Inc.",
    description="strelka: container-based file analysis at scale",
    license="Apache 2.0",
    packages=setuptools.find_packages(),
    scripts=["bin/strelka-backend"],
    zip_safe=False,
    entry_points={
        "console_scripts": [
            "strelka = strelka.__main__:main",
        ]
    },
)
