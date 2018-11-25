#!/usr/bin/env python

import os

from setuptools import setup, Extension
from gnutls import __info__ as package_info


def find_packages(toplevel):
    return [directory.replace(os.path.sep, '.') for directory, subdirs, files in os.walk(toplevel) if '__init__.py' in files]

setup(
    name=package_info.__project__,
    version=package_info.__version__,

    description=package_info.__summary__,
    long_description=open('README').read(),
    license=package_info.__license__,
    url=package_info.__webpage__,

    author=package_info.__author__,
    author_email=package_info.__email__,

    platforms=["Platform Independent"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],

    packages=find_packages('gnutls')
)

pygnutls = Extension('_libgnutls',
                     sources = ['pygnutls.c'],
                     libraries = ['gnutls'])

setup(
    name='libgnutls',
    version=package_info.__version__,

    ext_modules = [pygnutls],
    # do not create an egg from it so we can cdll.LoadLibrary() it
    zip_safe = False,
)
