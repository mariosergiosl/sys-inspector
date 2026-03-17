#!/usr/bin/python3
# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: setup.py
# USAGE: python3 setup.py bdist_wheel (or python3 setup.py install)
# DESCRIPTION: Installation and packaging script for sys-inspector.
#              Configures the package for PyPi and local deployments.
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: 0.90.02
# ==============================================================================

"""
Setup script for sys-inspector.
"""

from setuptools import setup, find_packages

# ------------------------------------------------------------------------------
# READ LONG DESCRIPTION
# ------------------------------------------------------------------------------
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# ------------------------------------------------------------------------------
# PACKAGE SETUP CONFIGURATION
# ------------------------------------------------------------------------------
setup(
    name='sys-inspector',
    version='0.90.02',
    author='Mario Luz',
    author_email='mario.mssl@gmail.com',
    description='eBPF-based System Inspector and Forensic Tool (Multi-Agent/Web)',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/mariosergiosl/sys-inspector',

    # Source Layout Configuration
    packages=find_packages(),
    py_modules=['main'],

    # Entry Point (Creates the 'sys-inspector' command in /usr/bin)
    entry_points={
        'console_scripts': [
            'sys-inspector=main:main',
        ],
    },

    # Dependencies
    install_requires=[
        'flask',
        'cryptography',
        'pyyaml'
        # 'bcc', # BCC is usually installed via system package manager (zypper/apt)
    ],

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Systems Administration",
    ],
    python_requires='>=3.6',
)
