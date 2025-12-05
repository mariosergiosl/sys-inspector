#!/usr/bin/python3
# ===============================================================================
# -*- coding: utf-8 -*-
# FILE: setup.py
# DESCRIPTION: Installation script for sys-inspector.
# ===============================================================================

"""
Setup script for sys-inspector.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='sys-inspector',
    version='0.30.8',
    author='Mario Luz',
    author_email='mario.mssl@gmail.com',
    description='eBPF-based System Inspector and Forensic Tool',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/mariosergiosl/sys-inspector',

    # Source Layout Configuration
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    py_modules=['inspector'],  # Include the top-level inspector.py script

    # Entry Point (Creates the 'sys-inspector' command in /usr/bin)
    entry_points={
        'console_scripts': [
            'sys-inspector=inspector:main',
        ],
    },

    install_requires=[
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
