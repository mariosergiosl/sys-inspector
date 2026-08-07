#!/usr/bin/python3
# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: setup.py
# USAGE: python3 setup.py bdist_wheel (or python3 setup.py install)
# DESCRIPTION: Installation and packaging script for sys-inspector.
#              Configures the package for PyPi and local deployments.
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.91.0
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

# A versao vem de um unico lugar. Ler o arquivo em vez de importa-lo evita
# depender do pacote durante a propria construcao dele.
_version = {}
with open("src/version.py", "r", encoding="utf-8") as fh:
    exec(fh.read(), _version)

# ------------------------------------------------------------------------------
# PACKAGE SETUP CONFIGURATION
# ------------------------------------------------------------------------------
setup(
    name='sys-inspector',
    version=_version['__version__'],
    license='AGPLv3',
    author='Mario Luz',
    author_email='mario.mssl[at]gmail.com',
    description='eBPF-based System Inspector and Forensic Tool (Multi-Agent/Web)',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/mariosergiosl/sys-inspector',

    # Source Layout Configuration
    packages=find_packages(),
    py_modules=['main'],
    scripts=[
        'tools/chaos_maker.sh',
        'tools/setup_env.sh',
        'tools/install_deps.sh',
        'tools/install_service.bash',
        'tools/generate_keys.py'
    ],
    include_package_data=True,
    data_files=[
        ('/etc/sys-inspector', [
            'conf/config.yaml'
        ]),
        ('/etc/systemd/system', ['systemd/sys-inspector.service'])
    ],
    # Entry Point (Creates the 'sys-inspector' command in /usr/bin)
    entry_points={
        'console_scripts': [
            'sys-inspector=main:main',
        ],
    },

    # Dependencies
    #
    # O nucleo carrega apenas o que TODO papel precisa: criptografia para a
    # evidencia e leitura de configuracao. Servidor web e sondas de kernel sao
    # exigencias de papeis distintos, e instala-las sempre significaria colocar
    # um servidor web dentro do host sob investigacao e sondas de kernel dentro
    # do servidor. Cada uma dessas e superficie de ataque acrescentada onde nao
    # ha funcao que a justifique.
    install_requires=[
        'cryptography',
        'pyyaml',
    ],

    extras_require={
        # Coleta no host inspecionado. O bcc NAO entra aqui de proposito: ele
        # vem do gerenciador de pacotes da distribuicao, porque depende de
        # bibliotecas nativas e dos cabecalhos do kernel em uso.
        'agent': [],
        # Recebe, guarda e apresenta. Nunca precisa de eBPF: o modo servidor
        # roda sem bcc instalado, e isso ja foi validado em campo.
        'server': ['flask'],
        # Conveniencia para uma unica maquina fazendo os dois papeis, como um
        # laboratorio ou uma instalacao pequena.
        'all': ['flask'],
    },

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Systems Administration",
    ],
    python_requires='>=3.6',
)
