#!/usr/bin/env python
from distutils.core import setup

import socks

setup(
    name = "PySocks",
    version = socks.__version__,
    description = "A Python SOCKS client module. See https://github.com/Anorov/PySocks for more information.",
    url = "https://github.com/Anorov/PySocks",
    license = "BSD",
    author = "Anorov",
    author_email = "anorov.vorona@gmail.com",
    keywords = ["socks", "proxy"],
    py_modules=["socks", "sockshandler"]
)

