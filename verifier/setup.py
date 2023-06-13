from distutils.core import setup, Extension

ravl = Extension(
    "ravl",
    sources=["pyravl.c"],
    libraries=["ravl", "crypto", "stdc++", "curl"],
)

setup(
    name="adns-verify",
    version="1.0",
    description="An aDNS verifier",
    ext_modules=[ravl],
    author="Christoph M. Wintersteiger",
    author_email="cwinter@microsoft.com",
    license="MIT",
)
