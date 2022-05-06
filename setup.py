import os
import re
from setuptools import setup, find_packages

HERE = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    with open(os.path.join(HERE, *parts), "r", encoding="utf-8") as f:
        return f.read()


def get_version():
    """
    Return version as listed in `__version__` in `__init__.py`.
    """
    init_py = read(os.path.join("pyp0f", "__init__.py"))
    match = re.search(r"__version__ = ['\"]([^'\"]*)['\"]", init_py)
    assert match
    return match.group(1)


setup(
    name="pyp0f",
    version=get_version(),
    description="p0f (v3) written in Python",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    url="https://github.com/Nisitay/pyp0f",
    keywords=["fingerprint", "p0f", "scapy", "network", "packets"],
    author="Itay Margolin",
    author_email="itay62848@gmail.com",
    license="MIT",
    packages=find_packages(include=("pyp0f", "pyp0f.*")),
    include_package_data=True,
    python_requires=">=3.7",
    install_requires=["scapy>=2.4.5"],
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Security",
        "Topic :: Internet",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Typing :: Typed"
    ],
)
