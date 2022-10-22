import os
import re
from codecs import open

from setuptools import setup, find_packages

HERE = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    with open(os.path.join(HERE, *parts), "r", encoding="utf-8") as f:
        return f.read()


with open(os.path.join(HERE, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

with open(os.path.join(HERE, "pyp0f", "__init__.py")) as f:
    match = re.search(r'VERSION = "(.+?)"', f.read())
    assert match
    VERSION = match.group(1)


setup(
    name="pyp0f",
    version=VERSION,
    description="p0f v3 written in Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Nisitay/scapy-p0f",
    author="Itay Margolin",
    author_email="itay62848@gmail.com",
    license="MIT",
    include_package_data=True,
    python_requires=">=3.7",
    packages=find_packages(
        include=[
            "pyp0f",
            "pyp0f.*"
        ]
    ),
    install_requires=[
        "scapy>=2.4.5",
        "h11>=0.11"
    ],
    extras_require={
        "dev": [
            "pytest>=6.1.0"
        ]
    },
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
