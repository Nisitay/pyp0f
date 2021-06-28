from setuptools import setup
import os
import io

workdir = os.path.abspath(os.path.dirname(__file__))

# https://packaging.python.org/single_source_version/
with open(os.path.join(workdir, "scapy_p0f", "__init__.py")) as fp:
    __version__ = fp.read().split('__version__ = "', 1)[1].split('"', 1)[0]


def get_long_description():
    """Extract description from README.md, for PyPI's usage"""
    try:
        fpath = os.path.join(os.path.dirname(__file__), "README.md")
        with io.open(fpath, encoding="utf-8") as f:
            readme = f.read()
            return readme
    except IOError:
        return None


setup(
    name="scapy-p0f",
    version=__version__,
    description="p0f v3 clone written in Python",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/Nisitay/scapy-p0f",
    download_url="https://github.com/Nisitay/scapy-p0f/tarball/master",
    author="Itay Margolin",
    author_email="itay62848@gmail.com",
    license="MIT",
    keywords=["p0f", "scapy", "network", "packets"],
    packages=["scapy_p0f"],
    package_data={"scapy_p0f": ["data/p0f.fp"]},
    include_package_data=True,
    install_requires=["scapy"],
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, <4",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Environment :: Console",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
)
