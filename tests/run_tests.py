import unittest

from scapy_p0f import p0fdb

p0fdb.reload("./scapy_p0f/data/p0f.fp")
loader = unittest.TestLoader()
suite = loader.discover(start_dir="./")
runner = unittest.TextTestRunner()
runner.run(suite)
