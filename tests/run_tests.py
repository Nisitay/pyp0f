import unittest

loader = unittest.TestLoader()
suite = loader.discover(start_dir="./")
runner = unittest.TextTestRunner()
runner.run(suite)
