__author__ = "jan"
import sys
import os
from unittest import skip

import xmlrunner
import unittest
from .integration_tests import IntegrationTest


# @skip
# class LiveIntegrationTest(IntegrationTest):
#     def setUp(self):
#         print(self._testMethodName)
#         IntegrationTest.setUp(self)
#         self.test_server = "https://openport.io"


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(LiveIntegrationTest)
    xmlrunner.XMLTestRunner(output="test-reports").run(suite)
