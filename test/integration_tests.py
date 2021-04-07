# -*- coding: utf-8 -*-

import logging
import unittest

import radicale_auth_ldap
from test.configuration import TEST_CONFIGURATION, VALID_USER, VALID_PASS
from test.util import ConfigMock


class Authentication(unittest.TestCase):
    configuration = None

    @classmethod
    def setUpClass(cls):
        cls.configuration = ConfigMock(TEST_CONFIGURATION)

    def test_authentication_works(self):
        auth = radicale_auth_ldap.Auth(self.__class__.configuration)
        self.assertTrue(auth.login(VALID_USER, VALID_PASS))


if __name__ == '__main__':
    unittest.main()
