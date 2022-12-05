from __future__ import print_function

import logging
import os
import subprocess
import unittest
from time import sleep
from unittest import skip

import xmlrunner
from tests.utils.openport_api import request_open_port

from tests.utils.keyhandling import create_new_key_pair
from tests.utils.session import Session
from tests.utils import osinteraction
from tests.utils.logger_service import set_log_level, get_logger
from tests.utils.utils import run_method_with_timeout
from .test_utils import (
    SimpleHTTPClient,
    HTTPServerForTests,
    click_open_for_ip_link,
    check_tcp_port_forward,
    get_public_key,
)
from .test_utils import (
    start_openport_session,
    wait_for_response,
)

TOKEN = "tokentest"

logger = get_logger(__name__)


@skip
class IntegrationTest(unittest.TestCase):
    def setUp(self):
        print(self._testMethodName)
        set_log_level(logging.DEBUG)
        # self.test_server = 'http://test.openport.be'
        self.test_server = "https://test2.openport.io"
        self.osinteraction = osinteraction.getInstance()

    def tearDown(self):
        if hasattr(self, "app"):
            self.app.stop()

    def test_long_key(self):
        private_key_file = os.path.join(
            os.path.dirname(__file__), "testfiles", "tmp", "id_rsa_tmp"
        )
        public_key_file = os.path.join(
            os.path.dirname(__file__), "testfiles", "tmp", "id_rsa_tmp.pub"
        )

        logger.debug("getting key pair")
        private_key, public_key = create_new_key_pair(4096)
        with open(private_key_file, "w") as f:
            f.write(private_key)
        with open(public_key_file, "w") as f:
            f.write(public_key)

        port_out = self.osinteraction.get_open_port()
        out_session = Session()
        out_session.local_port = port_out
        out_session.server_session_token = None
        out_session.public_key_file = public_key_file
        out_session.private_key_file = private_key_file

        out_app = None
        try:
            out_app = start_openport_session(self, out_session)
            remote_host, remote_port, link = (
                out_session.server,
                out_session.server_port,
                out_session.open_port_for_ip_link,
            )
            click_open_for_ip_link(link)
            print(remote_port)
            sleep(10)
            # sleep(1000)
            check_tcp_port_forward(
                self,
                remote_host=remote_host,
                local_port=port_out,
                remote_port=remote_port,
            )
        finally:
            if out_app:
                out_app.stop()

    def start_http_server(self, port, response):
        s = HTTPServerForTests(port)
        s.set_response(response)
        s.run_threaded()
        return s

    def test_brute_force_blocked(self):
        port = self.osinteraction.get_open_port()
        expected_response = "cha cha cha"

        server1 = self.start_http_server(port, expected_response)

        session = Session()
        session.local_port = port
        session.server_session_token = None
        # session.http_forward = True

        self.app = start_openport_session(self, session)

        click_open_for_ip_link(session.open_port_for_ip_link)

        link = session.get_link()
        print("link: %s" % link)
        self.assertTrue(session.server_port > 1000)

        c = SimpleHTTPClient()
        actual_response = c.get("http://localhost:%s" % port)
        self.assertEqual(actual_response, expected_response.strip())
        i = -1
        try:
            for i in range(20):
                print("connection %s" % i)
                actual_response = c.get("http://%s" % link)
                self.assertEqual(actual_response, expected_response.strip())
        except (urllib2.HTTPError, urllib2.URLError) as e:
            print(e)
        self.assertTrue(5 < i < 20, "i should be around 10 but was %s" % i)

        # check download on different port is still ok
        port2 = self.osinteraction.get_open_port()

        session2 = Session()
        session2.local_port = port2
        session2.server_session_token = None

        server2 = self.start_http_server(port2, expected_response)

        openport2 = start_openport_session(self, session2)
        sleep(3)
        print("http://%s" % session2.get_link())

        click_open_for_ip_link(session2.open_port_for_ip_link)
        actual_response = c.get("http://%s" % session2.get_link())
        self.assertEqual(actual_response, expected_response.strip())

        server1.stop()
        server2.stop()
        openport2.stop_port_forward()

    def test_brute_force_blocked__not_for_http_forward(self):
        port = self.osinteraction.get_open_port()

        response = "cha cha cha"

        s = self.start_http_server(port, response)

        session = Session()
        session.local_port = port
        session.server_port = 80
        session.server_session_token = None
        session.http_forward = True

        self.app = start_openport_session(self, session)
        click_open_for_ip_link(session.open_port_for_ip_link)

        link = session.http_forward_address
        print("link: %s" % link)

        c = SimpleHTTPClient()
        actual_response = c.get("http://localhost:%s" % port)
        self.assertEqual(actual_response, response.strip())
        i = -1
        try:
            for i in range(20):
                print("connection %s" % i)
                actual_response = c.get("http://%s" % link)
                self.assertEqual(actual_response, response.strip())
        except (urllib2.HTTPError, urllib2.URLError) as e:
            self.fail("url error on connection nr %s" % i)

    def test_rogue_ssh_sessions(self):
        port = self.osinteraction.get_open_port()
        port2 = self.osinteraction.get_open_port()

        self.assertNotEqual(port, port2)
        request_open_port(
            port,
            server=self.test_server,
            public_key=get_public_key(),
        )
        command = [
            "/usr/bin/ssh",
            "open@%s" % self.test_server.split("//")[1],
            "-R",
            "%s:localhost:%s" % (port2, port2),
            "wrong_session_token",
        ]
        print(command)
        p = subprocess.Popen(
            command,
            bufsize=2048,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        failed = wait_for_response(
            lambda: p.poll() is not None, timeout=10, throw=False
        )
        sleep(3)
        output = self.osinteraction.non_block_read(p)
        print(output)
        self.assertTrue("remote port forwarding failed for listen port" in output[1])
        self.assertFalse(failed)

    def test_rogue_ssh_session__correct(self):
        port = self.osinteraction.get_open_port()

        response = request_open_port(
            port,
            server=self.test_server,
            public_key=get_public_key(),
        )
        command = [
            "/usr/bin/ssh",
            "open@%s" % self.test_server.split("//")[1],
            "-R",
            "%s:localhost:%s" % (response.remote_port, port),
            response.session_token,
        ]
        print(command)
        p = subprocess.Popen(
            command,
            bufsize=2048,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        run_method_with_timeout(
            lambda: wait_for_response(
                lambda: p.poll() is not None, timeout=10, throw=False
            ),
            10,
            raise_exception=False,
        )
        if p.returncode:
            print(p.communicate())
        self.assertEqual(p.returncode, None)

    def test_rogue_ssh_session__correct__old_version(self):
        port = self.osinteraction.get_open_port()

        response = request_open_port(
            port,
            server=self.test_server,
            client_version="0.9.3",
            public_key=get_public_key(),
        )
        command = [
            "/usr/bin/ssh",
            "open@%s" % self.test_server.split("//")[1],
            "-R",
            "%s:localhost:%s" % (response.remote_port, port),
        ]  # No response.session_token!
        print(command)
        p = subprocess.Popen(
            command,
            bufsize=2048,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        run_method_with_timeout(
            lambda: wait_for_response(
                lambda: p.poll() is not None, timeout=10, throw=False
            ),
            10,
            raise_exception=False,
        )
        if p.returncode is not None:
            print(p.communicate())
        self.assertEqual(p.returncode, None)


if __name__ == "__main__":
    unittest.main(testRunner=xmlrunner.XMLTestRunner(output="test-reports"))
