import os
import logging
import signal

import threading
from time import sleep
from unittest import skip

from mock import patch
from requests import ConnectionError
import unittest

from tests.utils.osinteraction import getInstance
from tests.utils.logger_service import set_log_level

# from openport.apps import OpenportApp
from tests.utils import osinteraction, dbhandler
from tests.test_utils import (
    set_default_args,
    wait_for_response,
    click_open_for_ip_link,
    check_tcp_port_forward,
)


@skip
class OpenportAppTests(unittest.TestCase):
    def setUp(self):
        print(self._testMethodName)
        self.os_interaction = getInstance()
        set_log_level(logging.DEBUG)
        self.app = OpenportApp()
        self.os_interaction = osinteraction.getInstance()
        self.test_db = os.path.join(
            os.path.dirname(__file__), "testfiles", "tmp", "db_test.db"
        )
        try:
            os.remove(self.test_db)
        except:
            pass
        self.stop_port_forward = False

    def tearDown(self):

        self.stop_port_forward = True

    def test_session_token_is_stored_if_port_request_is_denied(self):
        """Check that if a session_token is denied, the new session token is stored and used."""

        set_default_args(self.app, self.test_db)

        this_test = self
        this_test.raise_exception = False

        this_test.received_session = None
        this_test.received_server = None

        this_test.returning_token = "first token"
        this_test.received_token = None

        this_test.returning_server_port = 1111
        this_test.received_server_port = None

        def extra_function(session):
            pass

        def fake_start_port_forward(session, server=None):
            this_test.received_session = session
            this_test.received_server = server

            this_test.received_token = session.server_session_token
            session.server_session_token = this_test.returning_token

            this_test.received_server_port = session.server_port
            session.server_port = this_test.returning_server_port

            session.server = "testserver123.jdb"

            extra_function(session)
            session.notify_start()

            while not this_test.stop_port_forward:
                sleep(1)
                if this_test.raise_exception:
                    raise Exception("test exception")

        self.app.openport.start_port_forward = fake_start_port_forward

        # Start new session without a session_token

        self.app.args.local_port = 24
        thr = threading.Thread(target=self.app.start)
        thr.setDaemon(True)
        thr.start()

        wait_for_response(lambda: self.app.session and self.app.session.active)
        # sleep(60)
        self.assertEqual(this_test.received_server, "http://test.openport.be")

        self.assertEqual(self.app.session.server_port, 1111)
        self.assertEqual(this_test.received_server_port, -1)
        self.assertEqual(this_test.received_token, "")

        # Stopping the app will make the share inactive.
        # self.app.stop()
        self.stop_port_forward = True
        self.app.server.stop()

        sleep(3)

        self.assertFalse(thr.isAlive())

        # Restart session with the same token
        # Fake response where session_token is denied, returns new session_token

        this_test.returning_server_port = 2222
        this_test.returning_token = "second token"
        self.stop_port_forward = False

        self.app = OpenportApp()
        set_default_args(self.app, self.test_db)
        self.app.openport.start_port_forward = fake_start_port_forward

        self.app.args.local_port = 24
        thr = threading.Thread(target=self.app.start)
        thr.setDaemon(True)
        thr.start()

        wait_for_response(lambda: self.app.session and self.app.session.active)

        self.assertEqual("first token", this_test.received_token)
        self.assertEqual(1111, this_test.received_server_port)
        self.assertEqual(
            "second token", this_test.received_session.server_session_token
        )
        self.assertEqual(2222, this_test.received_session.server_port)

        # Stopping the app will make the share inactive.
        # self.app.stop()
        self.stop_port_forward = True
        self.app.server.stop()

        sleep(3)

        self.assertFalse(thr.isAlive())

        # Check that new session_token is used

        this_test.returning_server_port = 2222
        this_test.returning_token = "second token"
        self.stop_port_forward = False

        self.app = OpenportApp()
        set_default_args(self.app, self.test_db)
        self.app.openport.start_port_forward = fake_start_port_forward

        self.app.args.local_port = 24
        thr = threading.Thread(target=self.app.start)
        thr.setDaemon(True)
        thr.start()

        wait_for_response(lambda: self.app.session and self.app.session.active)

        self.assertEqual("second token", this_test.received_token)
        self.assertEqual(2222, this_test.received_server_port)
        self.assertEqual(
            "second token", this_test.received_session.server_session_token
        )
        self.assertEqual(2222, this_test.received_session.server_port)

        # Stopping the app will make the share inactive.
        # self.app.stop()
        self.stop_port_forward = True
        self.app.server.stop()

    def test_exit(self):
        set_default_args(self.app, self.test_db)

        port = self.os_interaction.get_open_port()
        print("localport :", port)
        self.app.args.local_port = port

        thr = threading.Thread(target=self.app.start)
        thr.setDaemon(True)
        thr.start()

        wait_for_response(lambda: self.app.session and self.app.session.active)

        # sleep(3)
        session = self.app.session
        click_open_for_ip_link(session.open_port_for_ip_link)

        check_tcp_port_forward(self, session.server, port, session.server_port)

        self.app.handleSigTERM(signal.SIGINT)

        self.assertFalse(self.app.session.active)
        self.assertFalse(self.app.openport.running())
        self.assertFalse(
            check_tcp_port_forward(
                self, session.server, port, session.server_port, fail_on_error=False
            )
        )

    @patch("requests.post", side_effect=ConnectionError)
    @patch("requests.get", side_effect=ConnectionError)
    def test_openport_app__offline(self, mock_post, mock_get):
        set_default_args(self.app, self.test_db)

        self.app.args.local_port = 24
        self.app.args.restart_on_reboot = True
        thr = threading.Thread(target=self.app.start)
        thr.setDaemon(True)
        thr.start()
        sleep(2)
        self.assertTrue(thr.is_alive)

        db_handler = dbhandler.DBHandler(self.test_db)
        self.assertEqual(1, len(db_handler.get_shares_to_restart()))
        self.assertEqual(1, len(db_handler.get_active_shares()))
        self.app.stop()
