import json
import logging
import os
import shutil
import signal
import subprocess
import unittest
from pathlib import Path
from typing import Optional
from unittest import skip

import requests
from threading import Thread
from time import sleep

from toxiproxy.api import APIConsumer

from tests.utils.app_tcp_server import send_exit, is_running
from tests.utils import osinteraction, dbhandler
from tests.utils.logger_service import get_logger, set_log_level
from tests.utils.utils import run_method_with_timeout
from tests.utils.utils import (
    SimpleTcpServer,
    SimpleTcpClient,
    lineNumber,
    SimpleHTTPClient,
    HTTPServerForTests,
    get_ip,
    TEST_FILES_PATH,
    print_shares_in_db,
    application_is_alive,
)
from tests.utils.utils import get_nr_of_shares_in_db_file
from tests.utils.utils import (
    print_all_output,
    click_open_for_ip_link,
    check_tcp_port_forward,
)
from tests.utils.utils import (
    run_command_with_timeout,
    get_remote_host_and_port,
    kill_all_processes,
    wait_for_response,
)

logger = get_logger(__name__)

# TEST_SERVER = 'https://eu.openport.io'
# TEST_SERVER = "https://openport.io"
# TEST_SERVER = 'https://test2.openport.io'
# TEST_SERVER = 'https://test2.openport.xyz'
# TEST_SERVER = 'https://test.openport.xyz'
TEST_SERVER = "https://test.openport.io"
# TEST_SERVER = 'http://127.0.0.1:8000'
# TEST_SERVER = 'https://us.openport.io'
# TEST_SERVER = 'http://192.168.64.2.xip.io'

TEST_SERVERS = ["test.openport.io", "test2.openport.io"]

KEY_REGISTRATION_TOKEN = os.environ.get("KEY_REGISTRATION_TOKEN")


if not osinteraction.is_windows():
    PYTHON_EXE = subprocess.getoutput("which python")
    KILL_SIGNAL = signal.SIGKILL
else:
    PYTHON_EXE = "env\\Scripts\\python.exe"
    KILL_SIGNAL = signal.SIGTERM

openport_go_dir = Path(__file__).parents[2]

TOXI_PROXY_HOST = os.environ.get("TOXI_PROXY_HOST", "127.0.0.1")


class AppTests(unittest.TestCase):
    openport_exe = [
        os.environ.get("OPENPORT_EXE", str(openport_go_dir / "src" / "openport"))
    ]
    # openport_exe = [str(openport_go_dir / 'openport')]
    restart_shares = "restart-sessions"
    kill = "kill"
    kill_all = "kill-all"
    version = "version"
    app_version = "2.2.3-beta"
    forward = "forward"
    list = "list"
    ws_options = []

    @classmethod
    def setUpClass(cls):
        if os.environ.get("BUILD_OPENPORT_EXE", "1") == "1":
            print("building openport executable")
            exit_code, output = subprocess.getstatusoutput(
                str(openport_go_dir / "compile.sh")
            )
            print(output)
            assert exit_code == 0, exit_code

        if KEY_REGISTRATION_TOKEN:
            p = subprocess.Popen(
                cls.openport_exe
                + [
                    "register-key",
                    KEY_REGISTRATION_TOKEN,
                    "--server",
                    TEST_SERVER,
                    "--verbose",
                ],
                stderr=subprocess.STDOUT,
            )
            osinteraction.getInstance().print_output_continuously_threaded(p)
            run_method_with_timeout(p.wait, 10)
            if p.returncode != 0:
                raise Exception("Could not register key")
            else:
                print("Key registered")
        else:
            print("No key registration token set")

    def setUp(self):
        logging.getLogger("sqlalchemy").setLevel(logging.WARN)
        print(self._testMethodName)
        set_log_level(logging.DEBUG)
        self.processes_to_kill = []
        self.osinteraction = osinteraction.getInstance()
        self.manager_port = -1
        #        self.assertFalse(openportmanager.manager_is_running(8001))
        self.db_file = (
            TEST_FILES_PATH / "tmp" / f"tmp_openport_{self._testMethodName}.db"
        )
        if os.path.exists(self.db_file):
            try:
                os.remove(self.db_file)
            except:
                sleep(3)
                os.remove(self.db_file)
        os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        self.db_handler = dbhandler.DBHandler(self.db_file)

    def tearDown(self):
        logger.debug("teardown!")
        if self.manager_port > 0:
            logger.debug("killing manager")
            self.kill_manager(self.manager_port)

        if self.db_file.exists():
            for session in self.db_handler.get_all_shares():
                send_exit(session)
        kill_all_processes(self.processes_to_kill)
        logger.debug("end of teardown!")

    def start_openport_process_advanced(self, *args):
        args = [str(x) for x in args]
        print(f'Running {" ".join(self.openport_exe + args)}')
        p = subprocess.Popen(
            self.openport_exe + args, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        self.processes_to_kill.append(p)
        return p

    DB_PER_TEST = "db_per_test"

    def start_openport_process(
        self,
        *args,
        server: Optional[str] = TEST_SERVER,
        verbose=True,
        database=DB_PER_TEST,
        ws_options=True,
    ):
        if database == self.DB_PER_TEST:
            database = self.db_file

        args = (
            list(args)
            + (["--server", server] if server else [])
            + (["--verbose"] if verbose else [])
            + (["--database", database] if database else [])
            + (self.ws_options if ws_options else [])
        )

        return self.start_openport_process_advanced(*args)

    def test_aaa_openport_app(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process("--local-port", str(port))
        remote_host, remote_port, link = get_remote_host_and_port(
            p, self.osinteraction, timeout=30
        )
        self.check_application_is_still_alive(p)
        click_open_for_ip_link(link)
        #        self.assertEqual(1, get_nr_of_shares_in_db_file(self.db_file))
        check_tcp_port_forward(
            self, remote_host=remote_host, local_port=port, remote_port=remote_port
        )

    def test_same_port_after_sigkill(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process("--local-port", str(port))
        remote_host, remote_port, link = get_remote_host_and_port(
            p, self.osinteraction, timeout=30
        )

        self.check_application_is_still_alive(p)
        click_open_for_ip_link(link)
        #        self.assertEqual(1, get_nr_of_shares_in_db_file(self.db_file))
        #        self.assertFalse(openportmanager.manager_is_running(8001))
        check_tcp_port_forward(
            self, remote_host=remote_host, local_port=port, remote_port=remote_port
        )

        # kill the app
        os.kill(p.pid, KILL_SIGNAL)
        run_method_with_timeout(p.wait, 10)
        self.assertFalse(application_is_alive(p))

        # start a new app with the same port
        p = self.start_openport_process(port)
        remote_host2, remote_port2, link2 = get_remote_host_and_port(
            p, self.osinteraction, timeout=30
        )
        self.assertEqual(remote_host, remote_host2)
        self.assertEqual(remote_port, remote_port2)
        self.assertEqual(link, link2)
        self.check_application_is_still_alive(p)
        click_open_for_ip_link(link)
        check_tcp_port_forward(
            self, remote_host=remote_host, local_port=port, remote_port=remote_port
        )

    def test_openport_app__alt_domain(self):
        test_server = TEST_SERVER.replace(".io", ".xyz")
        port = self.osinteraction.get_open_port()

        p = self.start_openport_process("--local-port", str(port), server=test_server)

        remote_host, remote_port, link = get_remote_host_and_port(
            p, self.osinteraction, timeout=30
        )
        self.assertIn(".xyz", remote_host)
        self.assertIn(".xyz", link)
        self.check_application_is_still_alive(p)
        click_open_for_ip_link(link)
        check_tcp_port_forward(
            self, remote_host=remote_host, local_port=port, remote_port=remote_port
        )

    @skip("")
    def test_heavy_load(self):
        local_ports = []
        threads = []

        def click_link(p):
            remote_host, remote_port, link = get_remote_host_and_port(
                p, self.osinteraction, timeout=60
            )
            self.check_application_is_still_alive(p)
            click_open_for_ip_link(link)

        for i in range(200):
            port = self.osinteraction.get_open_port()
            local_ports.append(port)
            p = self.start_openport_process("--local-port", str(port))

            t = Thread(target=click_link, args=(p,))
            t.daemon = True
            t.start()
            threads.append(t)
        for t in threads:
            t.join(30)

        for local_port in local_ports:
            share = self.db_handler.get_share_by_local_port(local_port)
            check_tcp_port_forward(
                self,
                remote_host=share.server,
                local_port=local_port,
                remote_port=share.server_port,
            )

    def test_openport_app__daemonize(self):
        if osinteraction.is_mac():
            # does not work on mac-os
            return
        port = self.osinteraction.get_open_port()

        p = self.start_openport_process("--local-port", str(port), "--daemonize")
        # self.osinteraction.print_output_continuously(p, '****')
        run_method_with_timeout(p.wait, 3)
        output = self.osinteraction.non_block_read(p)
        for i in output:
            print(i)
        self.assertTrue(output[1] == False or "Traceback" not in output[1])
        wait_for_response(
            lambda: get_nr_of_shares_in_db_file(self.db_file) == 1, timeout=10
        )
        self.assertEqual(1, get_nr_of_shares_in_db_file(self.db_file))
        share = self.db_handler.get_share_by_local_port(port, filter_active=False)
        click_open_for_ip_link(share.open_port_for_ip_link)
        check_tcp_port_forward(
            self,
            remote_host=share.open_port_for_ip_link.split("://")[-1].split("/")[0],
            local_port=port,
            remote_port=share.server_port,
        )

    def test_openport_app__no_arguments(self):
        p = subprocess.Popen(
            self.openport_exe, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        self.processes_to_kill.append(p)
        run_method_with_timeout(p.wait, 10)
        output = self.osinteraction.get_all_output(p)
        print(output)
        all_output = "".join([str(x) for x in output])
        self.assertTrue("usage: " in all_output.lower(), all_output)

    def test_openport_app__live_site(self):
        port = self.osinteraction.get_open_port()

        p = self.start_openport_process(port, server="")
        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        self.check_application_is_still_alive(p)
        click_open_for_ip_link(link)

        self.assertEqual(1, get_nr_of_shares_in_db_file(self.db_file))
        sleep(1)
        check_tcp_port_forward(
            self, remote_host=remote_host, local_port=port, remote_port=remote_port
        )

    def test_save_share(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process("--local-port", str(port))

        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        share = self.db_handler.get_share_by_local_port(port, filter_active=False)

        self.assertEqual(1, share.id)
        self.assertEqual(TEST_SERVER, share.server)
        self.assertEqual(remote_port, share.server_port)
        self.assertEqual(p.pid, share.pid)
        self.assertTrue(share.active)
        self.assertNotEqual(None, share.account_id)
        self.assertNotEqual(None, share.key_id)
        self.assertEqual(port, share.local_port)
        self.assertNotEqual(None, share.server_session_token)
        self.assertEqual([], share.restart_command)
        self.assertFalse(share.http_forward)
        self.assertEqual("", share.http_forward_address)
        self.assertTrue(share.app_management_port > 1024)
        self.assertEqual(link, share.open_port_for_ip_link)
        self.assertFalse(share.forward_tunnel)

    def test_save_share__restart_on_reboot(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process(
            port,
            "--restart-on-reboot",
            "--ip-link-protection",
            "False",
            "--keep-alive",
            "5",
        )
        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)

        share = self.db_handler.get_share_by_local_port(port, filter_active=False)

        self.assertTrue(share.active)
        self.assertEqual(
            [
                x.encode("utf-8")
                for x in [
                    "%s" % port,
                    "--restart-on-reboot",
                    "--ip-link-protection",
                    "False",
                    "--keep-alive",
                    "5",
                    "--server",
                    TEST_SERVER,
                    "--verbose",
                    "--database",
                    str(self.db_file),
                ]
                + self.ws_options
            ],
            share.restart_command,
        )

    def test_save_share__restart_on_reboot__proxy(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process(
            port, "--restart-on-reboot", "--proxy", "socks5://jan:db@1.2.3.4:5555"
        )
        sleep(2)

        output = self.osinteraction.non_block_read(p)
        for i in output:
            print(i)
        share = self.db_handler.get_share_by_local_port(port, filter_active=False)
        self.assertEqual(
            [
                x.encode("utf-8")
                for x in [
                    "%s" % port,
                    "--restart-on-reboot",
                    "--proxy",
                    "socks5://jan:db@1.2.3.4:5555",
                    "--server",
                    TEST_SERVER,
                    "--verbose",
                    "--database",
                    str(self.db_file),
                ]
                + self.ws_options
            ],
            share.restart_command,
        )

    def test_save_share__restart_on_reboot__simple(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process(port, "--restart-on-reboot", verbose=False)
        get_remote_host_and_port(p, self.osinteraction)
        share = self.db_handler.get_share_by_local_port(port, filter_active=False)
        self.assertTrue(share.active)
        self.assertEqual(
            [
                str(x).encode("utf-8")
                for x in [
                    "%s" % port,
                    "--restart-on-reboot",
                    "--server",
                    TEST_SERVER,
                    "--database",
                    str(self.db_file),
                ]
                + self.ws_options
            ],
            share.restart_command,
        )

    def test_openport_app__forward_tunnel(self):
        if self.ws_options:
            self.skipTest("not supported with websockets")

        port_out = self.osinteraction.get_open_port()
        p_out = self.start_openport_process("--local-port", port_out)

        remote_host, remote_port, link = get_remote_host_and_port(
            p_out, self.osinteraction
        )
        self.osinteraction.print_output_continuously_threaded(p_out, "p_out")
        # click_open_for_ip_link(link)
        # check_tcp_port_forward(self, remote_host=remote_host, local_port=port_out, remote_port=remote_port)

        port_in = self.osinteraction.get_open_port()
        logger.info("port_in: %s" % port_in)
        p_in = self.start_openport_process(
            self.forward, "--local-port", port_in, "--remote-port", remote_port
        )

        self.processes_to_kill.append(p_in)
        self.check_application_is_still_alive(p_in)
        self.check_application_is_still_alive(p_out)
        get_remote_host_and_port(p_in, self.osinteraction, forward_tunnel=True)
        #     sleep(20)
        check_tcp_port_forward(
            self, remote_host="127.0.0.1", local_port=port_out, remote_port=port_in
        )
        self.assertEqual(2, get_nr_of_shares_in_db_file(self.db_file))

    def test_double_forward_tunnel_to_same_port(self):
        if self.ws_options:
            self.skipTest("not supported with websockets")

        port_out = self.osinteraction.get_open_port()
        p_out = self.start_openport_process(port_out)

        remote_host, remote_port, link = get_remote_host_and_port(
            p_out, self.osinteraction
        )
        self.osinteraction.print_output_continuously_threaded(p_out, "p_out")

        port_in_1 = self.osinteraction.get_open_port()
        logger.info("port_in_1: %s" % port_in_1)
        p_in = self.start_openport_process(
            self.forward, "--local-port", port_in_1, "--remote-port", remote_port
        )

        self.processes_to_kill.append(p_in)
        self.check_application_is_still_alive(p_in)
        self.check_application_is_still_alive(p_out)
        get_remote_host_and_port(p_in, self.osinteraction, forward_tunnel=True)
        check_tcp_port_forward(
            self, remote_host="127.0.0.1", local_port=port_out, remote_port=port_in_1
        )

        port_in_2 = self.osinteraction.get_open_port()
        logger.info("port_in_2: %s" % port_in_2)
        p_in = self.start_openport_process(
            self.forward, "--local-port", port_in_2, "--remote-port", remote_port
        )

        self.processes_to_kill.append(p_in)
        self.check_application_is_still_alive(p_in)
        self.check_application_is_still_alive(p_out)
        get_remote_host_and_port(p_in, self.osinteraction, forward_tunnel=True)
        check_tcp_port_forward(
            self, remote_host="127.0.0.1", local_port=port_out, remote_port=port_in_2
        )
        # check the old one again
        check_tcp_port_forward(
            self, remote_host="127.0.0.1", local_port=port_out, remote_port=port_in_1
        )

    def test_openport_app__forward_tunnel__killing_forward_does_not_kill_reverse_tunnel(
        self,
    ):
        if self.ws_options:
            self.skipTest("not supported with websockets")

        port_out = self.osinteraction.get_open_port()
        p_out = self.start_openport_process(port_out)

        remote_host, remote_port, link = get_remote_host_and_port(
            p_out, self.osinteraction
        )
        self.osinteraction.print_output_continuously_threaded(p_out, "p_out")

        port_in = self.osinteraction.get_open_port()
        logger.info("port_in: %s" % port_in)
        p_in = self.start_openport_process(
            self.forward, "--local-port", port_in, "--remote-port", remote_port
        )

        self.processes_to_kill.append(p_in)
        self.check_application_is_still_alive(p_in)
        self.check_application_is_still_alive(p_out)
        get_remote_host_and_port(p_in, self.osinteraction, forward_tunnel=True)
        #     sleep(20)
        check_tcp_port_forward(
            self, remote_host="127.0.0.1", local_port=port_out, remote_port=port_in
        )
        p_in.kill()
        p_in.wait()
        self.assertFalse(application_is_alive(p_in))
        self.check_application_is_still_alive(p_out)
        # If this fails, the reverse tunnel is killed when the forward tunnel is killed
        click_open_for_ip_link(link)

    def test_openport_app__forward_tunnel__host_port(self):
        if self.ws_options:
            self.skipTest("not supported with websockets")
        port_out = self.osinteraction.get_open_port()
        other_servers = [s for s in TEST_SERVERS if s not in TEST_SERVER]

        p_out = self.start_openport_process(
            "--local-port", port_out, "--request-server", other_servers[0]
        )
        remote_host, remote_port, link = get_remote_host_and_port(
            p_out, self.osinteraction
        )
        self.osinteraction.print_output_continuously_threaded(p_out, "p_out")
        # click_open_for_ip_link(link)
        # check_tcp_port_forward(self, remote_host=remote_host, local_port=port_out, remote_port=remote_port)

        port_in = self.osinteraction.get_open_port()
        logger.info("port_in: %s" % port_in)

        p_in = self.start_openport_process(
            self.forward,
            "--local-port",
            port_in,
            "--remote-port",
            f"{remote_host}:{remote_port}",
        )
        self.check_application_is_still_alive(p_in)
        self.check_application_is_still_alive(p_out)
        get_remote_host_and_port(p_in, self.osinteraction, forward_tunnel=True)
        check_tcp_port_forward(
            self, remote_host="127.0.0.1", local_port=port_out, remote_port=port_in
        )
        self.assertEqual(2, get_nr_of_shares_in_db_file(self.db_file))

    def test_openport_app__forward_tunnel__no_local_port_passed(self):
        if self.ws_options:
            self.skipTest("not supported with websockets")
        port_out = self.osinteraction.get_open_port()
        p_out = self.start_openport_process("--local-port", port_out)

        remote_host, remote_port, link = get_remote_host_and_port(
            p_out, self.osinteraction
        )
        self.osinteraction.print_output_continuously_threaded(p_out, "p_out")

        p_in = self.start_openport_process(self.forward, "--remote-port", remote_port)
        self.check_application_is_still_alive(p_in)
        self.check_application_is_still_alive(p_out)
        # self.osinteraction.print_output_continuously_threaded(p_in, 'p_in')
        host, port_in, link = get_remote_host_and_port(
            p_in, self.osinteraction, forward_tunnel=True
        )
        check_tcp_port_forward(
            self, remote_host="127.0.0.1", local_port=port_out, remote_port=port_in
        )
        self.assertEqual(2, get_nr_of_shares_in_db_file(self.db_file))

    def test_openport_app__forward_tunnel__restart_on_reboot(self):
        if self.ws_options:
            self.skipTest("not supported with websockets")
        serving_port = self.osinteraction.get_open_port()
        p_reverse_tunnel = self.start_openport_process("--local-port", serving_port)
        logger.debug("p_reverse_tunnel.pid: %s" % p_reverse_tunnel.pid)

        remote_host, remote_port, link = get_remote_host_and_port(
            p_reverse_tunnel, self.osinteraction
        )
        # click_open_for_ip_link(link)
        self.osinteraction.print_output_continuously_threaded(
            p_reverse_tunnel, "p_reverse_tunnel"
        )

        forward_port = self.osinteraction.get_open_port()

        p_forward_tunnel = self.start_openport_process(
            self.forward,
            "--local-port",
            str(forward_port),
            "--remote-port",
            str(remote_port),
            "--restart-on-reboot",
        )
        logger.debug("p_forward_tunnel.pid: %s" % p_forward_tunnel.pid)

        self.check_application_is_still_alive(p_forward_tunnel)
        self.check_application_is_still_alive(p_reverse_tunnel)
        # self.osinteraction.print_output_continuously_threaded(p_forward_tunnel, 'p_forward_tunnel')
        host, forwarding_port, link = get_remote_host_and_port(
            p_forward_tunnel, self.osinteraction, forward_tunnel=True
        )
        self.assertEqual(forward_port, forwarding_port)
        sleep(2)
        forward_session = self.db_handler.get_share_by_local_port(
            forwarding_port, filter_active=False
        )
        forward_app_management_port = forward_session.app_management_port
        check_tcp_port_forward(
            self,
            remote_host="127.0.0.1",
            local_port=serving_port,
            remote_port=forwarding_port,
        )
        print_shares_in_db(self.db_file)
        self.assertEqual(2, get_nr_of_shares_in_db_file(self.db_file))
        #
        p_forward_tunnel.terminate()  # on shutdown, ubuntu sends a sigterm
        logger.debug("p_forward_tunnel wait")
        run_method_with_timeout(p_forward_tunnel.wait, 4)
        self.assertFalse(
            check_tcp_port_forward(
                self,
                remote_host="127.0.0.1",
                local_port=serving_port,
                remote_port=forwarding_port,
                fail_on_error=False,
            )
        )

        self.assertEqual(1, len(self.db_handler.get_shares_to_restart()))

        p_restart = subprocess.Popen(
            self.openport_exe
            + [self.restart_shares, "--verbose", "--database", self.db_file],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self.processes_to_kill.append(p_restart)
        self.osinteraction.print_output_continuously_threaded(p_restart, "p_restart")

        logger.debug("p_restart.pid: %s" % p_restart.pid)
        logger.debug("p_restart.wait")
        run_method_with_timeout(p_restart.wait, 2)
        # p_restart.wait()
        logger.debug("p_restart.wait done")

        self.check_application_is_still_alive(p_reverse_tunnel)
        logger.debug("alive!")

        # check_tcp_port_forward(self, remote_host=remote_host, local_port=serving_port, remote_port=remote_port)

        def foo():
            in_session2 = self.db_handler.get_share_by_local_port(
                forwarding_port, filter_active=False
            )
            if in_session2 is None:
                print("forwarding session not found")
                return False

            print("forwarding session found")
            in_app_management_port2 = in_session2.app_management_port
            # wait for the session to be renewed
            if forward_app_management_port == in_app_management_port2:
                print("still same session")
                return False
            if not in_session2.active:
                print("session not active")
                return False

            return run_method_with_timeout(is_running, args=[in_session2], timeout_s=5)

        logger.debug("sleeping now")
        wait_for_response(foo, timeout=10)
        logger.debug("wait_for_response done")
        sleep(3)
        check_tcp_port_forward(
            self,
            remote_host="127.0.0.1",
            local_port=serving_port,
            remote_port=forwarding_port,
        )

    def test_openport_app__do_not_restart(self):
        port = self.osinteraction.get_open_port()
        s = SimpleTcpServer(port)
        s.run_threaded()

        p = self.start_openport_process("--local-port", port)
        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        self.check_application_is_still_alive(p)
        click_open_for_ip_link(link)

        self.assertEqual(1, get_nr_of_shares_in_db_file(self.db_file))
        #        self.assertFalse(openportmanager.manager_is_running(8001))

        c = SimpleTcpClient(remote_host, remote_port)
        request = "hello"
        response = c.send(request)
        self.assertEqual(request, response.strip())

        os.kill(p.pid, KILL_SIGNAL)
        run_method_with_timeout(p.wait, 10)

        manager_port = self.osinteraction.get_open_port()
        p_manager2 = subprocess.Popen(
            self.openport_exe
            + [
                self.restart_shares,
                "--database",
                self.db_file,
                "--verbose",
                "--manager-port",  # legacy, no longer used
                str(manager_port),
            ],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self.processes_to_kill.append(p_manager2)
        run_method_with_timeout(
            application_is_alive,
            args=[p_manager2],
            timeout_s=10,
            raise_exception=False,
        )
        print_all_output(p_manager2, self.osinteraction, "p_manager2")
        self.assertFalse(application_is_alive(p_manager2))
        try:
            response = c.send(request)
        except:
            response = ""
        self.assertNotEqual(request, response.strip())
        c.close()
        s.close()

    def test_openport_app_get_same_port(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process("--local-port", port)

        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        self.check_application_is_still_alive(p)
        click_open_for_ip_link(link)
        check_tcp_port_forward(self, remote_host, port, remote_port)

        share = self.db_handler.get_share_by_local_port(port)
        send_exit(share)
        run_method_with_timeout(p.wait, 10)

        p = self.start_openport_process(port)
        new_remote_host, new_remote_port, link = get_remote_host_and_port(
            p, self.osinteraction
        )
        self.check_application_is_still_alive(p)

        self.assertEqual(remote_port, new_remote_port)
        click_open_for_ip_link(link)

        check_tcp_port_forward(self, new_remote_host, port, new_remote_port)

    def test_openport_app_get_same_port__old_db_format(self):
        port = self.osinteraction.get_open_port()

        db_file_name = "openport-2.1.0-old-format.db"
        old_db = TEST_FILES_PATH / db_file_name
        old_db_tmp = TEST_FILES_PATH / "tmp" / db_file_name
        shutil.copy(old_db, old_db_tmp)
        self.db_handler = dbhandler.DBHandler(old_db_tmp)
        p = self.start_openport_process(port, database=old_db_tmp)

        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        self.check_application_is_still_alive(p)
        click_open_for_ip_link(link)
        check_tcp_port_forward(self, remote_host, port, remote_port)

        share = self.db_handler.get_share_by_local_port(port)
        send_exit(share)
        run_method_with_timeout(p.wait, 10)
        p = self.start_openport_process(
            "%s" % port,
            database=old_db_tmp,
        )

        new_remote_host, new_remote_port, link = get_remote_host_and_port(
            p, self.osinteraction
        )
        self.check_application_is_still_alive(p)

        self.assertEqual(remote_port, new_remote_port)
        click_open_for_ip_link(link)

        check_tcp_port_forward(self, new_remote_host, port, new_remote_port)

    def test_openport_app_get_same_port__after_sigint(self):
        # TEST_SERVER = "https://openport.io"
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process(port)

        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        self.check_application_is_still_alive(p)
        click_open_for_ip_link(link)
        check_tcp_port_forward(self, remote_host, port, remote_port)

        p.send_signal(signal.SIGINT)
        run_method_with_timeout(p.wait, 10)

        p = self.start_openport_process(port)

        new_remote_host, new_remote_port, link = get_remote_host_and_port(
            p, self.osinteraction
        )
        self.check_application_is_still_alive(p)

        self.assertEqual(remote_port, new_remote_port)
        click_open_for_ip_link(link)

        check_tcp_port_forward(self, new_remote_host, port, new_remote_port)

    def test_openport_app__http_forward(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process(port, "--http-forward")

        remote_host, remote_port, link = get_remote_host_and_port(
            p, self.osinteraction, output_prefix="app", http_forward=True
        )

        self.check_http_port_forward(remote_host=remote_host, local_port=port)

    def test_openport_app__http_forward__alt_domain(self):
        port = self.osinteraction.get_open_port()
        test_server = TEST_SERVER.replace(".io", ".xyz")

        p = self.start_openport_process(port, "--http-forward", server=test_server)

        remote_host, remote_port, link = get_remote_host_and_port(
            p, self.osinteraction, output_prefix="app", http_forward=True
        )
        self.assertIn(".xyz", remote_host)
        self.assertIn(".xyz", link)

        self.check_http_port_forward(remote_host=remote_host, local_port=port)

    def test_openport_app__regular_then_http_forward(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process(port)

        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        self.check_application_is_still_alive(p)
        click_open_for_ip_link(link)

        self.assertEqual(1, get_nr_of_shares_in_db_file(self.db_file))

        #        self.assertFalse(openportmanager.manager_is_running(8001))

        return_server = []
        check_tcp_port_forward(
            self,
            remote_host=remote_host,
            local_port=port,
            remote_port=remote_port,
            return_server=return_server,
        )
        p.kill()
        for s in return_server:
            s.close()
            print("closed server")
        p.wait()

        c = SimpleTcpClient("localhost", port)

        def server_is_not_active():
            print("checking server_is_not_active")
            try:
                response = c.send("pong").strip()
            except Exception as e:
                logger.info("this is expected")
                return True
            print(response)
            return response != "pong"

        wait_for_response(server_is_not_active, timeout=30)
        #        sleep(3)
        p = self.start_openport_process(
            "--local-port",
            port,
            "--http-forward",
        )

        remote_host, remote_port, link = get_remote_host_and_port(
            p, self.osinteraction, output_prefix="app", http_forward=True
        )

        self.check_http_port_forward(remote_host=remote_host, local_port=port)

    def check_application_is_still_alive(self, p):
        if not application_is_alive(p):  # process terminated
            print("application terminated: ", self.osinteraction.get_output(p))
            self.fail("p_app.poll() should be None but was %s" % p.poll())

    def test_exit(self):
        port = self.osinteraction.get_open_port()
        print("localport :", port)
        p_app = self.start_openport_process(
            "%s" % port,
        )

        remote_host, remote_port, link = get_remote_host_and_port(
            p_app, self.osinteraction, output_prefix="app"
        )

        share = self.db_handler.get_share_by_local_port(port)
        send_exit(share, force=True)

        run_method_with_timeout(p_app.wait, 10)
        self.assertTrue(p_app.poll() is not None)

    def test_restart_shares(self):
        port = self.osinteraction.get_open_port()
        print("localport :", port)
        p_app = self.start_openport_process(
            "%s" % port,
            "--restart-on-reboot",
            "--ip-link-protection",
            "True",
        )

        remote_host, remote_port, link = get_remote_host_and_port(
            p_app, self.osinteraction, output_prefix="app"
        )
        print(lineNumber(), "remote port:", remote_port)
        sleep(1)
        click_open_for_ip_link(link)
        logger.debug("ping")

        self.check_application_is_still_alive(p_app)
        check_tcp_port_forward(self, remote_host, port, remote_port)

        share = self.db_handler.get_share_by_local_port(port)
        send_exit(share, force=True)

        run_method_with_timeout(p_app.wait, 10)
        self.assertTrue(p_app.poll() is not None)

        print_all_output(p_app, self.osinteraction, "p_app")

        self.assertEqual(1, get_nr_of_shares_in_db_file(self.db_file))

        p_manager2 = subprocess.Popen(
            self.openport_exe
            + [self.restart_shares, "--database", self.db_file, "--verbose"],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self.osinteraction.print_output_continuously_threaded(p_manager2, "p_manager2")
        self.processes_to_kill.append(p_manager2)
        run_method_with_timeout(p_manager2.wait, 10)

        # self.assertFalse(application_is_alive(p_manager2))

        sleep(5)  # wait for app to restart
        # todo: replace by /register

        share = self.db_handler.get_share_by_local_port(port)
        logger.debug(share)
        click_open_for_ip_link(share.open_port_for_ip_link)
        logger.debug("pong")

        check_tcp_port_forward(self, remote_host, port, remote_port)

        share = self.db_handler.get_share_by_local_port(port)
        send_exit(share, force=True)
        sleep(1)

        self.assertFalse(
            check_tcp_port_forward(
                self, remote_host, port, remote_port, fail_on_error=False
            )
        )

    def test_restart_shares__with_dash_dash_port(self):
        port = self.osinteraction.get_open_port()
        p_app = self.start_openport_process(
            "--port",
            port,
            "--restart-on-reboot",
            "--ip-link-protection",
            "True",
        )

        remote_host, remote_port, link = get_remote_host_and_port(
            p_app, self.osinteraction, output_prefix="app"
        )
        share = self.db_handler.get_share_by_local_port(port)
        send_exit(share, force=True)
        run_method_with_timeout(p_app.wait, 10)
        self.assertTrue(p_app.poll() is not None)

        print_all_output(p_app, self.osinteraction, "p_app")

        self.assertEqual(1, get_nr_of_shares_in_db_file(self.db_file))

        p_manager = self.start_openport_process_advanced(
            self.restart_shares, "--database", self.db_file, "--verbose"
        )
        self.osinteraction.print_output_continuously_threaded(p_manager, "p_manager")
        run_method_with_timeout(p_manager.wait, 10)
        sleep(5)  # wait for app to restart

        share = self.db_handler.get_share_by_local_port(port)
        logger.debug(share)
        click_open_for_ip_link(share.open_port_for_ip_link)
        logger.debug("pong")

        check_tcp_port_forward(self, remote_host, port, remote_port)

        share = self.db_handler.get_share_by_local_port(port)
        send_exit(share, force=True)
        sleep(1)

        self.assertFalse(
            check_tcp_port_forward(
                self, remote_host, port, remote_port, fail_on_error=False
            )
        )

    def test_openport_app__start_twice(self):
        port = self.osinteraction.get_open_port()
        print("local port :", port)

        manager_port = self.osinteraction.get_open_port()
        self.manager_port = manager_port
        print("manager_port :", manager_port)
        print("######app1")
        p_app = self.start_openport_process(port)
        remote_host1, remote_port1, link1 = get_remote_host_and_port(
            p_app, self.osinteraction, output_prefix="app"
        )
        print("######app2")
        p_app2 = self.start_openport_process(port)

        def foo():
            command_output = print_all_output(p_app2, self.osinteraction, "p_app2")
            if command_output[0]:
                return (
                    "Port forward already running for port %s" % port
                    in command_output[0],
                    command_output[0],
                )
            else:
                return False

        wait_for_response(foo)

        run_method_with_timeout(p_app2.wait, 5)
        self.assertFalse(application_is_alive(p_app2))

        p_app.kill()
        run_method_with_timeout(p_app.wait, 5)

        print("######app3")
        p_app3 = self.start_openport_process(port)
        self.processes_to_kill.append(p_app3)
        sleep(2)
        remote_host3, remote_port3, link3 = get_remote_host_and_port(
            p_app3, self.osinteraction, output_prefix="app3"
        )
        self.assertEqual(remote_host1, remote_host3)
        self.assertEqual(remote_port1, remote_port3)

    def test_openport_app__start_trice(self):
        port = self.osinteraction.get_open_port()
        print("local port :", port)

        p_app1 = self.start_openport_process(port)
        remote_host1, remote_port1, link1 = get_remote_host_and_port(
            p_app1, self.osinteraction, output_prefix="app"
        )

        p_app2 = self.start_openport_process(port)
        self.processes_to_kill.append(p_app2)

        def foo(p_app):
            command_output = print_all_output(p_app, self.osinteraction, "p_app2")
            if command_output[0]:
                return (
                    "Port forward already running for port %s" % port
                    in command_output[0],
                    command_output[0],
                )
            else:
                return False

        wait_for_response(foo, args=[p_app2])
        run_method_with_timeout(p_app2.wait, 5)
        self.assertFalse(application_is_alive(p_app2))

        print("######app3")
        p_app3 = self.start_openport_process(port)
        self.processes_to_kill.append(p_app3)
        wait_for_response(foo, args=[p_app3])
        run_method_with_timeout(p_app3.wait, 5)
        self.assertFalse(application_is_alive(p_app3))

    def write_to_conf_file(self, section, option, value):
        import ConfigParser

        config = ConfigParser.ConfigParser()
        config_location = os.path.expanduser("~/.openport/openport.cfg")
        config.read(config_location)
        config.set(section, option, value)
        with open(config_location, "w") as f:
            config.write(f)

    #  def test_manager__other_tcp_app_on_port(self):
    #      manager_port = self.osinteraction.get_open_port()
    #      self.manager_port = manager_port
    #      s = SimpleTcpServer(manager_port)
    #      s.runThreaded()
    #
    #      print 'manager_port :', manager_port
    #      self.write_to_conf_file('manager', 'port', manager_port)
    #
    #      p_manager2 = subprocess.Popen(self.openport_exe + ['manager', '--database', self.db_file,
    #                                     '--verbose'],
    #                                    stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    #      self.processes_to_kill.append(p_manager2)
    #      sleep(2)
    #      command_output = print_all_output(p_manager2, self.osinteraction, 'p_manager2')
    #
    #      self.assertNotEqual(False, command_output[0])
    #      self.assertTrue('Manager is now running on port' in command_output[0])
    #      self.assertTrue(application_is_alive(p_manager2))
    #
    #      s.close()
    #
    #  def test_manager__other_tcp_app_on_port__pass_by_argument(self):
    #      manager_port = self.osinteraction.get_open_port()
    #      self.manager_port = manager_port
    #      s = SimpleTcpServer(manager_port)
    #      s.runThreaded()
    #
    #      print 'manager_port :', manager_port
    #
    #      p_manager2 = subprocess.Popen(self.openport_exe + ['manager', '--database', self.db_file,
    #                                     '--verbose', '--manager-port', str(manager_port)],
    #                                    stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    #      self.processes_to_kill.append(p_manager2)
    #      sleep(2)
    #      command_output = print_all_output(p_manager2, self.osinteraction, 'p_manager2')
    #
    #      self.assertNotEqual(False, command_output[0])
    #      self.assertTrue('Manager is now running on port' in command_output[0])
    #      self.assertTrue(application_is_alive(p_manager2))
    #
    #      s.close()
    #
    #  def test_manager__other_http_app_on_port(self):
    #      manager_port = self.osinteraction.get_open_port()
    #      self.manager_port = manager_port
    #      s = TestHTTPServer(manager_port)
    #      s.reply('hello')
    #      s.runThreaded()
    #
    #      print 'manager_port :', manager_port
    #      self.write_to_conf_file('manager', 'port', manager_port)
    #
    #      p_manager2 = subprocess.Popen(self.openport_exe + ['manager', '--database', self.db_file,
    #                                     '--verbose'],
    #                                    stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    #      self.processes_to_kill.append(p_manager2)
    #      sleep(2)
    #      command_output = print_all_output(p_manager2, self.osinteraction, 'p_manager2')
    #
    #      self.assertNotEqual(False, command_output[0])
    #      self.assertTrue('Manager is now running on port' in command_output[0])
    #      self.assertTrue(application_is_alive(p_manager2))
    #
    #      s.stop()

    def getRemoteAddress(self, output):
        print("getRemoteAddress - output:%s" % output)
        import re

        m = re.search(r"Now forwarding remote address ([a-z\\.]*) to localhost", output)
        if m is None:
            raise Exception("address not found in output: %s" % output)
        return m.group(1)

    # def test_openport_app_start_manager(self):
    #     manager_port = self.osinteraction.get_open_port()
    #     self.manager_port = manager_port
    #     print 'manager port: ', manager_port
    #     self.assertFalse(openportmanager.manager_is_running(manager_port))
    #
    #     port = self.osinteraction.get_open_port()
    #     print 'local port: ', port
    #
    #     p_app = subprocess.Popen(self.openport_exe + ['--local-port', '%s' % port,
    #                               '--verbose', '--server', TEST_SERVER, '--manager-port', str(manager_port),
    #                               '--database', self.db_file, '--restart-on-reboot'],
    #                              stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    #     self.processes_to_kill.append(p_app)
    #
    #     remote_host, remote_port, link = get_remote_host_and_port(p_app, self.osinteraction, output_prefix='app')
    #     print lineNumber(), "remote port:", remote_port
    #     click_open_for_ip_link(link)
    #
    #     self.check_application_is_still_alive(p_app)
    #
    #     self.assertTrue(openportmanager.manager_is_running(manager_port))
    #
    #     os.kill(p_app.pid, KILL_SIGNAL)
    #     run_method_with_timeout(p_app.wait, 10)
    #     sleep(1)
    #     self.assertTrue(openportmanager.manager_is_running(manager_port))
    #     self.kill_manager(manager_port)
    #     sleep(5)
    #     self.assertFalse(openportmanager.manager_is_running(manager_port))

    def test_openport_app__cannot_reach_manager(self):
        port = self.osinteraction.get_open_port()
        print("local port: ", port)
        p_app = self.start_openport_process(
            "%s" % port,
            "--listener-port",
            str(700000),  # port out of reach
            "--restart-on-reboot",
        )

        remote_host, remote_port, link = get_remote_host_and_port(
            p_app, self.osinteraction, output_prefix="app"
        )
        click_open_for_ip_link(link)
        self.check_application_is_still_alive(p_app)
        print(lineNumber(), "remote port:", remote_port)

    def test_kill(self):
        port = self.osinteraction.get_open_port()
        print("local port: ", port)
        p_app = self.start_openport_process(
            "%s" % port,
        )
        # Todo: there still is a problem if the app gets the signal before the tunnel is set up.
        remote_host, remote_port, link = get_remote_host_and_port(
            p_app, self.osinteraction, output_prefix="p_app"
        )
        self.osinteraction.print_output_continuously_threaded(p_app, "p_app")
        self.processes_to_kill.append(p_app)

        p_kill = subprocess.Popen(
            self.openport_exe
            + [self.kill, str(port), "--database", self.db_file, "--verbose"],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self.processes_to_kill.append(p_kill)
        self.osinteraction.print_output_continuously_threaded(p_kill, "p_kill")
        run_method_with_timeout(p_kill.wait, 10)
        run_method_with_timeout(p_app.wait, 10)
        self.assertFalse(application_is_alive(p_app))

    def test_kill_all(self):
        port = self.osinteraction.get_open_port()
        print("local port: ", port)
        self.assertEqual(0, get_nr_of_shares_in_db_file(self.db_file))
        p_app1 = self.start_openport_process(
            "%s" % port,
        )
        get_remote_host_and_port(p_app1, self.osinteraction)
        self.osinteraction.print_output_continuously_threaded(p_app1, "p_app1")
        self.assertEqual(1, get_nr_of_shares_in_db_file(self.db_file))

        port2 = self.osinteraction.get_open_port()
        print("local port2: ", port2)
        self.assertNotEqual(port, port2)

        # p_app2 = subprocess.Popen(
        #     self.openport_exe
        #     + [
        #         "%s" % port2,
        #         "--verbose",
        #         "--server",
        #         TEST_SERVER,
        #         "--database",
        #         self.db_file,
        #     ],
        #     stderr=subprocess.PIPE,
        #     stdout=subprocess.PIPE,
        # )
        # self.processes_to_kill.append(p_app2)
        # get_remote_host_and_port(p_app2, self.osinteraction)

        for share in self.db_handler.get_active_shares():
            logger.debug(share.local_port)

        # self.assertEqual(2, get_nr_of_shares_in_db_file(self.db_file))
        self.assertEqual(1, get_nr_of_shares_in_db_file(self.db_file))
        p_kill = subprocess.Popen(
            self.openport_exe + [self.kill_all, "--database", self.db_file],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self.osinteraction.print_output_continuously_threaded(p_kill, "p_kill")
        sleep(1)
        self.processes_to_kill.append(p_kill)
        run_method_with_timeout(p_kill.wait, 10)
        sleep(1)
        self.assertFalse(p_app1.poll() is None)
        # self.assertFalse(p_app2.poll() is None)

    def check_http_port_forward(self, remote_host, local_port, remote_port=80):
        s = HTTPServerForTests(local_port)
        response = "echo"
        s.set_response(response)
        s.run_threaded()
        sleep(0.2)
        try:
            c = SimpleHTTPClient()
            actual_response = c.get("http://localhost:%s" % local_port)
            self.assertEqual(actual_response, response.strip())
            url = (
                "http://%s:%s" % (remote_host, remote_port)
                if remote_port != 80
                else "http://%s" % remote_host
            )
            print("checking url:{}".format(url))
            try:
                actual_response = c.get(url)
            except Exception as e:
                logger.exception(e)
                self.fail("Http forward failed")
            self.assertEqual(actual_response, response.strip())
            logger.info("http portforward ok")

            url = "https://%s" % remote_host
            logger.info("checking url:{}".format(url))
            try:
                actual_response = c.get(url)
            except Exception as e:
                logger.exception(e)
                self.fail("Https forward failed")
            self.assertEqual(actual_response, response.strip())
            logger.info("http portforward ok")
        finally:
            s.stop()

    def kill_manager(self, manager_port):
        url = "http://localhost:%s/exit" % manager_port
        logger.debug("sending get request " + url)
        try:
            req = urllib2.Request(url)
            response = urllib2.urlopen(req, timeout=1).read()
            if response.strip() != "ok":
                print(lineNumber(), response)
            else:
                print("manager killed")
        except Exception as detail:
            print(detail)

    def get_share_count_of_manager(self, manager_port):
        url = "http://localhost:%s/active_count" % manager_port
        logger.debug("sending get request " + url)
        try:
            req = urllib2.Request(url)
            response = urllib2.urlopen(req, timeout=1).read()
            return int(response)

        except Exception as detail:
            print("error contacting the manager: %s %s" % (url, detail))
            raise

    def test_kill_openport_app(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process(
            "--local-port",
            "%s" % port,
        )
        sleep(2)
        get_remote_host_and_port(p, self.osinteraction)

        print("pid: %s" % p.pid)
        self.osinteraction.kill_pid(p.pid, signal.SIGINT)
        run_method_with_timeout(p.wait, 10)

        output = self.osinteraction.get_output(p)
        print(output[0])
        print(output[1])
        # Sadly, this does not work on windows...
        if not osinteraction.is_windows():
            self.assertTrue("got signal " in str(output[0]).lower())

        self.assertFalse(self.osinteraction.pid_is_running(p.pid))

    def test_remote_kill_stops_application(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process(port)

        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        self.check_application_is_still_alive(p)
        sleep(1)

        session = self.db_handler.get_share_by_local_port(port)
        data = {
            "port": session.server_port,
            "session_token": session.server_session_token,
        }
        print(data)
        r = requests.post("{}/api/v1/kill-session".format(TEST_SERVER), data)
        logger.debug("#########{}".format(r.text))

        self.assertEqual(200, r.status_code, r.text)
        self.osinteraction.print_output_continuously_threaded(p, "p")
        run_method_with_timeout(p.wait, 30)
        self.assertFalse(self.osinteraction.pid_is_running(p.pid))

    def test_version(self):
        p = subprocess.Popen(
            self.openport_exe + [self.version],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self.processes_to_kill.append(p)
        run_method_with_timeout(p.wait, 10)

        process_output = p.communicate()
        for out in process_output:
            print("output: ", out)

        self.assertFalse(application_is_alive(p))
        self.assertEqual(self.app_version, process_output[0].decode("utf-8").strip())

    def test_run_run_command_with_timeout(self):
        self.assertEqual(
            (False, False),
            run_command_with_timeout(
                [PYTHON_EXE, "-c", "from time import sleep;sleep(1)"], 2
            ),
        )
        self.assertEqual(
            (False, False),
            run_command_with_timeout(
                [PYTHON_EXE, "-c", "from time import sleep;sleep(2)"], 1
            ),
        )
        self.assertEqual(
            ("hello", False),
            run_command_with_timeout([PYTHON_EXE, "-c", "print('hello')"], 1),
        )
        self.assertEqual(
            ("hello", False),
            run_command_with_timeout(
                [
                    PYTHON_EXE,
                    "-c",
                    "from time import sleep;import sys"
                    ";print('hello');sys.stdout.flush()"
                    ";sleep(2)",
                ],
                1,
            ),
        )

    def test_shell_behaviour(self):
        p = subprocess.Popen(
            '''%s -c "print('hello')"''' % PYTHON_EXE,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(("hello", False), self.osinteraction.get_output(p))

        p = subprocess.Popen(
            [PYTHON_EXE, "-c", 'print("hello")'],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(("hello", False), self.osinteraction.get_output(p))

    def test_open_for_ip_option__False(self):
        port = self.osinteraction.get_open_port()

        p = self.start_openport_process(
            "--local-port",
            "%s" % port,
            "--ip-link-protection",
            "False",
        )
        self.check_application_is_still_alive(p)
        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        self.assertIsNone(link)
        check_tcp_port_forward(self, remote_host, port, remote_port)

    def test_open_for_ip_option__True(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process(
            "--local-port",
            "%s" % port,
            "--ip-link-protection",
            "True",
        )
        self.check_application_is_still_alive(p)
        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)

        self.assertFalse(
            check_tcp_port_forward(
                self, remote_host, port, remote_port, fail_on_error=False
            )
        )
        self.assertIsNotNone(link)

        click_open_for_ip_link(link)
        check_tcp_port_forward(self, remote_host, port, remote_port)

    def check_migration(self, old_db_file, local_port, old_token, old_remote_port):
        old_db = TEST_FILES_PATH / old_db_file
        old_db_tmp = TEST_FILES_PATH / "tmp" / old_db_file
        shutil.copy(old_db, old_db_tmp)
        self.db_handler = dbhandler.DBHandler(old_db_tmp)

        port = self.osinteraction.get_open_port()

        http_server = HTTPServerForTests(port)
        http_server.run_threaded()

        try:
            server = f"http://localhost:{port}"
            p = self.start_openport_process(
                "--local-port",
                str(local_port),
                server=server,
                database=old_db_tmp,
            )
            wait_for_response(lambda: len(http_server.requests) > 0, timeout=2)
            request = http_server.requests[0]
            self.assertEqual([old_token], request[b"restart_session_token"])
            self.assertEqual([old_remote_port], request[b"request_port"])
            self.assertEqual([b"false"], request[b"automatic_restart"])
        finally:
            http_server.stop()

    def check_migration__restart_sessions(
        self, old_db_file, local_port, old_token, old_remote_port
    ):
        old_db = TEST_FILES_PATH / old_db_file
        old_db_tmp = TEST_FILES_PATH / "tmp" / old_db_file
        shutil.copy(old_db, old_db_tmp)

        port = self.osinteraction.get_open_port()

        http_server = HTTPServerForTests(port)
        http_server.run_threaded()

        try:
            server = f"http://localhost:{port}"
            p = self.start_openport_process(
                self.restart_shares,
                server=server,
                database=old_db_tmp,
            )
            self.osinteraction.print_output_continuously_threaded(p, "restart_sessions")

            wait_for_response(lambda: len(http_server.requests) > 0, timeout=5)
            request = http_server.requests[0]
            self.assertEqual([old_token], request[b"restart_session_token"])
            self.assertEqual([old_remote_port], request[b"request_port"])
            self.assertEqual([b"true"], request[b"automatic_restart"])
        finally:
            http_server.stop()

    def test_db_migrate_from_0_9_1__new_share(self):
        if self.ws_options:
            self.skipTest("not supported with websockets")
        self.check_migration("openport-0.9.1.db", 22, b"gOFZM7vDDcxsqB1P", b"38261")
        self.check_migration__restart_sessions(
            "openport-0.9.1.db", 22, b"gOFZM7vDDcxsqB1P", b"38261"
        )
        self.kill_all_in_db(TEST_FILES_PATH / "tmp" / "openport-0.9.1.db")

    def test_db_migrate_from_1_2_0(self):
        if self.ws_options:
            self.skipTest("not supported with websockets")
        self.check_migration("openport-1.2.0.db", 22, b"yOEav4nqJaW1nfw0", b"18369")
        self.check_migration__restart_sessions(
            "openport-1.2.0.db", 22, b"yOEav4nqJaW1nfw0", b"18369"
        )

    def test_db_migrate_from_1_3_0(self):
        if self.ws_options:
            self.skipTest("not supported with websockets")
        self.check_migration("openport-1.3.0.db", 44, b"Me8eHwaze3F6SMS9", b"26541")
        # todo: does this mean it doesnt work?
        # with self.assertRaises(TimeoutError):
        self.check_migration__restart_sessions(
            "openport-1.3.0.db", 44, b"Me8eHwaze3F6SMS9", b"26541"
        )
        subprocess.Popen(
            self.openport_exe + self.kill_all,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

    def test_db_migrate_from_1_3_0__2(self):
        if self.ws_options:
            self.skipTest("not supported with websockets")
        self.check_migration(
            "openport-1.3.0_2.db", 54613, b"DRADXUnvHW9m6FuS", b"15070"
        )
        with self.assertRaises(TimeoutError):
            self.check_migration__restart_sessions(
                "openport-1.3.0_2.db", 54613, b"DRADXUnvHW9m6FuS", b"15070"
            )
            self.kill_all_in_db(TEST_FILES_PATH / "tmp" / "openport-1.3.0_2.db")

    def test_db_migrate_from_1_3_0__3(self):
        if self.ws_options:
            self.skipTest("not supported with websockets")
        self.check_migration("openport-1.3.0_3.db", 44, b"FYfS3a05OnkXWNj4", b"42006")
        self.check_migration__restart_sessions(
            "openport-1.3.0_3.db", 44, b"FYfS3a05OnkXWNj4", b"42006"
        )
        self.kill_all_in_db(TEST_FILES_PATH / "tmp" / "openport-1.3.0_3.db")

    def kill_all_in_db(self, db_file: Path):
        subprocess.Popen(
            self.openport_exe + f"{self.kill_all} --database {db_file}".split(),
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

    def test_restart_command_from_version_0_9_1(self):
        if self.ws_options:
            self.skipTest("not supported with websockets")
        cmd = (
            "22 --restart-on-reboot --request-port 38261 --request-token gOFZM7vDDcxsqB1P --start-manager False "
            "--manager-port 57738 --server http://localhost:63771 "
            f"--database {self.db_file}"
        )
        p = subprocess.Popen(
            self.openport_exe + cmd.split() + self.ws_options,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self.osinteraction.print_output_continuously_threaded(p)
        self.processes_to_kill.append(p)
        sleep(1)
        self.assertTrue(application_is_alive(p))

    def test_openport_app__no_errors(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process(port)

        get_remote_host_and_port(p, self.osinteraction)

        output = print_all_output(p, self.osinteraction)
        self.assertFalse(output[1])
        # self.assertFalse('UserWarning' in output[1])

    def test_openport_app__restart_on_reboot_app_not_running(self):
        port = self.osinteraction.get_open_port()
        # This app should be restarted
        p = self.start_openport_process(
            "--local-port",
            "%s" % port,
            "--restart-on-reboot",
        )
        get_remote_host_and_port(p, self.osinteraction)
        p.kill()

        # This app shouldn't be restarted
        q = self.start_openport_process(port)

        remote_host, remote_port, link = get_remote_host_and_port(q, self.osinteraction)
        output = self.osinteraction.get_all_output(q)

        self.assertTrue(
            "Port forward for port %s that would be restarted on reboot will not be restarted anymore."
            % port
            in output[0]
        )

    def test_hang(self):
        if self.ws_options:
            self.skipTest("not supported with websockets")

        sleep_and_print = """from time import sleep
for i in range(%s):
    print(i)
    sleep(1)
print('Now forwarding remote port test.openport.be:12345 to localhost:555')
print('to first go here: http://1235.be .')
print('INFO - You are now connected. You can access the remote pc\\\'s port 7777 on localhost:8888')

for i in range(%s):
    print(i)
    sleep(1)
    """
        port_out = self.osinteraction.get_open_port()
        if 1 == 1:
            p_out = self.start_openport_process(port_out)
        else:
            p_out = subprocess.Popen(
                [PYTHON_EXE, "-c", sleep_and_print % (3, 60)],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            logger.debug("p_out.pid: %s" % p_out.pid)

        self.processes_to_kill.append(p_out)
        remote_host, remote_port, link = get_remote_host_and_port(
            p_out, self.osinteraction
        )
        #   click_open_for_ip_link(link)
        self.osinteraction.print_output_continuously_threaded(p_out, "p_out")

        sleep(1)
        logger.debug(self.osinteraction.get_output(p_out))

        if 1 == 1:
            if 1 == 1:
                p_in = self.start_openport_process(
                    self.forward,
                    "--remote-port",
                    str(remote_port),
                    "--restart-on-reboot",
                )
                host, port_in, link = get_remote_host_and_port(
                    p_in, self.osinteraction, forward_tunnel=True
                )

            else:
                port_out = self.osinteraction.get_open_port()
                p_in = self.start_openport_process(
                    "--local-port",
                    port_out,  # --verbose,
                )
                host, port_in, link = get_remote_host_and_port(p_in, self.osinteraction)

        else:
            p_in = subprocess.Popen(
                [PYTHON_EXE, "-c", sleep_and_print % (3, 60)],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            host, port_in, link = get_remote_host_and_port(
                p_in, self.osinteraction, forward_tunnel=True
            )
        logger.debug("p_in.pid: %s" % p_in.pid)

        self.processes_to_kill.append(p_in)
        self.check_application_is_still_alive(p_in)
        self.check_application_is_still_alive(p_out)

        sleep(1)
        logger.debug(self.osinteraction.get_output(p_in))

        #  sleep(2)
        #  in_session = self.db_handler.get_share_by_local_port(port_in, filter_active=False)
        #  check_tcp_port_forward(self, remote_host='127.0.0.1', local_port=port_out, remote_port=port_in)

        p_in.terminate()
        logger.debug("p_in wait")
        run_method_with_timeout(p_in.wait, 10)
        logger.debug("p_in wait done")

        if 1 == 1:
            p_restart = subprocess.Popen(
                self.openport_exe
                + [self.restart_shares, "--verbose", "--database", self.db_file],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
        else:
            p_restart = subprocess.Popen(
                [PYTHON_EXE, "-c", sleep_and_print % (1, 3)],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
        logger.debug("p_restart started")
        self.processes_to_kill.append(p_restart)
        logger.debug("p_restart continuous print")
        self.osinteraction.print_output_continuously_threaded(p_restart, "p_restart")
        logger.debug("p_restart.wait")
        # run_method_with_timeout(p_restart.wait, 10)
        # p_restart.communicate()
        logger.debug("p_restart.pid: %s" % p_restart.pid)
        run_method_with_timeout(p_restart.wait, 10)
        #  p_restart.wait()
        logger.debug("p_restart.wait done")

        self.check_application_is_still_alive(p_out)
        logger.debug("alive!")

        #        check_tcp_port_forward(self, remote_host=remote_host, local_port=port_out, remote_port=remote_port)

        def foo():
            return False

        logger.debug("wait for response")
        #        wait_for_response(foo, timeout=5)
        logger.debug("sleeping now")
        sleep(1)
        # sleep(20)
        logger.debug("wait_for_response done")

    #   check_tcp_port_forward(self, remote_host='127.0.0.1', local_port=port_out, remote_port=port_in)

    def test_list(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process(port)

        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        self.check_application_is_still_alive(p)

        session = self.db_handler.get_share_by_local_port(port)

        p = subprocess.Popen(
            self.openport_exe + [self.list, "--database", self.db_file],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        p.wait(10)
        output = p.communicate()
        for i in output:
            print(i)
        self.assertTrue(session.open_port_for_ip_link in output[0].decode("utf-8"))

    def test_auto_restart_on_disconnect(self):
        port = self.osinteraction.get_open_port()
        proxy, proxy_client = self.get_proxy()

        p = self.start_openport_process(
            port,
            "--restart-on-reboot",
            "--ip-link-protection",
            "False",
            "--keep-alive",
            "1",
            "--proxy",
            f"socks5://{proxy}",
        )
        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        self.osinteraction.print_output_continuously_threaded(p)

        self.check_application_is_still_alive(p)
        self.assertIsNone(link)
        check_tcp_port_forward(
            self, remote_host=remote_host, local_port=port, remote_port=remote_port
        )
        proxy_client.disable()
        sleep(0.1)
        self.assertFalse(
            check_tcp_port_forward(
                self,
                remote_host=remote_host,
                local_port=port,
                remote_port=remote_port,
                fail_on_error=False,
            )
        )

        sleep(5)
        proxy_client.enable()
        remote_host, remote_port, link = get_remote_host_and_port(
            p, self.osinteraction, timeout=30
        )
        self.assertIsNone(link)
        sleep(5)
        check_tcp_port_forward(
            self, remote_host=remote_host, local_port=port, remote_port=remote_port
        )

    def test_exits_on_disconnect_if_connection_timeout_set(self):
        port = self.osinteraction.get_open_port()
        proxy, proxy_client = self.get_proxy()

        p = self.start_openport_process(
            port,
            "--proxy",
            f"socks5://{proxy}",
            "--ip-link-protection",
            "False",
            "--keep-alive",
            "1",
            "--exit-on-failure-timeout",
            "5",
            "--restart-on-reboot",
        )
        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        self.osinteraction.print_output_continuously_threaded(p)

        self.check_application_is_still_alive(p)
        self.assertIsNone(link)
        check_tcp_port_forward(
            self, remote_host=remote_host, local_port=port, remote_port=remote_port
        )
        proxy_client.disable()
        self.assertFalse(
            check_tcp_port_forward(
                self,
                remote_host=remote_host,
                local_port=port,
                remote_port=remote_port,
                fail_on_error=False,
            )
        )

        sleep(5)
        self.assertEqual(4, p.returncode, "Expected process to have killed itself.")

    def get_proxy(self):
        import toxiproxy

        # make sure you've run
        # docker compose -f docker-compose/toxiproxy.yaml up
        APIConsumer.host = TOXI_PROXY_HOST
        server = toxiproxy.Toxiproxy()
        server.destroy_all()
        socks_proxy = os.environ.get("SOCKS_PROXY", get_ip())

        return f"{TOXI_PROXY_HOST}:22220", server.create(
            name="socks_proxy",
            upstream=f"{socks_proxy}:1080",
            enabled=True,
            listen="0.0.0.0:22220",
        )

    def test_killed_session_not_restarting(self):
        port = self.osinteraction.get_open_port()
        http_server = HTTPServerForTests(port)
        http_server.set_response(
            {
                "session_token": "abc",
                "server_ip": "localhost",
                "server_port": 266,  # nobody is listening
                "fallback_ssh_server_ip": "localhost",
                "fallback_ssh_server_port": 226,  # nobody is listening
                "message": "You will not be able to connect, which is expected",
                "account_id": 1,
                "key_id": 1,
                "session_end_time": None,
                "session_max_bytes": 100,
                "session_id": 1,
                "http_forward_address": "",
                "open_port_for_ip_link": "",
            }
        )
        http_server.run_threaded()

        local_port = self.osinteraction.get_open_port()

        try:
            server = f"http://localhost:{port}"
            logger.info(f"local server: {server}")
            p = self.start_openport_process(local_port, server=server)
            self.osinteraction.print_output_continuously_threaded(p)

            wait_for_response(lambda: len(http_server.requests) > 0, timeout=10)

            http_server.set_response(
                {
                    "error": "Session killed",
                    "fatal_error": True,
                }
            )

            wait_for_response(lambda: p.returncode is not None, timeout=20)
        finally:
            http_server.stop()

    def test_app_keeps_retrying_after_invalid_server_response(self):
        port = self.osinteraction.get_open_port()
        http_server = HTTPServerForTests(port)
        http_server.set_response(
            {
                "session_token": "abc",
                "server_ip": "localhost",
                "server_port": 266,  # nobody is listening
                "fallback_ssh_server_ip": "localhost",
                "fallback_ssh_server_port": 226,  # nobody is listening
                "message": "You will not be able to connect, which is expected",
                "account_id": 1,
                "key_id": 1,
                "session_end_time": None,
                "session_max_bytes": 100,
                "session_id": 1,
                "http_forward_address": "",
                "open_port_for_ip_link": "",
            }
        )
        http_server.run_threaded()

        local_port = self.osinteraction.get_open_port()

        try:
            server = f"http://localhost:{port}"
            logger.info(f"local server: {server}")
            p = self.start_openport_process(local_port, server=server)

            self.osinteraction.print_output_continuously_threaded(p)

            wait_for_response(lambda: len(http_server.requests) > 0, timeout=10)

            http_server.set_response(
                """
                <html>
                <head><title>504 Gateway Time-out</title></head>
                <body bgcolor="white">
                <center><h1>504 Gateway Time-out</h1></center>
                <hr><center>nginx/1.14.2</center>
                </body>
                </html>
                """
            )
            wait_for_response(lambda: len(http_server.requests) > 3, timeout=60)
            self.assertEqual([b"true"], http_server.requests[-1][b"automatic_restart"])

        finally:
            http_server.stop()

    def test_set_request_server(self):
        self.check_request_server_is_respected("test2.openport.io", "test2.openport.io")
        self.check_request_server_is_respected("test2.openport.io", "test.openport.io")
        self.check_request_server_is_respected("test.openport.io", "test2.openport.io")
        self.check_request_server_is_respected("test.openport.io", "test.openport.io")

    def check_request_server_is_respected(self, https_server, ssh_server):
        local_port = self.osinteraction.get_open_port()
        p = self.start_openport_process(
            local_port, "--request-server", ssh_server, server=f"https://{https_server}"
        )
        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        self.assertEqual(ssh_server, remote_host)
        p.kill()

    def check_live_server(self, tunnel_server):
        local_port = self.osinteraction.get_open_port()
        p = self.start_openport_process(
            local_port,
            "--request-server",
            tunnel_server,
            server=None,
        )
        remote_host, remote_port, link = get_remote_host_and_port(
            p, self.osinteraction, timeout=60
        )

        messing_with_dns = False
        if messing_with_dns:
            remote_host = remote_host.replace(".io", ".xyz")
            link = link.replace(".io", ".xyz")
            tunnel_server = tunnel_server.replace(".io", ".xyz")

        click_open_for_ip_link(link)
        self.assertEqual(tunnel_server, remote_host)
        check_tcp_port_forward(self, remote_host, local_port, remote_port)
        p.kill()

    def test_all_servers_live(self):
        live_servers = ["openport.io", "spr.openport.io", "us.openport.io"]
        for live_server in live_servers:
            with self.subTest(live_server):
                self.check_live_server(live_server)
                sleep(1)

    def test_rm_session(self):
        port = self.osinteraction.get_open_port()
        p = self.start_openport_process(port)
        remote_host, remote_port, link = get_remote_host_and_port(p, self.osinteraction)
        self.check_application_is_still_alive(p)

        p = self.start_openport_process_advanced(
            "rm",
            port,
            "--verbose",
            "--database",
            self.db_file,
        )
        p.wait(10)
        output = p.communicate()
        for i in output:
            print(i)
        self.assertIn(
            f"Session for local port {port} deleted.".encode("utf-8"), output[0]
        )

        p = self.start_openport_process(port)
        remote_host_2, remote_port_2, link_2 = get_remote_host_and_port(
            p, self.osinteraction
        )
        self.assertNotEqual(remote_port, remote_port_2)
        self.assertNotEqual(link, link_2)

    def test_help_messages(self):
        commands = [
            "",
            "forward",
            "list",
            "restart-sessions",
            "kill",
            "kill-all",
            "register",
            "rm",
            "version",
        ]
        for command in commands:
            logger.info(f"command: {command}")
            command_list = []
            if command != "":
                command_list = [command]
            p = subprocess.Popen(
                self.openport_exe + command_list + ["--help"],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )

            process_output = p.communicate()
            print(process_output[1].decode("utf-8"))

            self.assertEqual(0, p.returncode)
            self.assertEqual(b"", process_output[0])
            self.assertIn(b"Usage: ", process_output[1])

    def test_request_content(self):
        local_port = self.osinteraction.get_open_port()
        port = self.osinteraction.get_open_port()
        http_server = HTTPServerForTests(port)
        http_server.run_threaded()
        token = "M7Vgwg3drk32yafdf"
        server_reply_port = 49482
        server_reply_server = "blah.openport.io"
        http_server.set_response(
            {
                "session_token": token,
                "server_ip": server_reply_server,
                "server_port": server_reply_port,
                "fallback_ssh_server_ip": "s.openport.io",
                "fallback_ssh_server_port": 443,
                "message": "You are now connected.",
                "account_id": 0,
                "key_id": 123455,
                "session_end_time": None,
                "session_max_bytes": 1000,
                "session_id": 3331221,
                "http_forward_address": None,
                "open_port_for_ip_link": "https://openport.io/l/49482/abcde",
            }
        )

        try:
            server = f"http://localhost:{port}"
            p = self.start_openport_process(local_port, server=server)

            wait_for_response(lambda: len(http_server.requests) > 0, timeout=2)
            request = http_server.requests[0]
            self.assertNotIn(b"restart_session_token", request)
            self.assertEqual([b"0"], request[b"request_port"])
            self.assertEqual([b"false"], request[b"automatic_restart"])

            p.kill()
            p.wait()

            p = self.start_openport_process(local_port, server=server)

            wait_for_response(lambda: len(http_server.requests) > 1, timeout=2)
            self.osinteraction.print_output_continuously_threaded(
                p, "restarted_process"
            )
            request = http_server.requests[1]
            self.assertEqual(
                [str(server_reply_port).encode()], request[b"request_port"]
            )
            self.assertEqual([token.encode()], request[b"restart_session_token"])
            self.assertEqual([b"false"], request[b"automatic_restart"])
            self.assertEqual([server_reply_server.encode()], request[b"request_server"])
        finally:
            http_server.stop()

    def test_request_content__forward_tunnel(self):
        if self.ws_options:
            self.skipTest("forwards not yet supported with websockets")
        local_port = self.osinteraction.get_open_port()
        port = self.osinteraction.get_open_port()
        http_server = HTTPServerForTests(port)
        http_server.run_threaded()
        try:
            server = f"http://localhost:{port}"
            p = self.start_openport_process(
                self.forward,
                "--local-port",
                local_port,
                "--remote-port",
                "abc.openport.io:1234",
                server=server,
            )
            wait_for_response(lambda: len(http_server.requests) > 0, timeout=2)
            request = http_server.requests[0]
            self.assertEqual([b"1234"], request[b"request_port"])
            self.assertNotIn(b"restart_session_token", request)
            self.assertEqual([b"false"], request[b"automatic_restart"])
            self.assertEqual([b"abc.openport.io"], request[b"request_server"])
        finally:
            http_server.stop()


class AppTestWS(AppTests):
    ws_options = ["--ws"]


class AppTestWSNoSSL(AppTests):
    ws_options = ["--ws", "--no-ssl"]
