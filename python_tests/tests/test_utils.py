import inspect
import json
import os
import re
import subprocess
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs
from urllib.request import Request, urlopen

import datetime
import requests
import socket
import threading
from time import sleep

# from openport.apps.openport_service import Openport
# from openport.apps.openportit import OpenportItApp
from tests.utils import osinteraction, dbhandler
from tests.utils.logger_service import get_logger
from tests.utils.utils import run_method_with_timeout, TimeoutException
from prettytable import PrettyTable

logger = get_logger(__name__)

TEST_FILES_PATH = Path(__file__).parent / "testfiles"


class HTTPServerForTests(object):
    def __init__(self, port):
        self.server = HTTPServer(("", port), HTTPRequestHandlerForTests)
        self.requests = []
        self.server.requests = self.requests
        self.server.response = ""

    def set_response(self, response):
        self.server.response = response  # what a hack

    def run_threaded(self):
        import threading

        thr = threading.Thread(target=self.server.serve_forever, daemon=True)
        thr.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class HTTPRequestHandlerForTests(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, http_server):
        self._response = http_server.response
        self.requests = http_server.requests
        super().__init__(request, client_address, http_server)

    def _set_headers(self, response_length, content_type="application/json"):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(response_length))
        self.end_headers()

    def do_GET(self):
        response = self._response.encode("utf-8")
        print(f"got request: {self.raw_requestline}, will reply : {response}")
        self._set_headers(len(response))
        self.wfile.write(response)

    def do_POST(self):
        print(self.raw_requestline)
        response = json.dumps(self._response).encode("utf-8")
        self._set_headers(len(response), "application/json")
        data = self.rfile.read(int(self.headers["Content-Length"]))
        print(f"request body: {data}")
        try:
            data = parse_qs(data)
        except:
            data = json.loads(data)
        print(f"request body: {data}")
        self.requests.append(data)
        self.wfile.write(response)


class SimpleHTTPClient(object):
    def get(self, url, print500=True):
        logger.debug("sending get request " + url)
        try:
            r = requests.get(url)
            return r.text
        except HTTPError as e:
            if print500 and e.getcode() == 500:
                print(e.read())
            raise
        except Exception as detail:
            logger.exception(detail)
            print("An error has occurred: {}".format(detail))
            raise


class SimpleTcpServer(object):
    def __init__(self, port):
        self.HOST = "127.0.0.1"  # Symbolic name meaning the local host
        self.PORT = port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((self.HOST, self.PORT))
        self.s.listen(5)
        self.connections_accepted = 0
        self.closed = False

    def run(self):
        while not self.closed:
            print("connections accepted: ", self.connections_accepted)
            self.connections_accepted += 1
            conn, self.address = self.s.accept()
            print("Connected by", self.address)
            data = conn.recv(1024)
            if data:
                conn.send(data)
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()

    def close(self):
        self.closed = True
        try:
            self.s.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            logger.exception(e)
        try:
            self.s.close()
        except Exception as e:
            logger.exception(e)

    def runThreaded(self):
        import threading

        thr = threading.Thread(target=self.run, args=())
        thr.setDaemon(True)
        thr.start()


class SimpleTcpClient(object):
    def __init__(self, host, port):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(2)
        except socket.error as msg:
            sys.stderr.write("[ERROR] %s\n" % msg[1])
        #            sys.exit(1)

        try:
            self.sock.connect((host, port))

        except socket.timeout as e:
            sys.stderr.write("[timeout] %s\n" % e)
        except socket.error as msg:
            sys.stderr.write("[ERROR] %s\n" % msg)
            if hasattr(msg, "len") and len(msg) > 0:
                sys.stderr.write("[ERROR] %s\n" % msg[1])

    #            sys.exit(2)

    def send(self, request):
        # noinspection PyTypeChecker
        self.sock.send("{}\n".format(request).encode("utf-8"))

        data = self.sock.recv(1024)
        response = ""
        while len(data):
            response += data.decode("utf-8")
            data = self.sock.recv(1024)
        return response

    def close(self):
        #        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()


def lineNumber():
    """Returns the current line number in our program."""
    return inspect.currentframe().f_back.f_lineno


if __name__ == "__main__":
    #    port = get_open_port()
    #    s = SimpleTcpServer(port)
    #    s.runThreaded()
    #    sleep(1)
    #
    #    c = SimpleTcpClient('localhost', port)
    #
    #    var = raw_input('Enter something: ')
    #    print 'you entered ', var
    #    print 'server replied', c.send(var)

    port = osinteraction.getInstance().get_open_port()
    s = HTTPServerForTests(port)
    s.set_response("hooray")
    s.run_threaded()
    sleep(1)

    c = SimpleHTTPClient()

    print("server replied", c.get("http://localhost:%s" % port))


def run_command_with_timeout(args, timeout_s):
    process = subprocess.Popen(
        args,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        shell=osinteraction.is_windows(),
        close_fds=not osinteraction.is_windows(),
    )
    try:
        process.wait(timeout_s)
    except subprocess.TimeoutExpired:
        print("Terminating process")
        process.terminate()
    print(process.returncode)
    return osinteraction.getInstance().get_output(process)


def run_command_with_timeout_return_process(args, timeout_s):
    class Command(object):
        def __init__(self, cmd):
            self.cmd = cmd
            self.process = None

        def run(self, timeout):
            command = self.cmd
            if osinteraction.is_windows():
                command = " ".join(['"%s"' % arg for arg in self.cmd])
            self.process = subprocess.Popen(
                command,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                shell=osinteraction.is_windows(),
                close_fds=not osinteraction.is_windows(),
            )

            def kill_target():
                wait_thread.join(timeout)
                if wait_thread.is_alive():
                    print("Terminating process")
                    self.process.terminate()
                    wait_thread.join()

            def wait_target():
                self.process.wait()

            wait_thread = threading.Thread(target=wait_target)
            wait_thread.setDaemon(True)
            wait_thread.start()

            kill_thread = threading.Thread(target=kill_target)
            kill_thread.setDaemon(True)
            kill_thread.start()

            return self.process

    c = Command(args)
    return c.run(timeout_s)


def get_remote_host_and_port(
    p,
    osinteraction,
    timeout=10,
    output_prefix="",
    http_forward=False,
    forward_tunnel=False,
):
    start = datetime.datetime.now()
    all_output = ["", ""]
    while start + datetime.timedelta(seconds=timeout) > datetime.datetime.now():
        output = osinteraction.get_output(p)
        for j in range(2):
            if output[j]:
                all_output[j] += output[j] + "\n"
        if output[0]:
            logger.info("%s - stdout -  <<<<<%s>>>>>" % (output_prefix, output[0]))
        if output[1]:
            logger.error("%s - stderr - <<<<<%s>>>>>" % (output_prefix, output[1]))
        if not output[0]:
            sleep(0.1)
            continue

        if http_forward:
            m = re.search(
                r"Now forwarding remote address (?P<host>[a-z0-9\.\-]*) to localhost",
                output[0],
            )
        elif forward_tunnel:
            m = re.search(
                r"You are now connected. You can access the remote pc\'s port (?P<remote_port>\d*) "
                r"on localhost:(?P<local_port>\d*)",
                output[0],
            )
        else:
            m = re.search(
                r"Now forwarding remote port (?P<host>[^:]*):(?P<remote_port>\d*) to localhost",
                output[0],
            )
        if m is None:
            if p.poll() is not None:
                raise Exception("Application is stopped")
            sleep(0.1)
            continue
        else:
            if http_forward:
                host = m.group("host")
                port = 80
            elif forward_tunnel:
                host = "localhost"
                port = int(m.group("local_port"))
            else:
                host, port = m.group("host"), int(m.group("remote_port"))
            m = re.search(r"to first go here: ([a-zA-Z0-9\:/\.\-]+) .", output[0])
            link = m.group(1) if m is not None else None
            return host, port, link

    raise Exception("remote host and port not found in output: {}".format(all_output))


def wait_for_response(
    function, args=[], kwargs={}, timeout=30, throw=True, max_method_run_time=None
):
    if max_method_run_time is None:
        max_method_run_time = timeout

    start_time = datetime.datetime.now()
    while start_time + datetime.timedelta(seconds=timeout) > datetime.datetime.now():
        try:
            output = run_method_with_timeout(
                function,
                max_method_run_time,
                args=args,
                kwargs=kwargs,
                raise_exception=True,
            )
            if output:
                return output
        except TimeoutException:
            logger.debug("method timeout")
            pass
        logger.debug("Waiting for response: no response, try again")
        sleep(1)
    if throw:
        raise TimeoutError("function did not response in time")
    return False


def print_all_output(app, osinteraction, output_prefix=""):
    all_output = osinteraction.get_output(app)
    if all_output[0]:
        print("%s - stdout -  <<<%s>>>" % (output_prefix, all_output[0]))
    if all_output[1]:
        print("%s - stderr - <<<%s>>>" % (output_prefix, all_output[1]))
    return all_output


def wait_for_success_callback(p_manager, osinteraction, timeout=30, output_prefix=""):
    i = 0
    while i < timeout:
        i += 1
        all_output = print_all_output(p_manager, osinteraction, output_prefix)
        if not all_output[0]:
            sleep(1)
            continue
        if "/successShare" in all_output[0]:
            return
        else:
            sleep(1)
    raise Exception("success_callback not found (timeout expired)")


def kill_all_processes(processes_to_kill):
    for p in processes_to_kill:
        try:
            if p.poll() is None:
                logger.debug("killing process %s" % p.pid)
                osinteraction.getInstance().kill_pid(p.pid)
            p.wait()
        except Exception as e:
            logger.exception(e)


def click_open_for_ip_link(link):
    if link:
        # link = link.replace("https", "http")
        logger.info("clicking link %s" % link)
        #        ctx = ssl.create_default_context()
        #        ctx.check_hostname = False
        #        ctx.verify_mode = ssl.CERT_NONE
        req = Request(link)
        response = run_method_with_timeout(lambda: urlopen(req, timeout=20).read(), 20)
        assert response is not None
        assert "is now open" in response.decode("utf-8")


servers = {}


def check_tcp_port_forward(
    test, remote_host, local_port, remote_port, fail_on_error=True, return_server=[]
):
    text = "ping"

    s = servers[local_port] if local_port in servers else SimpleTcpServer(local_port)
    return_server.append(s)
    servers[local_port] = s
    try:
        s.runThreaded()
        # Connect to local service directly
        cl = SimpleTcpClient("127.0.0.1", local_port)
        response = cl.send(text).strip()
        if not fail_on_error and text != response:
            return False
        else:
            test.assertEqual(text, response)
        cl.close()
        print("local server ok")

        sleep(3)

        # Connect to remote service
        print(f"Connecting to {remote_host}:{remote_port}")
        cr = SimpleTcpClient(remote_host, remote_port)
        response = cr.send(text).strip()
        if not fail_on_error and text != response:
            return False
        else:
            test.assertEqual(text, response)

        cr.close()
        print("tcp portforward ok")
    except Exception as e:
        logger.error(e)
        logger.exception(e)
        if not fail_on_error:
            return False
        else:
            raise e
    finally:
        # s.close()
        pass
    return True


def start_openport_session(test, session):
    # openport = Openport()
    test.called_back_success = False
    test.called_back_error = False

    def start_openport():
        pass
        # openport.start_port_forward(session, server=test.test_server)

    thr = threading.Thread(target=start_openport)
    thr.setDaemon(True)
    thr.start()
    i = 0
    while i < 30 and (not test.called_back_success or session.server_port < 0):
        if test.called_back_error:
            test.fail("error call back!")
        sleep(1)
        i += 1
    test.assertTrue(test.called_back_success, "not called back in time")
    print("called back after %s seconds" % i)
    # return openport
    return None


def set_default_args(app, db_location=None):
    app.args.local_port = -1
    app.args.register_key = ""
    app.args.port = -1

    app.args.manager_port = 8001
    app.args.start_manager = True
    app.args.database = db_location
    app.args.request_port = -1
    app.args.request_token = ""
    app.args.verbose = True
    app.args.http_forward = False
    app.args.server = "http://test.openport.be"
    app.args.restart_on_reboot = False
    app.args.no_manager = False
    app.args.config_file = ""
    app.args.list = False
    app.args.kill = 0
    app.args.kill_all = False
    app.args.restart_shares = False
    app.args.listener_port = -1
    app.args.forward_tunnel = False
    app.args.remote_port = -1
    app.args.ip_link_protection = None
    app.args.create_migrations = False
    app.args.daemonize = False


def get_ip():
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    result = s.getsockname()[0]
    s.close()
    return result


def get_nr_of_shares_in_db_file(db_file):
    db_handler = dbhandler.DBHandler(db_file)
    try:
        return len(db_handler.get_active_shares())
    except:
        return 0


def print_shares_in_db(db_file):
    db_handler = dbhandler.DBHandler(db_file)
    t = PrettyTable(
        [
            "server",
            # "ssh_server",
            "remote_port",
            "session_token",
            "local_port",
            # "forward_tunnel",
            "pid",
            "active",
            "http_forward",
            "http_forward_address",
            "open_port_for_ip_link",
            "restart_command",
        ]
    )

    for s in db_handler.get_active_shares():
        t.add_row(
            [
                s.server,
                # s.ssh_server,
                s.server_port,
                s.server_session_token,
                s.local_port,
                # s.forward_tunnel,
                s.pid,
                s.active,
                s.http_forward,
                s.http_forward_address,
                s.open_port_for_ip_link,
                "",  # s.restart_command,
            ]
        )
    print(t)


def get_toxi_mysql():
    import toxiproxy

    # make sure you've run
    # docker-compose -f docker-compose/toxiproxy.yaml up
    server = toxiproxy.Toxiproxy()
    server.destroy_all()
    return "127.0.0.1:33306", server.create(
        name="mysql_proxy", upstream=f"mysql:3306", enabled=True, listen="0.0.0.0:33306"
    )


def get_public_key() -> str:
    """read the public ssh key from the current user"""
    with open(os.path.expanduser("~/.ssh/id_rsa.pub")) as f:
        return f.read()


if __name__ == "__main__":
    address, client = get_toxi_mysql()
    # client.add_toxic(type='latency', attributes=dict(latency=5000, jitter=0))
    toxics = client.toxics()
    print(toxics)
