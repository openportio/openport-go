import dataclasses
import logging
import subprocess
import threading
from datetime import datetime, timedelta
from multiprocessing.pool import ThreadPool
from pathlib import Path
from time import sleep
from unittest import TestCase

import docker

from tests.utils.utils import (
    click_open_for_ip_link,
    check_tcp_port_forward,
    get_remote_host_and_port__docker,
    get_remote_host_and_port__docker_exec_result,
    wait_for_response,
)
from tests.utils import osinteraction

TEST_SERVER = "https://test.openport.io"
# TEST_SERVER = "https://openport.io"

OLD_VERSION_DIR = Path(__file__).parent

LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

SKIP_BUILD = False


@dataclasses.dataclass
class Version:
    version: str
    extra_args: str = ""
    timeout: int = 60
    help_exit_code: int = 0
    test_started: datetime = None


def get_timeout(version: Version):
    if version.test_started:
        timeout = max(
            0, version.timeout - (datetime.now() - version.test_started).seconds
        )
    else:
        timeout = version.timeout
    logging.info("Timeout for version %s: %s", version.version, timeout)

    return timeout


class OldVersionsTest(TestCase):

    UBUNTU_VERSIONS = [
        "16.04",
        "18.04",
        "20.04",
        "22.04",
        "24.04",
    ]

    VERSIONS = [
        # Version("1.0.1", "", 60),  # fails, no longer used
        Version("1.0.2", "", 180),  # works
        Version("1.1.0", "", 180),  # works
        Version("1.1.1", "", 180),  # works
        Version("1.2.0", "", 180),  # works
        Version("1.3.0", "", 180),  # works
        Version("2.0.2", "--keep-alive 2", 180, 2),  # works
        Version("2.0.3", "--keep-alive 2", 180, 2),  # works
        Version("2.0.4", "--keep-alive 2", 180, 2),  # works
        Version("2.1.0", "--keep-alive 2", 180, 2),  # works
        Version("2.2.0", "--keep-alive 2", 30, 0),  # works
        Version("2.2.1", "--keep-alive 2", 30, 0),  # works
        Version("2.2.2", "--keep-alive 2", 30, 0),  # works
    ]

    def test_old_version(self):
        skip_versions = [
            ("2.2.0", "16.04"),
            ("2.2.0", "18.04"),
            ("2.2.1", "16.04"),
            ("2.2.1", "18.04"),
        ]

        pool = ThreadPool(processes=10)
        results = []
        for version in self.VERSIONS:
            for ubuntu_version in self.UBUNTU_VERSIONS:
                if (version.version, ubuntu_version) in skip_versions:
                    continue
                result = pool.apply_async(
                    self.start_and_check_port_forward, (version, ubuntu_version, 60)
                )
                results.append((version, ubuntu_version, result))

        for version, ubuntu_version, result in results:
            with self.subTest(version=version.version, ubuntu_version=ubuntu_version):
                result.wait(timeout=get_timeout(version))
                self.assertTrue(result.successful())

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.osinteraction = osinteraction.getInstance()
        cls.docker_client = docker.from_env()

        if not SKIP_BUILD:

            for version in cls.VERSIONS:
                for ubuntu_version in cls.UBUNTU_VERSIONS:
                    stream = cls.docker_client.api.build(
                        dockerfile=f"{OLD_VERSION_DIR}/Dockerfile",
                        path="..",
                        tag=f"openport-client:{ubuntu_version}_{version.version}",
                        buildargs={
                            "OPENPORT_VERSION": version.version,
                            "UBUNTU_VERSION": ubuntu_version,
                        },
                    )

                    for line in stream:
                        print(line)

                    # try:
                    #     container = cls.docker_client.containers.run(
                    #         f"openport-client:{ubuntu_version}_{version.version}",
                    #         detach=True,
                    #         command="openport --help",
                    #     )
                    #     logs = container.logs()
                    #     try:
                    #         if isinstance(logs, bytes):
                    #             logs = [logs.decode("utf-8")]
                    #         elif isinstance(logs, str):
                    #             logs = [logs]
                    #         logging.info("\n".join([str(x) for x in logs]))
                    #     except Exception:
                    #         logging.exception(f"Failed to get logs: {logs}")
                    # except Exception as e:
                    #     logging.exception(e)

    def setUp(self) -> None:
        self.osinteraction = osinteraction.getInstance()
        self.docker_client = docker.from_env()
        self.containers = []
        self.errors = []

    def tearDown(self) -> None:
        for container in self.containers:
            container.stop()
            if not container.attrs["HostConfig"]["AutoRemove"]:
                container.remove()

    def test_old_version__port_22_blocked(self):
        ubuntu_version = "20.04"
        known_issues = []
        versions = self.VERSIONS

        pool = ThreadPool(processes=20)
        results = []
        for version in versions:
            result = pool.apply_async(
                self.check_old_version__port_22_blocked, (version, ubuntu_version)
            )
            results.append((version, ubuntu_version, result))

        for version, ubuntu_version, result in results:
            with self.subTest(version=version.version, ubuntu_version=ubuntu_version):
                result.wait(timeout=get_timeout(version))
                if (version.version, ubuntu_version) in known_issues:
                    self.assertFalse(result.successful())
                else:
                    self.assertTrue(result.successful())

    def check_old_version__port_22_blocked(self, version, ubuntu_version):
        version.test_started = datetime.now()

        port = self.osinteraction.get_open_port()

        container = self.docker_client.containers.run(
            f"openport-client:{ubuntu_version}_{version.version}",
            detach=True,
            command=f"/app/block_port_and_run_openport.sh {port} --server {TEST_SERVER} --verbose "
            + version.extra_args,
            # network="host",  # do not use network="host" because it will add iptables rules to the host.
            volumes=[
                f"{OLD_VERSION_DIR}/:/app/",
            ],
            environment={
                "SERVER": TEST_SERVER.split("://")[1].split(":")[0],
                "PORT": port,
            },
            privileged=True,
            extra_hosts=["host.docker.internal:host-gateway"],
        )
        try:
            self.containers.append(container)
            remote_host, remote_port, link = get_remote_host_and_port__docker(
                container, timeout=version.timeout
            )

            self.assertIsNotNone(link)
            click_open_for_ip_link(link)
            check_tcp_port_forward(
                self,
                remote_host=remote_host,
                local_port=port,
                remote_port=remote_port,
            )
        finally:
            self.stop_container_in_thread(container)

    def test_load_test(self):
        self.maxDiff = None
        amount_of_clients = 250
        version = max(self.VERSIONS, key=lambda x: x.version)
        ports_to_container = {}
        ports = list(range(20000, 20000 + amount_of_clients))

        def start_container(port):
            container = self.start_container(port, version, "20.04")
            ports_to_container[port] = container

        pool = ThreadPool(processes=1000)

        pool.map(start_container, ports)
        pool.map(
            lambda x: self.check_port_forward(
                ports_to_container[x], x, get_link_timeout=120
            ),
            ports_to_container.keys(),
        )

        self.assertListEqual([], self.errors)

    def start_and_check_port_forward(
        self, version: Version, ubuntu_version: str, get_link_timeout=15
    ):
        version.test_started = datetime.now()
        port = self.osinteraction.get_open_port()
        container = self.start_container(port, version, ubuntu_version)
        try:
            self.check_port_forward(container, port, get_link_timeout=get_link_timeout)
        finally:
            self.stop_container_in_thread(container)

    def stop_container_in_thread(self, container):
        def do():
            container.stop()
            if container in self.containers:
                self.containers.remove(container)

        threading.Thread(target=do, daemon=False).start()

    def start_container(self, port, version, ubuntu_version):
        self.assertIsNotNone(port)
        container = self.docker_client.containers.run(
            f"openport-client:{ubuntu_version}_{version.version}",
            detach=True,
            command=f"nice -n 19 openport {port} --server {TEST_SERVER} --verbose  "
            + version.extra_args,
            network="host",
            remove=True,
        )
        self.containers.append(container)
        return container

    def start_container_as_sleeping(self, version, ubuntu_version):
        container = self.docker_client.containers.run(
            f"openport-client:{ubuntu_version}_{version.version}",
            detach=True,
            command=f"sleep 180",  # sleep for 3 minutes
            remove=True,
        )
        self.containers.append(container)
        return container

    def check_port_forward(self, container, port, get_link_timeout=15):
        remote_host, remote_port, link = get_remote_host_and_port__docker(
            container, timeout=get_link_timeout
        )
        try:
            # self.assertIsNone(link)
            self.assertIsNotNone(link)
            click_open_for_ip_link(link)
            stop = datetime.now() + timedelta(seconds=30)
            while True:
                try:
                    check_tcp_port_forward(
                        self,
                        remote_host=remote_host,
                        local_port=port,
                        remote_port=remote_port,
                    )
                    break
                except Exception:
                    if datetime.now() > stop:
                        raise
                    sleep(1)

        except Exception as e:
            logging.exception(f"Failed: {port} -> {remote_host}:{remote_port} - {link}")
            self.errors.append(e)
            # raise
        finally:
            container.stop()
            self.containers.remove(container)

    def test_upgrade(self):
        upgrade_version = "2.2.2"

        known_issues = [
            ("1.0.2", "20.04"),
            ("1.1.0", "20.04"),
        ]
        pool = ThreadPool(processes=20)
        results = []
        for version in self.VERSIONS:
            ubuntu_version = "20.04"

            result = pool.apply_async(
                self.start_and_check_upgrade, (version, ubuntu_version, upgrade_version)
            )
            results.append((version, ubuntu_version, result))
        for version, ubuntu_version, result in results:
            with self.subTest(version=version.version, ubuntu_version=ubuntu_version):
                result.wait(timeout=get_timeout(version))
                if (version.version, ubuntu_version) in known_issues:
                    try:
                        self.assertFalse(result.successful())
                    except Exception as e:
                        logging.exception(e)
                else:
                    self.assertTrue(result.successful())

    def start_ssh_server(self, container: docker.models.containers.Container):
        public_ssh_key_content = Path.home().joinpath(".ssh/id_rsa.pub").read_text()
        self.run_command(container, "mkdir -p /root/.ssh")
        self.run_command(
            container,
            f"""bash -c "echo '{public_ssh_key_content}' >> /root/.ssh/authorized_keys" """,
        )
        self.run_command(container, "chmod 700 /root/.ssh -R")
        self.run_command(container, "chmod 600 /root/.ssh/authorized_keys")
        self.run_command(container, "mkdir /var/run/sshd")
        self.run_command(container, "chmod 0755 /var/run/sshd")
        exit_code, output = self.run_command(
            # container, "bash -c '/usr/sbin/sshd -d > /tmp/sshd.log 2>&1 &'"
            container,
            "/usr/sbin/sshd",
        )
        self.assertEqual(exit_code, 0)

    def start_openport(self, container: docker.models.containers.Container, port: int):
        """Returns (exit_code, generator)"""
        return container.exec_run(
            f"openport {port} --server {TEST_SERVER} --verbose --restart-on-reboot",
            stream=True,
        )

    def upgrade_to_version_via_ssh(self, remote_host, remote_port, version: str):
        def do(command):
            self.run_ssh_command(remote_host, remote_port, command)

        do(f"wget https://openport.io/static/releases/openport_{version}-1_amd64.deb")
        do(f"dpkg -i openport_{version}-1_amd64.deb")
        # do('to killall openport ; openport restart-sessions ')

    def run_ssh_command(self, remote_host, remote_port, command):
        ssh_command = f"ssh root@{remote_host} -p {remote_port} -o StrictHostKeyChecking=no '{command}'"
        LOGGER.info(f"Running command: {ssh_command}")
        output = subprocess.run(ssh_command, shell=True, capture_output=True)
        LOGGER.info(output)
        self.assertEqual(output.returncode, 0, output)
        return output

    def kill_all_openport_processes(self, container):
        exit_code, output = container.exec_run("""openport kill-all""")
        self.assertEqual(exit_code, 0, output)

        def no_openport_running():
            exit_code, output = container.exec_run(
                """bash -c "ps aux|grep openport|grep -v grep|grep -v defunct" """
            )
            # self.assertEqual(0, exit_code)
            print(output)
            return not bool(output)

        if not wait_for_response(no_openport_running, timeout=5, throw=False):
            exit_code, output = container.exec_run(
                """bash -c "ps aux|grep openport|grep -v grep|awk '{print $2}'|xargs kill -9 " """
            )
            self.assertEqual(exit_code, 0, output)

    def run_command(self, container, command) -> tuple[int, bytes]:
        LOGGER.info(f"Running command: {command}")
        output = container.exec_run(command)
        LOGGER.info(output)
        self.assertEqual(output[0], 0, output[1])
        return output

    def check_ssh_echo(self, remote_host, remote_port):
        output = self.run_ssh_command(remote_host, remote_port, "echo hello")
        text = output.stdout
        self.assertEqual(
            text,
            b"hello\n",
        )

    def start_and_check_upgrade(self, version, ubuntu_version, upgrade_version):
        version.test_started = datetime.now()

        container = self.start_container_as_sleeping(version, ubuntu_version)
        try:
            port = 22
            self.start_ssh_server(container)
            # old version
            stream = self.start_openport(container, port)
            remote_host, remote_port, link = (
                get_remote_host_and_port__docker_exec_result(stream, timeout=15)
            )
            self.assertIsNotNone(link)
            click_open_for_ip_link(link)

            # upgrade
            self.upgrade_to_version_via_ssh(remote_host, remote_port, upgrade_version)
            # todo: check version of running application
            self.check_ssh_echo(remote_host, remote_port)

            self.kill_all_openport_processes(container)
            # sleep(5)
            self.run_command(container, f"openport restart-sessions -v")

            # sleep(2)

            def do_click():
                try:
                    click_open_for_ip_link(link)
                    return True
                except Exception as e:
                    logging.exception(e)
                    sleep(0.5)
                    return False

            wait_for_response(do_click)
            self.check_ssh_echo(remote_host, remote_port)
        finally:
            self.stop_container_in_thread(container)
