import dataclasses
import logging
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
)
from tests.utils import osinteraction

TEST_SERVER = "https://test.openport.io"
# TEST_SERVER = "https://openport.io"

OLD_VERSION_DIR = Path(__file__).parent


@dataclasses.dataclass
class Version:
    version: str
    extra_args: str = ""
    timeout: int = 30
    help_exit_code: int = 0


class OldVersionsTest(TestCase):

    UBUNTU_VERSIONS = [
        "16.04",
        "18.04",
        "20.04",
        "22.04",
        "24.04",
    ]

    VERSIONS = [
        # # Version("1.0.1", "", 60),  # fails, no longer used
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
        for version in self.VERSIONS:
            for ubuntu_version in self.UBUNTU_VERSIONS:
                with self.subTest(version=version.version, ubuntu_version=ubuntu_version):
                    self.start_and_check_port_forward(version, ubuntu_version)

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.osinteraction = osinteraction.getInstance()
        cls.docker_client = docker.from_env()

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
        for version in self.VERSIONS:
            with self.subTest(version=version.version):
                port = self.osinteraction.get_open_port()

                container = self.docker_client.containers.run(
                    f"openport-client:{version.version}",
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

    def test_load_test(self):
        self.maxDiff = None
        amount_of_clients = 100
        version = max(self.VERSIONS, key=lambda x: x.version)
        ports_to_container = {}
        ports = list(range(20000, 20000 + amount_of_clients))
        #
        # for i in range(amount_of_clients):
        #     port = None
        #
        #
        #     while port is None or port in ports or port > 32768:
        #         port = self.osinteraction.get_open_port()
        #     ports.append(port)

        def start_container(port):
            container = self.start_container(port, version)
            ports_to_container[port] = container

        pool = ThreadPool(processes=100)

        pool.map(start_container, ports)
        pool.map(
            lambda x: self.check_port_forward(x, ports_to_container[x]),
            ports_to_container.keys(),
        )

        self.assertListEqual([], self.errors)

    def start_and_check_port_forward(self, version: Version, ubuntu_version:str):
        port = self.osinteraction.get_open_port()
        container = self.start_container(port, version, ubuntu_version)
        try:
            self.check_port_forward(port, container)
        finally:
            container.stop()
            self.containers.remove(container)

    def start_container(self, port, version, ubuntu_version):
        self.assertIsNotNone(port)
        container = self.docker_client.containers.run(
            f"openport-client:{ubuntu_version}_{version.version}",
            detach=True,
            command=f"openport {port} --server {TEST_SERVER} --verbose  "
            + version.extra_args,
            network="host",
            remove=True,
        )
        self.containers.append(container)
        return container

    def check_port_forward(self, port, container):
        remote_host, remote_port, link = get_remote_host_and_port__docker(
            container, timeout=15
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
