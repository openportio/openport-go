import dataclasses
import logging
from pathlib import Path
from unittest import TestCase

import docker

from tests.test_utils import (
    click_open_for_ip_link,
    check_tcp_port_forward,
    get_remote_host_and_port__docker,
)
from tests.utils import osinteraction

TEST_SERVER = "https://test.openport.io"
# TEST_SERVER = "https://openport.io"

OLD_VERSION_DIR = Path(__file__).parent / "old_versions"


@dataclasses.dataclass
class Version:
    version: str
    extra_args: str = ""
    timeout: int = 30
    help_exit_code: int = 0


class OldVersionsTest(TestCase):
    VERSIONS = [
        Version("1.0.1", "", 60),  # fails, no longer used
        Version("1.0.2", "", 180),  # works
        Version("1.1.0", "", 180),  # works
        Version("1.1.1", "", 180),  # works
        Version("1.2.0", "", 180),  # works
        Version("1.2.0", "", 180),  # works
        Version("1.3.0", "", 180),  # works
        Version("2.0.2", "--keep-alive 2", 180, 2),  # works
        Version("2.0.3", "--keep-alive 2", 180, 2),  # works
        Version("2.0.4", "--keep-alive 2", 180, 2),  # works
        Version("2.1.0", "--keep-alive 2", 180, 2),  # works
        Version("2.2.0", "--keep-alive 2", 30, 0),  # works
    ]

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.osinteraction = osinteraction.getInstance()
        cls.docker_client = docker.from_env()

        for version in cls.VERSIONS:
            stream = cls.docker_client.api.build(
                dockerfile=f"{OLD_VERSION_DIR}/Dockerfile",
                path=".",
                tag=f"openport-client:{version.version}",
                buildargs={"OPENPORT_VERSION": version.version},
            )

            for line in stream:
                print(line)

            container = cls.docker_client.containers.run(
                f"openport-client:{version.version}",
                detach=True,
                command="openport --help",
            )
            logs = container.logs()
            try:
                print("\n".join(logs))
            except Exception:
                logging.exception(f"Failed to get logs: {logs}")

    def setUp(self) -> None:
        self.osinteraction = osinteraction.getInstance()
        self.containers = []

    def tearDown(self) -> None:
        for container in self.containers:
            container.stop()
            container.remove()

    def test_old_version(self):
        docker_client = docker.from_env()
        for version in self.VERSIONS:
            with self.subTest(version=version.version):
                port = self.osinteraction.get_open_port()

                container = docker_client.containers.run(
                    f"openport-client:{version.version}",
                    detach=True,
                    command=f"openport {port} --server {TEST_SERVER} --verbose "
                    + version.extra_args,
                    network="host",
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

    def test_old_version__port_22_blocked(self):
        docker_client = docker.from_env()
        for version in self.VERSIONS:
            with self.subTest(version=version.version):
                port = self.osinteraction.get_open_port()

                container = docker_client.containers.run(
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
