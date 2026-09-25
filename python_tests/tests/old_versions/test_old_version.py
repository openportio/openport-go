import dataclasses
import logging
import os
import subprocess
import threading
from datetime import datetime, timedelta
from multiprocessing.pool import ThreadPool
from pathlib import Path
from time import sleep
from unittest import TestCase, skip

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

# Dedicated keypair for the upgrade test, so it does not depend on the
# developer's personal ~/.ssh keys. Generated on first use; the lock keeps
# concurrent pool workers from racing ssh-keygen on the same path.
TEST_SSH_KEY = OLD_VERSION_DIR / "test_id_rsa"
TEST_SSH_KEY_LOCK = threading.Lock()


def get_test_ssh_key() -> Path:
    with TEST_SSH_KEY_LOCK:
        if not TEST_SSH_KEY.exists():
            subprocess.run(
                [
                    "ssh-keygen",
                    "-t",
                    "rsa",
                    "-b",
                    "3072",
                    "-N",
                    "",
                    "-f",
                    str(TEST_SSH_KEY),
                ],
                check=True,
            )
    return TEST_SSH_KEY


LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Image build behaviour (env OPENPORT_TEST_BUILD):
#   always (default) rebuild everything - cheap now that the build context is
#          small, and always picks up Dockerfile changes
#   auto   build only images that do not exist locally; keeps using an
#          outdated existing image after a Dockerfile change
#   never  fail fast when an image is missing instead of building it
BUILD_MODE = os.environ.get("OPENPORT_TEST_BUILD", "always")

UPGRADE_TIMEOUT = 600  # the upgrade flow installs packages over the tunnel


@dataclasses.dataclass
class Version:
    version: str
    extra_args: str = ""
    timeout: int = 60
    help_exit_code: int = 0
    test_started: datetime = None
    # Ubuntu releases this client version is tested on; see the comment on
    # OldVersionsTest.VERSIONS for how the pairing is chosen.
    ubuntu_versions: tuple = ("24.04",)


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

    # Versions still seen in the field (ELK, 2026-08). Each version is paired
    # with every Ubuntu LTS release that was in standard (5-year) support at
    # some point while that client version was the newest one available —
    # i.e. between its release and the release of its successor. Users
    # install "the current version" on whatever supported LTS they run, so an
    # LTS released mid-window counts too.
    #
    # Availability dates come from the Last-Modified headers of the .deb
    # files on https://openport.io/static/releases/ (what Linux users could
    # actually download), except 2.2.2 whose deb was re-uploaded in Dec 2025
    # for the certificate re-signing — its git tag date is used instead.
    # 1.1.0's successor is 1.1.1 (2018-09-02); 1.3.0's is the 2.0.2 deb
    # (2021-01-21) because 1.4.0 was never published as a deb.
    #
    #   version  available   superseded   LTS in support during window
    #   1.1.0    2016-05-28  2018-09-02   12.04, 14.04, 16.04, 18.04
    #   1.3.0    2020-02-25  2021-01-21   16.04, 18.04, 20.04
    #   2.0.2    2021-01-21  2021-10-11   16.04, 18.04, 20.04
    #   2.0.3    2021-10-11  2021-12-13   18.04, 20.04
    #   2.0.4    2021-12-13  2022-06-08   18.04, 20.04, 22.04
    #   2.1.0    2022-06-08  2024-01-09   18.04, 20.04, 22.04
    #   2.2.0    2024-01-09  2024-05-21   20.04, 22.04, 24.04
    #   2.2.1    2024-05-21  2024-10-04   20.04, 22.04, 24.04
    #   2.2.2    2024-10-04  2026-02-12   20.04, 22.04, 24.04
    #   2.2.3    2026-02-12  (current)    22.04, 24.04, 26.04
    #
    # Keep the tuples in ascending order: several tests use
    # ubuntu_versions[-1] as "the newest OS this version shipped for".
    # 1.0.0 is also still seen in the field, but its package is no longer
    # downloadable, so it cannot be tested.
    # version 1.0.2, 1.1.1 and 1.2.0 are no longer supported because of expired built-in CA certificates.

    VERSIONS = [
        Version(
            "1.1.0", "", 180, ubuntu_versions=("12.04", "14.04", "16.04", "18.04")
        ),
        Version("1.3.0", "", 180, ubuntu_versions=("16.04", "18.04", "20.04")),
        Version(
            "2.0.2", "--keep-alive 2", 180, 2, ubuntu_versions=("16.04", "18.04", "20.04")
        ),
        Version("2.0.3", "--keep-alive 2", 180, 2, ubuntu_versions=("18.04", "20.04")),
        Version(
            "2.0.4", "--keep-alive 2", 180, 2, ubuntu_versions=("18.04", "20.04", "22.04")
        ),
        Version(
            "2.1.0", "--keep-alive 2", 180, 2, ubuntu_versions=("18.04", "20.04", "22.04")
        ),
        Version(
            "2.2.0", "--keep-alive 2", 30, 0, ubuntu_versions=("20.04", "22.04", "24.04")
        ),
        Version(
            "2.2.1", "--keep-alive 2", 30, 0, ubuntu_versions=("20.04", "22.04", "24.04")
        ),
        Version(
            "2.2.2", "--keep-alive 2", 30, 0, ubuntu_versions=("20.04", "22.04", "24.04")
        ),
        Version(
            "2.2.3", "--keep-alive 2", 30, 0, ubuntu_versions=("22.04", "24.04", "26.04")
        ),
    ]

    def test_old_version(self):
        pool = ThreadPool(processes=10)
        results = []
        for version in self.VERSIONS:
            for ubuntu_version in version.ubuntu_versions:
                result = pool.apply_async(
                    self.start_and_check_port_forward, (version, ubuntu_version, 60)
                )
                results.append((version, ubuntu_version, result))

        for version, ubuntu_version, result in results:
            with self.subTest(version=version.version, ubuntu_version=ubuntu_version):
                # get() re-raises the worker's exception (with its traceback),
                # unlike successful() which only reports True/False.
                result.get(timeout=get_timeout(version))

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.osinteraction = osinteraction.getInstance()
        cls.docker_client = docker.from_env()

        for version in cls.VERSIONS:
            for ubuntu_version in version.ubuntu_versions:
                tag = f"openport-client:{ubuntu_version}_{version.version}"

                if BUILD_MODE != "always":
                    try:
                        cls.docker_client.images.get(tag)
                        continue
                    except docker.errors.ImageNotFound:
                        if BUILD_MODE == "never":
                            raise Exception(
                                f"Image {tag} does not exist and "
                                f"OPENPORT_TEST_BUILD=never; run once with "
                                f"OPENPORT_TEST_BUILD=always to build it."
                            )

                # The Dockerfile uses nothing from the build context (it wgets
                # the deb), so keep the context to this directory - a context of
                # ".." tars the whole repo (~1.5GB) into the daemon per image.
                stream = cls.docker_client.api.build(
                    dockerfile=f"{OLD_VERSION_DIR}/Dockerfile",
                    path=str(OLD_VERSION_DIR),
                    tag=tag,
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
            try:
                container.stop()
                if not container.attrs["HostConfig"]["AutoRemove"]:
                    container.remove()
            except docker.errors.NotFound:
                pass  # auto-removed containers can be gone already

    def test_old_version__port_22_blocked(self):
        known_issues = []
        versions = self.VERSIONS

        pool = ThreadPool(processes=20)
        results = []
        for version in versions:
            ubuntu_version = version.ubuntu_versions[-1]
            result = pool.apply_async(
                self.check_old_version__port_22_blocked, (version, ubuntu_version)
            )
            results.append((version, ubuntu_version, result))

        for version, ubuntu_version, result in results:
            with self.subTest(version=version.version, ubuntu_version=ubuntu_version):
                if (version.version, ubuntu_version) in known_issues:
                    result.wait(timeout=get_timeout(version))
                    self.assertFalse(result.successful())
                else:
                    # get() re-raises the worker's exception, showing the cause.
                    result.get(timeout=get_timeout(version))

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

    @skip
    def test_load_test(self):
        self.maxDiff = None
        amount_of_clients = 250
        version = max(self.VERSIONS, key=lambda x: x.version)
        ports_to_container = {}
        ports = list(range(20000, 20000 + amount_of_clients))

        def start_container(port):
            container = self.start_container(port, version, version.ubuntu_versions[-1])
            ports_to_container[port] = container

        pool = ThreadPool(processes=1000)

        def check(port):
            try:
                self.check_port_forward(
                    ports_to_container[port], port, get_link_timeout=120
                )
            except Exception:
                pass  # collected in self.errors

        pool.map(start_container, ports)
        pool.map(check, ports_to_container.keys())

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
            try:
                container.stop()
            except docker.errors.NotFound:
                pass  # auto-removed containers can be gone already
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
            # The sleep must outlast the whole upgrade flow (UPGRADE_TIMEOUT),
            # or the container auto-removes itself mid-test on a slow run.
            # It still acts as a fallback cleanup if stopping the container fails.
            command=f"sleep {UPGRADE_TIMEOUT + 120}",
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
            raise
        finally:
            container.stop()
            self.containers.remove(container)

    def test_upgrade(self):
        upgrade_version = "2.2.3"

        # Upgrading from 1.1.0 is broken regardless of OS; the entry tracks
        # ubuntu_versions[-1] for that version.
        known_issues = [
            ("1.1.0", "18.04"),
        ]
        pool = ThreadPool(processes=20)
        results = []
        for version in self.VERSIONS:
            ubuntu_version = version.ubuntu_versions[-1]

            result = pool.apply_async(
                self.start_and_check_upgrade, (version, ubuntu_version, upgrade_version)
            )
            results.append((version, ubuntu_version, result))
        for version, ubuntu_version, result in results:
            with self.subTest(version=version.version, ubuntu_version=ubuntu_version):
                if (version.version, ubuntu_version) in known_issues:
                    # A known issue may fail or hang; it must just not succeed.
                    result.wait(timeout=UPGRADE_TIMEOUT)
                    if result.ready():
                        self.assertFalse(result.successful())
                else:
                    # get() re-raises the worker's exception, showing the cause.
                    # The version timeouts are tuned for the quick port-forward
                    # check; upgrading (apt install over the tunnel) takes minutes.
                    result.get(timeout=UPGRADE_TIMEOUT)

    def start_ssh_server(self, container: docker.models.containers.Container):
        public_ssh_key_content = get_test_ssh_key().with_suffix(".pub").read_text()
        self.run_command(container, "mkdir -p /root/.ssh")
        self.run_command(
            container,
            f"""bash -c "echo '{public_ssh_key_content}' >> /root/.ssh/authorized_keys" """,
        )
        self.run_command(container, "chmod 700 /root/.ssh -R")
        self.run_command(container, "chmod 600 /root/.ssh/authorized_keys")
        self.run_command(container, "mkdir -p /var/run/sshd")
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
        ssh_command = (
            f"ssh root@{remote_host} -p {remote_port} "
            f"-i {get_test_ssh_key()} -o IdentitiesOnly=yes "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '{command}'"
        )
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

    def wait_for_ssh_echo(self, remote_host, remote_port, timeout=60):
        """Retry check_ssh_echo until the tunnel is reachable. After
        restart-sessions the client needs a few seconds to re-establish the
        tunnel; until then the ssh connection is refused."""

        def try_echo():
            try:
                self.check_ssh_echo(remote_host, remote_port)
                return True
            except AssertionError as e:
                logging.info("ssh echo not up yet: %s", e)
                return False

        wait_for_response(try_echo, timeout=timeout)

    def start_and_check_upgrade(self, version, ubuntu_version, upgrade_version):
        version.test_started = datetime.now()

        container = self.start_container_as_sleeping(version, ubuntu_version)
        try:
            port = 22
            self.start_ssh_server(container)
            # old version
            stream = self.start_openport(container, port)
            # 10 versions connect to the test server concurrently; 15s was not
            # always enough for the slower/older clients to get their tunnel up.
            remote_host, remote_port, link = (
                get_remote_host_and_port__docker_exec_result(stream, timeout=60)
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
            # Clicking the link only talks to the server; the restarted
            # client may not have its tunnel up yet, so retry the ssh check.
            self.wait_for_ssh_echo(remote_host, remote_port)
        finally:
            self.stop_container_in_thread(container)
