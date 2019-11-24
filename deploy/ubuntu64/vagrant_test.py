import subprocess
from time import sleep
from unittest import TestCase


def run_command(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        print(output)
        return output
    except subprocess.CalledProcessError as e:
        print(e.output)
        raise

class VagrantTest(TestCase):
    @classmethod
    def setUpClass(cls):
        super(VagrantTest, cls).setUpClass()
        run_command('cp ../../debian/openport_*-1_amd64.deb .')
        run_command("vagrant up")

    @classmethod
    def tearDownClass(cls):
        super(VagrantTest, cls).tearDownClass()
        run_command("vagrant destroy -f")

    def test_restart_on_reboot(self):
        sleep(10)
        run_command("vagrant ssh -c 'sudo reboot' || true")
        sleep(10)
        output = run_command("vagrant ssh -c 'ps aux|grep openport|grep -v grep'")
        self.assertIn('openport 22', output)
