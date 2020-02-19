import subprocess
from time import sleep

from openport.apps.openport_app_version import VERSION


def print_progress(process):
    for line in process.communicate():
        if line:
            print(line)


def run_command(c):
    p = subprocess.Popen(c, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    while p.returncode is None:
        print_progress(p)
        sleep(1)
    print_progress(p)
    return c


command = ["C:\Program Files (x86)\NSIS\makensis.exe", "/DVERSION=%s" % VERSION, "clean.nsi"]
print command
run_command(command)

# signtool_path = "C:\\Program\ Files\\Microsoft\ SDKs\\Windows\\v7.1\\bin\\signtool.exe"
signtool_path = "C:/Program Files (x86)/Windows Kits/10/bin/x64/signtool.exe"

# As admin, run 'mmc.exe'
# From 'file' add snap in 'certificates' for 'this computer'
# From 'Certificates > more actions' click 'import'
# Browse to the Danger Software.p12 certificate
# Add it to 'Trusted Root Certification Authorities' and to 'Personal'

command = [signtool_path, 'sign', '/sm', '/a', '/v', '/sm', '/s', 'My', '/n', 'Danger Software',
           'openport_%s.exe' % VERSION]
print '" "'.join(command)
run_command(command)

with open('hash-windows.md5', 'wb') as f:
    output = run_command(['md5sum', 'Openport_%s.exe' % VERSION])[0]
    f.write(output.replace('\r\n', '\n'))

# raw_input("press any key to continue...")
