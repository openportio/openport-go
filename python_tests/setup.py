import os

from setuptools import setup, find_packages

install_reqs = [
    "paramiko==2.7.1",
    "CherryPy==8.1.2",
    "SQLAlchemy==1.3.13",
    "argparse==1.4.0",
    "bottle==0.12.10",
    "cryptography==2.8",
    "ipaddress==1.0.17",
    "lockfile==0.12.2",
    "prettytable==3.3.0",
    "psutil==4.3.1",
    "pyOpenSSL==18.0.0",
    "pycrypto==2.6.1",
    "requests[socks]==2.23.0",
    "six==1.10.0",
    "pysocks==1.7.1",
    "setuptools==45.2.0",
    "supervisor==4.1.0",
]


def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join("..", path, filename))
    return paths


setup(
    name="openport",
    version="1.0",
    description="Official Openport Client",
    author="Jan De Bleser",
    author_email="jan@openport.io",
    install_requires=install_reqs,
    url="https://openport.io",
    packages=find_packages(),
    package_data={"": package_data},
)
