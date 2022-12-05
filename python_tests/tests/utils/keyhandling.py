import paramiko

from io import StringIO
from tests.utils.logger_service import get_logger

log = get_logger(__name__)


def create_new_key_pair(length=1024):
    key = paramiko.RSAKey.generate(length)

    private_key = StringIO()
    key.write_private_key(private_key)
    private_key.seek(0)

    pk = paramiko.RSAKey(file_obj=private_key)
    import getpass

    username = getpass.getuser()
    public_key = "ssh-rsa %s %s \n" % (pk.get_base64(), username)

    return private_key.getvalue(), public_key
