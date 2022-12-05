import requests

from tests.utils.logger_service import get_logger

logger = get_logger("server")


def send_exit(share, force=False):
    port = share.app_management_port
    logger.debug("Sending exit to %s." % port)
    url = "http://127.0.0.1:%s/exit" % (port,)
    logger.debug("sending get request " + url)
    try:
        data = {"id": share.id, "force": force}
        r = requests.post(url, data=data, timeout=1)
        if r.text.strip() != "ok":
            logger.error(r.text)
    except Exception as detail:
        logger.error("An error has occurred while killing the app: %s" % detail)


def is_running(share, print_error=False):
    port = share.app_management_port
    logger.debug("Sending info to %s." % port)
    url = "http://127.0.0.1:%s/info" % (port,)
    logger.debug("sending get request " + url)
    try:
        r = requests.get(url, timeout=1)
        if r.text.splitlines()[0].strip() != "openport":
            print(r.text)
            logger.error(r.text)
            return False
        return True
    except Exception as detail:
        logger_function = logger.error if print_error else logger.debug
        logger_function(
            "An error has occurred while getting info from the app: %s" % detail
        )
        return False
