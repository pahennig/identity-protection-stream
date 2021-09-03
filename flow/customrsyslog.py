import logging
import logging.handlers
from rfc5424logging import Rfc5424SysLogHandler
import sys

SIEM = sys.argv[1]
SIEM_PORT = sys.argv[2]

def rfc5434_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    sh = Rfc5424SysLogHandler(address=(str(SIEM), int(SIEM_PORT)),msg_as_utf8=False)
    logger.addHandler(sh)
    return logger
