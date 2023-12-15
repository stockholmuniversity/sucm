import configparser
import logging
import logging.handlers
import os
import sys

# Get the root directory of the virtual environment
venv_root = sys.prefix

# Construct the paths relative to the virtual environment root
APP_LOGFILE = os.path.join(venv_root, "application.log")
AUDIT_LOGFILE = os.path.join(venv_root, "audit.log")
CONFIG_FILE = os.path.join(venv_root, "conf", "sucm_conf.ini")

# This will clear the log file content
with open(APP_LOGFILE, "w", encoding="utf-8"):
    pass

# Setup for application logs to file
app_logger = logging.getLogger("application_logger")
app_logger.setLevel(logging.INFO)
app_handler = logging.FileHandler(APP_LOGFILE)
app_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
app_logger.addHandler(app_handler)

# Setup for system logs to syslog
sys_logger = logging.getLogger("system_logger")
sys_logger.setLevel(logging.INFO)
syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
syslog_handler.setFormatter(logging.Formatter("SUCM: %(message)s"))
sys_logger.addHandler(syslog_handler)

# Setup for audit logs to file
audit_logger = logging.getLogger("audit_logger")
audit_logger.setLevel(logging.INFO)
audit_handler = logging.FileHandler(AUDIT_LOGFILE)
audit_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
audit_logger.addHandler(audit_handler)

# SUCM Configparser
cfg = configparser.ConfigParser()
cfg.read(CONFIG_FILE)
