import configparser
import logging
import logging.handlers
import os

# Get the directory of the current script
script_dir = os.path.dirname(os.path.realpath(__file__))

# Construct the paths relative to the script directory
APP_LOGFILE = os.path.join(script_dir, "../application.log")
AUDIT_LOGFILE = os.path.join(script_dir, "../audit.log")
CONFIG_FILE = os.path.join(script_dir, "../conf/sucm_conf.ini")

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
