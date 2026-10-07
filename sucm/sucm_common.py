import importlib
import smtplib
from email.mime.text import MIMEText

from .sucm_db import SucmMysql
from .sucm_secret import SucmSecret
from .sucm_settings import cfg, sys_logger

sucm_db = SucmMysql()

# Load secrets backend based on configuration
plugin_class_name = cfg.get("SUCM", "secrets_backend_class")
plugin_module_name = cfg.get("SUCM", "secrets_backend_module")

try:
    # Dynamically import the module
    plugin_module = importlib.import_module(f"sucm.sucm_secret.{plugin_module_name}")

    # Fetch the class from the module
    plugin_class = getattr(plugin_module, plugin_class_name)

    # Check if the class is a subclass of SucmSecret
    if not issubclass(plugin_class, SucmSecret):
        raise TypeError("%s is not a subclass of SucmSecret", plugin_class_name)

    # Instantiate the class
    sucm_secret = plugin_class()

except ImportError as e:
    sys_logger.error("Error importing module: %s", e)
except AttributeError as e:
    sys_logger.error("Error accessing class %s in module: %s", plugin_class_name, e)
except TypeError as e:
    sys_logger.error(e)


def _sanitize_header(value):
    """Strip CR/LF so a caller-supplied value can never break out of its header
    and inject additional headers into the outbound message."""
    return str(value).replace("\r", " ").replace("\n", " ")


def send_email(ject, body, to, from_addr="noreply@su.se"):
    try:
        # Create a text/plain message. Recipients/subject are sanitized
        # against header injection (defense-in-depth - the notify-group save
        # path already validates the address CSV via validate_email_csv).
        msg = MIMEText(body)
        msg["Subject"] = _sanitize_header(ject)
        msg["From"] = _sanitize_header(from_addr)
        msg["To"] = _sanitize_header(to)

        # Send the message via our own SMTP server.
        s = smtplib.SMTP("localhost")
        s.send_message(msg)
        s.quit()
    except Exception as e:
        # Swallowed on purpose so the automation loop doesn't fail and skip
        # updating cert.status (which would cause it to re-mail the group
        # every 10 minutes for a cert pending manual renewal). Logged so the
        # failure is visible. Considered a temporary fix until a better one
        # comes along.
        sys_logger.error("Failed to send email to %s: %s", to, e)
