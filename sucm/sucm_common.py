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
    plugin_module = importlib.import_module(f"sucm.plugins.{plugin_module_name}")

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


def send_email(ject, body, to, from_addr="m@se"):
    # Create a text/plain message
    msg = MIMEText(body)
    msg["Subject"] = ject
    msg["From"] = from_addr
    msg["To"] = to

    # Send the message via our own SMTP server.
    s = smtplib.SMTP("localhost")
    s.send_message(msg)
    s.quit()
