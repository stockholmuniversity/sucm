from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler

from .sucm_certificate import SucmCertificate
from .sucm_common import send_email, sucm_secret
from .sucm_notifygroup import SucmNotifyGroup
from .sucm_settings import (APP_LOGFILE, app_logger, audit_logger, cfg,
                            sys_logger)


def job_function():
    app_logger.info("Job started!")
    certs_to_renew = SucmCertificate().get_renewable_certs()
    certs_to_remove = SucmCertificate().get_expired_certs()
    if certs_to_renew:
        for cert in certs_to_renew:
            if cert["cert_type"] == "Manual":
                emailaddresses = SucmNotifyGroup().get_notifygroup_detail(
                    cert["notify_group"]
                )[2]
                for email in emailaddresses.replace(" ", "").split(","):
                    send_email(
                        cert["common_name"] + " needs manual intervention in SUCM",
                        cert["common_name"] + " needs to be renewed",
                        email,
                    )
                    app_logger.info(
                        cert["common_name"]
                        + ": Email has been sent to "
                        + email
                        + " to request manual intervention."
                    )
            else:
                cert = SucmCertificate(cert_id=cert["cert_id"])
                cert.set_current_class_values_from_db()
                cert.create_new_key_and_csr()
                cert.renew_cert_with_csr()
                app_logger.info(
                    cert.common_name
                    + " has been renewed automatically and pushed to vault."
                )
                del cert

    if certs_to_remove:
        for active_cert in certs_to_remove:
            SucmCertificate().delete_active_cert(
                active_cert_id=active_cert["active_cert_id"]
            )
            app_logger.info(
                "Certificate for "
                + active_cert["common_name"]
                + " that expired "
                + active_cert["expiry_date"]
                + " has been removed from the database, since it is no longer valid."
            )

    global LAST_RUN
    app_logger.info("Job completed!")
    LAST_RUN = datetime.datetime.now()


def start_scheduler():
    app_logger.info("Scheduler started with an interval of 10 minutes.")
    scheduler = BackgroundScheduler()
    scheduler.add_job(job_function, "interval", minutes=10)
    scheduler.start()
