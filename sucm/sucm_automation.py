from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler

from .sucm_certificate import SucmCertificate
from .sucm_common import send_email
from .sucm_globals import state
from .sucm_notifygroup import SucmNotifyGroup
from .sucm_settings import app_logger

def retry_failed_fetch():
    certs_that_failed = SucmCertificate().get_fetch_failures()
    if certs_that_failed:
        for cert in certs_that_failed:
            try:
                cert_obj = SucmCertificate(cert_id=cert["cert_id"])
                cert_obj.set_current_class_values_from_db()
                cert_obj.renew_cert_with_csr()
                app_logger.info(
                    "%s has been renewed after previous fetch failure and is now pushed to vault.",
                    cert["common_name"],
                )
                del cert_obj
            except:
                return

def job_function():
    app_logger.info("Job started!")
    retry_failed_fetch()
    certs_to_renew = SucmCertificate().get_renewable_certs()
    certs_to_remove = SucmCertificate().get_expired_certs()
    if certs_to_renew:
        for cert in certs_to_renew:
            if cert["cert_type"] == "Manual":
                emailaddresses = SucmNotifyGroup().get_notifygroup_detail(
                    cert["notify_group"]
                )[2]
                cert_obj = SucmCertificate(cert_id=cert["cert_id"])
                cert_obj.set_current_class_values_from_db()
                if cert_obj.status != "Sent Email":
                    for email in emailaddresses.replace(" ", "").split(","):
                        send_email(
                            cert["common_name"] + " needs manual intervention in SUCM",
                            cert["common_name"] + " needs to be renewed",
                            email,
                        )
                        app_logger.info(
                            "%s: Email has been sent to %s to request manual intervention.",
                            cert["common_name"],
                            email,
                        )
                    cert_obj.status = "Sent Email"
                    cert_obj.commit_changes_to_db()
                    del cert_obj
            else:
                cert_obj = SucmCertificate(cert_id=cert["cert_id"])
                cert_obj.set_current_class_values_from_db()
                cert_obj.create_new_key_and_csr()
                cert_obj.renew_cert_with_csr()
                app_logger.info(
                    "%s has been renewed automatically and pushed to vault.",
                    cert["common_name"],
                )
                del cert_obj

    if certs_to_remove:
        for active_cert in certs_to_remove:
            SucmCertificate().delete_active_cert(
                active_cert_id=active_cert["active_cert_id"]
            )
            app_logger.info(
                "Certificate for %s that expired %s has been removed from the database, since it is no longer valid.",
                active_cert["common_name"],
                active_cert["expiry_date"],
            )

    app_logger.info("Job completed!")
    state["LAST_RUN"] = datetime.now()


def start_scheduler():
    app_logger.info("Scheduler started with an interval of 10 minutes.")
    scheduler = BackgroundScheduler()
    scheduler.add_job(job_function, "interval", minutes=10)
    scheduler.start()
