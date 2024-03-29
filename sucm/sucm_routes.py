import os

from flask import (Blueprint, g, redirect, render_template, request, session,
                   url_for)
from werkzeug.utils import secure_filename

from .sucm_certificate import SucmCertificate
from .sucm_common import sucm_secret
from .sucm_globals import CERT_TYPES, state
from .sucm_notifygroup import SucmNotifyGroup
from .sucm_settings import APP_LOGFILE, audit_logger, cfg

bp = Blueprint("main", __name__)


@bp.before_request
def before_request():
    session["username"] = request.headers.get("X-Remote-User")
    g.eppn = session["username"]
    session["display_name"] = request.headers.get("X-Remote-Display-Name")
    session["group"] = request.headers.get("X-Remote-MemberOf")


@bp.route("/")
def index():
    all_certs = SucmCertificate().get_all_certificate()
    noti_msg = request.args.get("notification_message", None)
    noti_type = request.args.get("notification_type", None)

    if noti_msg and noti_type:
        return render_template(
            "index.html",
            all_certs=all_certs,
            notification_message=noti_msg,
            notification_type=noti_type,
        )

    return render_template("index.html", all_certs=all_certs)


@bp.route("/automation")
def automation():
    logs = []
    last_run = state["LAST_RUN"]
    with open(APP_LOGFILE, "r", encoding="utf-8") as f:
        logs = f.read().splitlines()
    return render_template("automation.html", logs=logs, last_run=last_run)


@bp.route("/active_certs")
def active_certs():
    all_active_certs = SucmCertificate().get_all_active_certs()
    return render_template("active_certs.html", all_active_certs=all_active_certs)


@bp.route("/notifygroups")
def notifygroups():
    all_groups_tuple = SucmNotifyGroup().get_all_notifygroups()
    all_groups = []

    for group_tuple in all_groups_tuple:
        used_in = SucmNotifyGroup().get_all_certs_for_group_id(group_tuple[0])
        group_dict = {
            "group_id": group_tuple[0],
            "group_name": group_tuple[1],
            "email_csv": group_tuple[2],
            "used_in": ", ".join(used_in),
        }
        all_groups.append(group_dict)

    noti_msg = request.args.get("notification_message")
    noti_type = request.args.get("notification_type")

    if noti_msg is not None:
        return render_template(
            "notifygroups.html",
            all_groups=all_groups,
            notification_message=noti_msg,
            notification_type=noti_type,
        )

    return render_template("notifygroups.html", all_groups=all_groups)


@bp.route("/faq")
def faq():
    return render_template("faq.html")


@bp.route("/edit_cert_response", methods=["POST"])
def edit_cert_response():
    try:
        cert_id = request.form["cert_id"]
        cert_operation = "add"
        noti_type = "Success"
        noti_msg = "Cert added successfully!"
        cert_details = SucmCertificate().get_certificate_detail(cert_id)
        if cert_details:
            cert_operation = "edit"
            noti_type = "Success"
            noti_msg = "Cert edited successfully!"

        cert_conf = {
            "common_name": request.form["common_name"],
            "certificate_authority_id": request.form["certificate_authority"][1],
            "country": request.form["country"],
            "state": request.form["state"],
            "city": request.form["city"],
            "organisation": request.form["organisation"],
            "subject_alt": request.form["subject_alt"],
            "cert_type": request.form["cert_type"],
            "notify_group": request.form["notify_group"],
            "status": None,
            "secret_path": request.form["secret_path"],
        }

        if not cert_conf["common_name"]:
            noti_type = "Danger"
            noti_msg = "Failure! Missing commonName"
            return redirect(
                url_for(
                    "main.index",
                    notification_message=noti_msg,
                    notification_type=noti_type,
                )
            )

        existing_common_name = SucmCertificate().get_common_name(
            cert_conf["common_name"]
        )
        if existing_common_name and cert_operation == "add":
            cert_id = existing_common_name["cert_id"]
            noti_type = "Danger"
            noti_msg = "Failure! CommonName already exist on this certificate entry, edit this instead!"
            return redirect(
                url_for(
                    "main.inspect_cert",
                    cert_id=cert_id,
                    notification_message=noti_msg,
                    notification_type=noti_type,
                )
            )

        cert = SucmCertificate(
            cert_id=cert_id,
            cert_conf=cert_conf,
        )

        if cert_operation == "add" and cert_conf["cert_type"] == "Automatic":
            cert.create_new_key_and_csr()
            cert.renew_cert_with_csr()
        else:
            cert.commit_changes_to_db()

        audit_logger.info(
            "Data saved for certificate: "
            + cert_id
            + " by user "
            + session.get("username")
        )
        cert_id = cert.cert_id
        del cert

        return redirect(
            url_for(
                "main.inspect_cert",
                cert_id=cert_id,
                notification_message=noti_msg,
                notification_type=noti_type,
            )
        )

    except Exception as e:
        print(f"An error occurred: {e}")
        noti_type = "Danger"
        noti_msg = "An unexpected error occurred!"
        return redirect(
            url_for(
                "main.index",
                notification_message=noti_msg,
                notification_type=noti_type,
            )
        )


@bp.route("/edit_group_response", methods=["POST"])
def edit_group_response():
    group_id = int(request.form["group_id"])
    group_name = request.form["group_name"]
    email_csv = request.form["email_csv"]

    notify_group = SucmNotifyGroup(group_id, group_name, email_csv)

    try:
        noti_type = "Success"
        noti_msg = "Group added successfully!"
        try:
            if notify_group.get_notifygroup_detail():
                noti_type = "Success"
                noti_msg = "Group edited successfully!"
        except:
            pass
        notify_group.add_update_notifygroup()
        audit_logger.info(
            "Group: " + group_name + " added by user " + session.get("username")
        )
    except:
        noti_type = "Danger"
        noti_msg = "Failed to save notifygroup!"
    del notify_group

    return redirect(
        url_for(
            "main.notifygroups",
            notification_message=noti_msg,
            notification_type=noti_type,
        )
    )


@bp.route("/add_group")
def add_group():
    group_id = SucmNotifyGroup().get_next_notifygroup_id()
    return render_template(
        "edit_group.html",
        group_data=(group_id, "fobargroup", "foo@su.se,bar@su.se"),
    )


@bp.route(
    "/delete_group/<group_id>", methods=["POST", "GET"]
)  ## Note! need to add method for cleaning these from the certs data also.
def delete_group(group_id):
    try:
        SucmNotifyGroup().delete_notifygroup(group_id)
        noti_type = "Success"
        noti_msg = "NotifyGroup removed successfully!"
        audit_logger.info(
            "Group ID: " + group_id + " removed by user " + session.get("username")
        )
    except:
        noti_type = "Danger"
        noti_msg = "Failed to remove NotifyGroup!"
    return redirect(
        url_for(
            "main.notifygroups",
            notification_message=noti_msg,
            notification_type=noti_type,
        )
    )


@bp.route("/delete_cert/<cert_id>", methods=["POST", "GET"])
def delete_cert(cert_id):
    try:
        cert = SucmCertificate().get_certificate_detail(cert_id=cert_id)
        SucmCertificate().delete_cert(cert_id)
        noti_type = "Success"
        noti_msg = "Certificate removed successfully!"
        audit_logger.info(
            "Cert: "
            + cert["common_name"]
            + " removed by user "
            + session.get("username")
        )
    except:
        noti_type = "Danger"
        noti_msg = "Failed to remove Certificate!"
    return redirect(
        url_for(
            "main.index", notification_message=noti_msg, notification_type=noti_type
        )
    )


@bp.route("/inspect_active_cert/<active_cert_id>", methods=["POST", "GET"])
def inspect_active_cert(active_cert_id):
    details = SucmCertificate().get_active_cert_ssl_data(active_cert_id)

    return render_template(
        "inspect_active_cert.html",
        active_cert_id=active_cert_id,
        cert_details=details,
    )


@bp.route("/revoke_cert/<active_cert_id>", methods=["POST", "GET"])
def revoke_cert(active_cert_id):
    try:
        active_cert = SucmCertificate().get_active_cert_detail(
            active_cert_id=active_cert_id
        )
        SucmCertificate().revoke_cert(active_cert_id)
        noti_type = "Success"
        noti_msg = "Cert revoked successfully!"
        audit_logger.info(
            "Active cert for: %s with id: %s removed by user %s",
            active_cert["common_name"],
            str(active_cert["active_cert_id"]),
            session.get("username"),
        )
    except:
        noti_type = "Danger"
        noti_msg = "Failed to revoke certificate!"

    try:
        cert_id = active_cert["cert_id"]
        cert_data = SucmCertificate().get_certificate_detail(cert_id)
        certificate_authority_detail = (
            SucmCertificate().get_certificate_authority_detail(
                cert_data["certificate_authority_id"]
            )
        )
        all_active_certs = SucmCertificate().get_all_active_certs(cert_id)
        return redirect(
            url_for(
                "main.inspect_cert",
                cert_id=cert_id,
                cert_data=cert_data,
                certificate_authority_detail=certificate_authority_detail,
                notification_message=noti_msg,
                notification_type=noti_type,
                all_active_certs=all_active_certs,
            )
        )
    except:
        return redirect(
            url_for(
                "main.active_certs",
                notification_message=noti_msg,
                notification_type=noti_type,
            )
        )


@bp.route("/add_cert")
def add_cert():
    certificate_authoritys = SucmCertificate().get_all_certificate_authority()
    notify_groups = SucmNotifyGroup().get_all_notifygroups()
    secret_paths = sucm_secret.get_all_paths()
    cert_id = SucmCertificate().get_next_cert_id()
    cert_data = {
        "cert_id": cert_id,
        "common_name": None,
        "subject_alt": None,
        "country": cfg.get("cert_defaults", "country_name"),
        "state": cfg.get("cert_defaults", "state_or_province_name"),
        "city": cfg.get("cert_defaults", "locality_name"),
        "organisation": cfg.get("cert_defaults", "organization_name"),
    }

    return render_template(
        "edit_cert.html",
        cert_data=cert_data,
        certificate_authoritys=certificate_authoritys,
        notify_groups=notify_groups,
        cert_types=CERT_TYPES,
        secret_paths=secret_paths,
        cert_operation="add",
    )


@bp.route("/<int:cert_id>", methods=["POST", "GET"])
def inspect_cert(cert_id):
    cert_data = SucmCertificate().get_certificate_detail(cert_id)
    certificate_authority_detail = SucmCertificate().get_certificate_authority_detail(
        cert_data["certificate_authority_id"]
    )

    all_active_certs_list = SucmCertificate().get_all_active_certs(cert_data["cert_id"])
    all_active_certs = []

    for cert_dict in all_active_certs_list:
        serial_number = SucmCertificate().get_active_cert_ssl_data(
            cert_dict["active_cert_id"]
        )["serial_number"]
        cert_dict["serial_number"] = serial_number
        all_active_certs.append(cert_dict)

    try:
        if request.args["notification_message"]:
            noti_msg = request.args["notification_message"]
            noti_type = request.args["notification_type"]
            return render_template(
                "inspect_cert.html",
                cert_data=cert_data,
                certificate_authority_detail=certificate_authority_detail,
                notification_message=noti_msg,
                notification_type=noti_type,
                all_active_certs=all_active_certs,
            )
        return render_template(
            "inspect_cert.html",
            cert_data=cert_data,
            certificate_authority_detail=certificate_authority_detail,
            all_active_certs=all_active_certs,
        )
    except:
        return render_template(
            "inspect_cert.html",
            cert_data=cert_data,
            certificate_authority_detail=certificate_authority_detail,
            all_active_certs=all_active_certs,
        )


@bp.route("/edit_cert?<cert_id>", methods=["POST", "GET"])
def edit_cert(cert_id):
    cert_data = SucmCertificate().get_certificate_detail(cert_id)
    notify_groups = SucmNotifyGroup().get_all_notifygroups()
    certificate_authoritys = SucmCertificate().get_all_certificate_authority()

    try:
        current_notify_group = SucmNotifyGroup().get_notifygroup_detail(
            cert_data["notify_group"]
        )
        notify_groups.remove(current_notify_group)
        notify_groups.insert(0, current_notify_group)
    except:
        pass

    secret_paths = sucm_secret.get_all_paths()
    current_secret_path = cert_data["secret_path"]
    if current_secret_path is not None:
        secret_paths.remove(current_secret_path)
        secret_paths.insert(0, current_secret_path)

    current_cert_type = cert_data["cert_type"]
    new_cert_types = CERT_TYPES.copy()
    new_cert_types.remove(current_cert_type)
    new_cert_types.insert(0, current_cert_type)

    current_certificate_authority = SucmCertificate().get_certificate_authority_detail(
        cert_data["certificate_authority_id"]
    )
    certificate_authoritys.remove(current_certificate_authority)
    certificate_authoritys.insert(0, current_certificate_authority)

    cert_data["cert_id"] = cert_id

    return render_template(
        "edit_cert.html",
        cert_data=cert_data,
        certificate_authoritys=certificate_authoritys,
        notify_groups=notify_groups,
        cert_types=new_cert_types,
        secret_paths=secret_paths,
        cert_operation="edit",
    )


@bp.route("/submit_csr/<cert_id>", methods=["POST", "GET"])
def submit_csr(cert_id):
    cert_data = SucmCertificate().get_certificate_detail(cert_id)
    return render_template("submit_csr.html", cert_data=cert_data)


@bp.route("/renew_crt/<cert_id>", methods=["POST", "GET"])
def renew_crt(cert_id):
    cert = SucmCertificate(cert_id=cert_id)
    cert.create_new_key_and_csr()
    cert.renew_cert_with_csr()
    all_active_certs = cert.get_all_active_certs(cert_id=cert_id)
    del cert
    noti_type = "Success"
    noti_msg = "New CRT collected successfully!"
    return redirect(
        url_for(
            "main.inspect_cert",
            cert_id=cert_id,
            notification_message=noti_msg,
            notification_type=noti_type,
            all_active_certs=all_active_certs,
        )
    )


@bp.route("/renew_csr/<cert_id>", methods=["POST", "GET"])
def renew_csr(cert_id):
    cert = SucmCertificate(cert_id=cert_id)
    cert.create_new_key_and_csr()
    all_active_certs = cert.get_all_active_certs(cert_id=cert_id)
    del cert
    noti_type = "Success"
    noti_msg = "New CSR and key genereated successfully!"
    return redirect(
        url_for(
            "main.inspect_cert",
            cert_id=cert_id,
            notification_message=noti_msg,
            notification_type=noti_type,
            all_active_certs=all_active_certs,
        )
    )


@bp.route("/submit_csr_response", methods=["POST", "GET"])
def submit_csr_response():
    cert_id = request.form["cert_id"]

    # Handle uploaded file
    csr_file = request.files.get("csr_file")
    if csr_file:
        filename = secure_filename(csr_file.filename)
        filepath = os.path.join("/tmp", filename)
        csr_file.save(filepath)
        with open(filepath, "r", encoding="utf-8") as file:
            csr_data = file.read()
        os.remove(filepath)
    else:
        csr_data = request.form["freeform"]

    if len(csr_data) < 5:
        noti_type = "Danger"
        noti_msg = "CSR missing from input field or file upload!"
        all_active_certs = SucmCertificate().get_all_active_certs(cert_id)
        return redirect(
            url_for(
                "main.inspect_cert",
                cert_id=cert_id,
                notification_message=noti_msg,
                notification_type=noti_type,
                all_active_certs=all_active_certs,
            )
        )

    cert = SucmCertificate(cert_id=cert_id)
    cert.submit_manual_csr(csr_data)
    cert.renew_cert_with_csr()
    all_active_certs = cert.get_all_active_certs(cert_id=cert_id)
    del cert
    noti_type = "Success"
    noti_msg = "New CRT collected successfully!"
    return redirect(
        url_for(
            "main.inspect_cert",
            cert_id=cert_id,
            notification_message=noti_msg,
            notification_type=noti_type,
            all_active_certs=all_active_certs,
        )
    )


@bp.route("/edit_group/<group_id>", methods=["POST", "GET"])
def edit_group(group_id):
    group_data = SucmNotifyGroup().get_notifygroup_detail(int(group_id))
    return render_template("edit_group.html", group_data=group_data)
