import os

from flask import (
    Blueprint,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from .sucm_certificate import SucmCertificate
from .sucm_common import sucm_secret
from .sucm_globals import ACME_CERT_TYPE, CERT_TYPES, state
from .sucm_notifygroup import SucmNotifyGroup, validate_email_csv
from .sucm_roles import parse_member_of, require_role, roles_for_groups
from .sucm_settings import APP_LOGFILE, app_logger, audit_logger, cfg

bp = Blueprint("main", __name__)


def _is_valid_secret_path(secret_path):
    """
    Defense-in-depth validation of the user-supplied Vault secret_path.

    The authoritative control is the Vault user's own ACLs, but we also
    restrict the value in-app to exactly the set of paths the secrets
    backend advertises via get_all_paths() (the same list the GUI dropdown
    is populated from), plus a basic shape check. Anything else is rejected.
    """
    if not secret_path or ".." in secret_path or not secret_path.endswith("/"):
        return False
    return secret_path in sucm_secret.get_all_paths()


@bp.before_request
def before_request():
    # Apache/Shibboleth sets X-Remote-User / X-Remote-MemberOf via
    # `RequestHeader set` in sucm-apache.conf, which replaces any
    # client-supplied value. We nevertheless fail closed if X-Remote-User is
    # absent: a request that reaches the app without it has bypassed (or
    # misconfigured) the SSO gate and must not be treated as authenticated.
    remote_user = request.headers.get("X-Remote-User")
    if not remote_user:
        abort(403)
    session["username"] = remote_user
    g.eppn = session["username"]
    session["display_name"] = request.headers.get("X-Remote-Display-Name")
    raw_member_of = request.headers.get("X-Remote-MemberOf")
    session["group"] = raw_member_of  # kept for backward compat / audit logging
    session["groups"] = parse_member_of(raw_member_of)
    session["roles"] = sorted(roles_for_groups(session["groups"]))
    # TEMP DEBUG: diagnose memberOf parsing / role resolution (see 403 on /).
    app_logger.info(
        "AUTH-DEBUG user=%s raw_memberOf=%r groups=%s roles=%s",
        session["username"],
        raw_member_of,
        session["groups"],
        session["roles"],
    )


@bp.route("/")
@require_role("cert_manager")
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


# NOTE: gated to the tighter acme_admin group (it-produktion-infra-imdb), not
# the broad cert_manager/it-staff group, because it reads and renders the raw
# application log - operational detail that the wider cert-manager population
# does not need. The matching Apache <LocationMatch> for /automation should be
# tightened to the same group in su-salt-states-services-cert (TODO).
@bp.route("/automation")
@require_role("acme_admin")
def automation():
    logs = []
    last_run = state["LAST_RUN"]
    with open(APP_LOGFILE, "r", encoding="utf-8") as f:
        # Tail, not the whole file: the log is truncated on each app start but
        # can still grow large between restarts.
        logs = f.read().splitlines()[-500:]
    return render_template("automation.html", logs=logs, last_run=last_run)


@bp.route("/active_certs")
@require_role("cert_manager")
def active_certs():
    all_active_certs = SucmCertificate().get_all_active_certs()
    return render_template("active_certs.html", all_active_certs=all_active_certs)


@bp.route("/notifygroups")
@require_role("cert_manager")
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
@require_role("cert_manager", "acme_requester")
def faq():
    return render_template("faq.html")


@bp.route("/edit_cert_response", methods=["POST"])
@require_role("cert_manager")
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

        # ACME-managed certs are only ever created/edited by the ACME account
        # admin panel / order-finalize bridge, never through this form - even
        # if a tampered request tries to smuggle it in via the cert_type field.
        if request.form["cert_type"] == ACME_CERT_TYPE or (
            cert_details and cert_details.get("cert_type") == ACME_CERT_TYPE
        ):
            noti_type = "Danger"
            noti_msg = "ACME-managed certificates cannot be created or edited here."
            return redirect(
                url_for(
                    "main.index",
                    notification_message=noti_msg,
                    notification_type=noti_type,
                )
            )

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

        if not _is_valid_secret_path(cert_conf["secret_path"]):
            noti_type = "Danger"
            noti_msg = "Failure! Invalid secret path."
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
@require_role("cert_manager")
def edit_group_response():
    group_id = int(request.form["group_id"])
    group_name = request.form["group_name"]

    # Validate the recipient list before it ever reaches the DB or a mail
    # header - a CR/LF or malformed entry here would otherwise become a header
    # injection primitive when send_email() splits and interpolates it.
    try:
        email_csv = validate_email_csv(request.form["email_csv"])
    except ValueError as e:
        return redirect(
            url_for(
                "main.notifygroups",
                notification_message=f"Invalid email list: {e}",
                notification_type="Danger",
            )
        )

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
@require_role("cert_manager")
def add_group():
    group_id = SucmNotifyGroup().get_next_notifygroup_id()
    return render_template(
        "edit_group.html",
        group_data=(group_id, "fobargroup", "foo@su.se,bar@su.se"),
    )


@bp.route(
    "/delete_group/<int:group_id>", methods=["POST"]
)  ## Note! need to add method for cleaning these from the certs data also.
@require_role("cert_manager")
def delete_group(group_id):
    try:
        SucmNotifyGroup().delete_notifygroup(group_id)
        noti_type = "Success"
        noti_msg = "NotifyGroup removed successfully!"
        audit_logger.info(
            "Group ID: " + str(group_id) + " removed by user " + session.get("username")
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


@bp.route("/delete_cert/<int:cert_id>", methods=["POST"])
@require_role("cert_manager")
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


@bp.route("/inspect_active_cert/<int:active_cert_id>", methods=["POST", "GET"])
@require_role("cert_manager")
def inspect_active_cert(active_cert_id):
    details = SucmCertificate().get_active_cert_ssl_data(active_cert_id)

    return render_template(
        "inspect_active_cert.html",
        active_cert_id=active_cert_id,
        cert_details=details,
    )


@bp.route("/revoke_cert/<int:active_cert_id>", methods=["POST"])
@require_role("cert_manager")
def revoke_cert(active_cert_id):
    print(f"[REVOKE][route][pid={os.getpid()}] start active_cert_id={active_cert_id}")

    sc = SucmCertificate()  # fresh instance per request
    print(f"[REVOKE][route] SucmCertificate obj_id={id(sc)}")

    # Resolve only what's needed to (a) set CA on this instance, (b) redirect later
    try:
        active = sc.get_active_cert_detail(active_cert_id=active_cert_id)  # dict
        print(
            f"[REVOKE][route] active row: cert_id={active.get('cert_id')} cn={active.get('common_name')}"
        )
        cert = sc.get_certificate_detail(active["cert_id"])  # dict
        print(
            f"[REVOKE][route] cert row: CA_Id={cert.get('certificate_authority_id')} cn={cert.get('common_name')}"
        )
        cert_id_for_redirect = cert["cert_id"]
    except Exception as e:
        print(
            f"[REVOKE][route] failed to load active/cert rows for {active_cert_id}: {e}"
        )
        return redirect(
            url_for(
                "main.active_certs",
                notification_message="Failed to load certificate.",
                notification_type="Danger",
            )
        )

    # 🔑 First lock: pre-set CA on this instance BEFORE calling service
    sc.certificate_authority_id = cert["certificate_authority_id"]
    sc.common_name = cert.get("common_name")
    print(
        f"[REVOKE][route] preset on instance: CA_Id={sc.certificate_authority_id} CN={sc.common_name}"
    )

    try:
        print(
            f"[REVOKE][route] calling service revoke_cert for ActiveCertificate_Id={active_cert_id}"
        )
        sc.revoke_cert(
            active_cert_id
        )  # service will re-derive & verify CA (second lock)
        print(f"[REVOKE][route] service revoke_cert returned OK")
        noti_type, noti_msg = "Success", "Cert revoked successfully!"
    except Exception as e:
        print(f"[REVOKE][route] revoke_cert raised: {e}")
        noti_type, noti_msg = "Danger", "Failed to revoke certificate!"

    print(f"[REVOKE][route] redirect → inspect_cert cert_id={cert_id_for_redirect}")
    return redirect(
        url_for(
            "main.inspect_cert",
            cert_id=cert_id_for_redirect,
            notification_message=noti_msg,
            notification_type=noti_type,
        )
    )


@bp.route("/add_cert")
@require_role("cert_manager")
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
@require_role("cert_manager")
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
@require_role("cert_manager")
def edit_cert(cert_id):
    cert_data = SucmCertificate().get_certificate_detail(cert_id)

    if cert_data.get("cert_type") == ACME_CERT_TYPE:
        return redirect(
            url_for(
                "main.inspect_cert",
                cert_id=cert_id,
                notification_message="ACME-managed certificates cannot be edited here.",
                notification_type="Danger",
            )
        )

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


@bp.route("/submit_csr/<int:cert_id>", methods=["POST", "GET"])
@require_role("cert_manager")
def submit_csr(cert_id):
    cert_data = SucmCertificate().get_certificate_detail(cert_id)
    return render_template("submit_csr.html", cert_data=cert_data)


@bp.route("/renew_crt/<int:cert_id>", methods=["POST"])
@require_role("cert_manager")
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


@bp.route("/renew_csr/<int:cert_id>", methods=["POST"])
@require_role("cert_manager")
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


@bp.route("/submit_csr_response", methods=["POST"])
@require_role("cert_manager")
def submit_csr_response():
    cert_id = request.form["cert_id"]

    # Handle uploaded file. A CSR is a public artifact (it only ever contains
    # a public key + identifiers), so there is no reason to stage it on disk -
    # read it straight from the in-memory upload stream. This avoids the
    # previous predictable-/tmp-path write, which was open to symlink /
    # pre-creation games and concurrent-upload clobbering.
    csr_file = request.files.get("csr_file")
    if csr_file:
        csr_data = csr_file.read().decode("utf-8", errors="replace")
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


@bp.route("/edit_group/<int:group_id>", methods=["POST", "GET"])
@require_role("cert_manager")
def edit_group(group_id):
    group_data = SucmNotifyGroup().get_notifygroup_detail(group_id)
    return render_template("edit_group.html", group_data=group_data)
