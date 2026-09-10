from flask import Blueprint, g, redirect, render_template, request, session, url_for

from .sucm_acme_account import SucmAcmeAccount
from .sucm_settings import audit_logger

bp = Blueprint("acme_accounts", __name__, url_prefix="/acme-accounts")


def _short_username(remote_user):
    """
    Apache/Shibboleth sets X-Remote-User to the full eppn (e.g.
    "cljo1227@su.se"). For display/audit purposes we only want the short,
    local part before the "@" (e.g. "cljo1227").
    """
    if not remote_user:
        return remote_user
    return remote_user.split("@", 1)[0]


@bp.before_request
def before_request():
    # Mirrors main.bp's before_request. Apache/Shibboleth enforces the
    # actual group membership per path (it-staff for the request form,
    # it-produktion-infra-imdb for the admin views) - this only captures
    # identity for session/audit purposes.
    session["username"] = _short_username(request.headers.get("X-Remote-User"))
    g.eppn = session["username"]
    session["display_name"] = request.headers.get("X-Remote-Display-Name")
    session["group"] = request.headers.get("X-Remote-MemberOf")


@bp.route("/request", methods=["GET", "POST"])
def request_account():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        topdesk_ticket = request.form.get("topdesk_ticket", "").strip()
        if not name or not topdesk_ticket:
            return render_template(
                "acme_account_request.html",
                notification_message="Name and TOPDESK ticket are both required.",
                notification_type="Danger",
            )

        account_id, eab_kid, hmac_key = SucmAcmeAccount().create_account(
            name=name,
            topdesk_ticket=topdesk_ticket,
            requested_by=session.get("username"),
        )
        audit_logger.info(
            "ACME account %s (name: %s, TOPDESK: %s) requested by %s",
            account_id,
            name,
            topdesk_ticket,
            session.get("username"),
        )

        # Stash the plaintext secret in the session for a single, one-time
        # reveal on the next page. It is never written to the DB or logs.
        session["acme_new_account"] = {
            "account_id": account_id,
            "eab_kid": eab_kid,
            "hmac_key": hmac_key,
        }
        return redirect(url_for("acme_accounts.account_created"))

    return render_template("acme_account_request.html")


@bp.route("/created")
def account_created():
    new_account = session.pop("acme_new_account", None)
    if not new_account:
        return redirect(url_for("acme_accounts.request_account"))
    return render_template("acme_account_created.html", new_account=new_account)


@bp.route("/admin")
def admin_list():
    accounts = SucmAcmeAccount().get_all_accounts()
    return render_template("acme_admin_accounts.html", accounts=accounts)


@bp.route("/admin/<int:account_id>/activate", methods=["POST"])
def admin_activate(account_id):
    SucmAcmeAccount().activate_account(
        account_id, activated_by=session.get("username")
    )
    audit_logger.info(
        "ACME account %s activated by %s", account_id, session.get("username")
    )
    return redirect(url_for("acme_accounts.admin_list"))


@bp.route("/admin/<int:account_id>/disable", methods=["POST"])
def admin_disable(account_id):
    SucmAcmeAccount().disable_account(account_id)
    audit_logger.info(
        "ACME account %s disabled by %s", account_id, session.get("username")
    )
    return redirect(url_for("acme_accounts.admin_list"))


@bp.route("/admin/<int:account_id>/domains")
def admin_domains(account_id):
    account = SucmAcmeAccount(account_id).get_account_detail(account_id)
    domains = SucmAcmeAccount(account_id).get_domains(account_id)
    return render_template(
        "acme_admin_domains.html", account=account, domains=domains
    )


@bp.route("/admin/<int:account_id>/domains/add", methods=["POST"])
def admin_domains_add(account_id):
    domain_pattern = request.form.get("domain_pattern", "").strip()
    if domain_pattern:
        SucmAcmeAccount().add_domain(account_id, domain_pattern)
        audit_logger.info(
            "ACME domain %s added to account %s by %s",
            domain_pattern,
            account_id,
            session.get("username"),
        )
    return redirect(url_for("acme_accounts.admin_domains", account_id=account_id))


@bp.route("/admin/domains/<int:domain_id>/delete", methods=["POST"])
def admin_domains_delete(domain_id):
    SucmAcmeAccount().remove_domain(domain_id)
    audit_logger.info(
        "ACME domain id %s removed by %s", domain_id, session.get("username")
    )
    return redirect(request.referrer or url_for("acme_accounts.admin_list"))
