import base64

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

from .sucm_acme_account import SucmAcmeAccount
from .sucm_acme_reveal import SucmAcmeRevealToken
from .sucm_roles import parse_member_of, require_role, roles_for_groups
from .sucm_settings import audit_logger

bp = Blueprint("acme_accounts", __name__, url_prefix="/acme-accounts")


def _build_certbot_config(eab_kid, hmac_key):
    """
    Builds a ready-to-use certbot cli.ini for this account: just the ACME
    directory URL and the EAB kid/hmac, everything else left at certbot's
    own defaults. The directory URL is derived from the current request so
    it is correct for whichever environment (test/prod) issued it.
    """
    directory_url = url_for("acme_server.directory", _external=True)
    return (
        f"server = {directory_url}\n"
        f"eab-kid = {eab_kid}\n"
        f"eab-hmac-key = {hmac_key}\n"
    )


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
    # actual group membership per path (jira-administrators/it-staff for
    # the request form, it-produktion-infra-imdb for the admin views) -
    # role checks below are defense-in-depth on top of that. Apache sets the
    # X-Remote-* headers via `RequestHeader set`; fail closed if X-Remote-User
    # is absent rather than treating an SSO-bypassing request as authenticated.
    remote_user = request.headers.get("X-Remote-User")
    if not remote_user:
        abort(403)
    session["username"] = _short_username(remote_user)
    g.eppn = session["username"]
    session["display_name"] = request.headers.get("X-Remote-Display-Name")
    raw_member_of = request.headers.get("X-Remote-MemberOf")
    session["group"] = raw_member_of  # kept for backward compat / audit logging
    session["groups"] = parse_member_of(raw_member_of)
    session["roles"] = sorted(roles_for_groups(session["groups"]))


@bp.route("/request", methods=["GET", "POST"])
@require_role("acme_requester")
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

        # Stash only the NON-secret identifiers in the session. The plaintext
        # HMAC key is kept server-side in a one-time reveal token (see
        # sucm_acme_reveal) so it never rides the client-side session cookie -
        # Flask's default cookie is signed, not encrypted, so a secret stored
        # in it would be base64-readable by the browser/proxy until consumed.
        reveal_token = SucmAcmeRevealToken.create(account_id, hmac_key)
        session["acme_new_account"] = {
            "account_id": account_id,
            "eab_kid": eab_kid,
            "reveal_token": reveal_token,
        }
        return redirect(url_for("acme_accounts.account_created"))

    return render_template("acme_account_request.html")


@bp.route("/created")
@require_role("acme_requester")
def account_created():
    stashed = session.pop("acme_new_account", None)
    if not stashed or "reveal_token" not in stashed:
        return redirect(url_for("acme_accounts.request_account"))

    # Consume the one-time token (deletes the server-side row). A second visit,
    # an expired token, or a tampered/unknown token all return None -> the
    # plaintext HMAC key is only ever revealed once.
    revealed = SucmAcmeRevealToken.consume(stashed["reveal_token"])
    if not revealed:
        return redirect(url_for("acme_accounts.request_account"))
    _account_id, hmac_key = revealed

    new_account = {
        "account_id": stashed["account_id"],
        "eab_kid": stashed["eab_kid"],
        "hmac_key": hmac_key,
    }
    certbot_config = _build_certbot_config(
        new_account["eab_kid"], new_account["hmac_key"]
    )
    certbot_config_b64 = base64.b64encode(certbot_config.encode("utf-8")).decode(
        "ascii"
    )
    return render_template(
        "acme_account_created.html",
        new_account=new_account,
        certbot_config_b64=certbot_config_b64,
    )


@bp.route("/admin")
@require_role("acme_admin")
def admin_list():
    accounts = SucmAcmeAccount().get_all_accounts()
    return render_template("acme_admin_accounts.html", accounts=accounts)


@bp.route("/admin/<int:account_id>/activate", methods=["POST"])
@require_role("acme_admin")
def admin_activate(account_id):
    SucmAcmeAccount().activate_account(account_id, activated_by=session.get("username"))
    audit_logger.info(
        "ACME account %s activated by %s", account_id, session.get("username")
    )
    return redirect(url_for("acme_accounts.admin_list"))


@bp.route("/admin/<int:account_id>/disable", methods=["POST"])
@require_role("acme_admin")
def admin_disable(account_id):
    SucmAcmeAccount().disable_account(account_id)
    audit_logger.info(
        "ACME account %s disabled by %s", account_id, session.get("username")
    )
    return redirect(url_for("acme_accounts.admin_list"))


@bp.route("/admin/<int:account_id>/domains")
@require_role("acme_admin")
def admin_domains(account_id):
    account = SucmAcmeAccount(account_id).get_account_detail(account_id)
    domains = SucmAcmeAccount(account_id).get_domains(account_id)
    return render_template("acme_admin_domains.html", account=account, domains=domains)


@bp.route("/admin/<int:account_id>/domains/add", methods=["POST"])
@require_role("acme_admin")
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
@require_role("acme_admin")
def admin_domains_delete(domain_id):
    SucmAcmeAccount().remove_domain(domain_id)
    audit_logger.info(
        "ACME domain id %s removed by %s", domain_id, session.get("username")
    )
    return redirect(request.referrer or url_for("acme_accounts.admin_list"))
