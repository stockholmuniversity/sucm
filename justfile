# SUCM task runner: Jenkins status helpers, release to test, promote/deploy to prod.
# Meant to be run from your Linux "skal" machine (<user>.it.su.se), where Jenkins, GitHub and the
# test/prod servers are reachable without any jump host.
#
# REQUIREMENTS (run `just check` to verify them)
#   Packages (Debian): sudo apt install just git gh python3 curl openssh-client   (just >= 1.40)
#   Repos, cloned side by side in the same parent directory (anywhere; or set CERT_APP_DIR=/path to sua-cert-app):
#     <dir>/sucm (this repo, branch master) and <dir>/sua-cert-app (requirements.txt pins sucm==<version>)
#       gh repo clone stockholmuniversity/sucm; gh repo clone stockholmuniversity/sua-cert-app
#   GitHub: `gh auth login` (HTTPS) and `gh auth setup-git`, with push rights to both repos.
#     git user.name / user.email must be set.
#   Jenkins (https://ci.it.su.se/): group su-jenkins:user (sysadmin for promotion). Create an API token under
#     User -> Configure -> API Token and store it in ~/.config/jenkins/env (chmod 600, never commit):
#       JENKINS_URL=https://ci.it.su.se/
#       JENKINS_USER_ID=<user>@su.se       (the Jenkins id, i.e. with @su.se)
#       JENKINS_API_TOKEN=<token>
#     Override the file location with JENKINS_ENV=/path/to/file.
#   SSH: key-based login from this machine to the test server (sucm-test.it.su.se) with passwordless sudo
#     (needed for salt-call and apache). Prod: set SUCM_PROD_HOST=<fqdn of the prod cert-app server>.
#
# Over ssh the recipes only touch the test/prod server: salt-call state.apply (plus test=True dry-run), apache2
# restart, apt --only-upgrade sua-cert-app (upgrade-test only), and read-only checks (sudo -n true, pip list, is-active).
#
# Mutating recipes (release*, update-cert-app, deploy-*) ask for confirmation; set YES=1 to skip the prompt.
# Nothing here starts a build directly: builds are triggered by the GitHub webhooks when you push, as before.
# Prod promotion is an interactive Jenkins step.

set shell := ["bash", "-euo", "pipefail", "-c"]

job := "sucm"
cert_app := "sua-cert-app"
test_host := "sucm-test.it.su.se"
# Default: sua-cert-app next to this repo (same parent directory); override with CERT_APP_DIR=/path
cert_app_dir := env("CERT_APP_DIR", justfile_directory() + "/../sua-cert-app")

default:
    @just --list

# Verify local tools, credentials, Jenkins login, ssh and GitHub access (read-only)
check:
    #!/usr/bin/env bash
    set -uo pipefail
    fail=0
    ok()  { printf '  ok   %s\n' "$1"; }
    bad() { printf '  FAIL %s\n' "$1"; fail=1; }
    for t in just git python3 curl ssh gh; do command -v "$t" >/dev/null && ok "tool: $t" || bad "tool: $t not found"; done
    for t in poetry black; do command -v "$t" >/dev/null && ok "optional tool: $t" || echo "  --   optional tool $t missing"; done
    gh auth status >/dev/null 2>&1 && ok "gh logged in" || bad "gh not logged in (gh auth login)"
    [ -d "{{cert_app_dir}}/.git" ] && ok "repo {{cert_app_dir}}" || bad "{{cert_app_dir}} not cloned (clone it next to sucm or set CERT_APP_DIR)"
    envf="${JENKINS_ENV:-$HOME/.config/jenkins/env}"
    if [ -r "$envf" ]; then
      ok "jenkins env file $envf"
      perm=$(stat -c %a "$envf" 2>/dev/null || stat -f %Lp "$envf"); [ "$perm" = 600 ] && ok "env file mode 600" || bad "env file mode is $perm (chmod 600)"
      just whoami >/dev/null 2>&1 && ok "jenkins login ($(just whoami))" || bad "jenkins login failed (user id with @su.se? token valid?)"
    else bad "missing $envf"; fi
    ssh -o BatchMode=yes -o ConnectTimeout=20 {{test_host}} 'sudo -n true' 2>/dev/null && ok "ssh {{test_host}} + sudo" || bad "ssh/sudo on {{test_host}}"
    [ -n "${SUCM_PROD_HOST:-}" ] && ok "SUCM_PROD_HOST=$SUCM_PROD_HOST" || echo "  --   SUCM_PROD_HOST not set (only needed for prod deploy)"
    exit $fail

# Current version in pyproject.toml, latest tag, and what sua-cert-app pins
version:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "pyproject.toml : $(grep -m1 '^version' pyproject.toml)"
    echo "latest tag     : $(git tag --sort=-creatordate | head -1)"
    echo "sua-cert-app   : $(grep '^sucm==' "{{cert_app_dir}}/requirements.txt")"

# Show which Jenkins user the token authenticates as
whoami:
    #!/usr/bin/env bash
    set -euo pipefail
    set -a; . "${JENKINS_ENV:-$HOME/.config/jenkins/env}"; set +a
    curl -fsS -m 20 -u "$JENKINS_USER_ID:$JENKINS_API_TOKEN" "${JENKINS_URL%/}/me/api/json?tree=id,fullName" \
      | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["id"], "-", d["fullName"])'

# List jobs, optionally filtered by a case-insensitive substring
jobs filter="":
    #!/usr/bin/env bash
    set -euo pipefail
    set -a; . "${JENKINS_ENV:-$HOME/.config/jenkins/env}"; set +a
    curl -fsS -m 30 -u "$JENKINS_USER_ID:$JENKINS_API_TOKEN" "${JENKINS_URL%/}/api/json?tree=jobs%5Bname,color%5D" \
      | python3 -c 'import sys,json; f=sys.argv[1].lower(); [print(j["name"]) for j in json.load(sys.stdin)["jobs"] if f in j["name"].lower()]' "{{filter}}"

# Show parameter names and defaults for a job
params name=job:
    #!/usr/bin/env bash
    set -euo pipefail
    set -a; . "${JENKINS_ENV:-$HOME/.config/jenkins/env}"; set +a
    curl -fsS -m 20 -u "$JENKINS_USER_ID:$JENKINS_API_TOKEN" "${JENKINS_URL%/}/job/{{name}}/api/json?tree=property%5BparameterDefinitions%5Bname,defaultParameterValue%5Bvalue%5D%5D%5D" \
      | python3 -c 'import sys,json; [print("%-12s default=%r" % (p["name"], p.get("defaultParameterValue", {}).get("value"))) for x in json.load(sys.stdin)["property"] for p in x.get("parameterDefinitions", [])]'

# Show the most recent builds of a job (result, duration, parameters)
status name=job count="5":
    #!/usr/bin/env bash
    set -euo pipefail
    set -a; . "${JENKINS_ENV:-$HOME/.config/jenkins/env}"; set +a
    curl -fsS -m 20 -u "$JENKINS_USER_ID:$JENKINS_API_TOKEN" "${JENKINS_URL%/}/job/{{name}}/api/json?tree=builds%5Bnumber,result,building,timestamp,duration,actions%5Bparameters%5Bname,value%5D%5D%5D%7B0,{{count}}%7D" \
      | python3 -c 'import sys,json,datetime as d; [print("#%-4s %-8s %s %4ds %s" % (b["number"], "RUNNING" if b["building"] else b["result"], d.datetime.fromtimestamp(b["timestamp"]/1000).strftime("%Y-%m-%d %H:%M"), b["duration"]//1000, {p["name"]: p["value"] for a in b["actions"] for p in a.get("parameters", [])})) for b in json.load(sys.stdin)["builds"]]'

# Print the console log of a build (default: last build)
log name=job build="lastBuild":
    #!/usr/bin/env bash
    set -euo pipefail
    set -a; . "${JENKINS_ENV:-$HOME/.config/jenkins/env}"; set +a
    curl -fsS -m 60 -u "$JENKINS_USER_ID:$JENKINS_API_TOKEN" "${JENKINS_URL%/}/job/{{name}}/{{build}}/consoleText"

# ---------------------------------------------------------------------------------------------
# Release / deploy (see the Confluence page "Deployment")
# ---------------------------------------------------------------------------------------------

# Ask for confirmation (skipped with YES=1)
[private]
_confirm msg:
    #!/usr/bin/env bash
    set -euo pipefail
    [ "${YES:-}" = 1 ] && exit 0
    read -r -p "{{msg}} [y/N] " a
    [ "$a" = y ] || [ "$a" = Y ] || { echo "aborted"; exit 1; }

# Print an uppercase step label (the numbering matches the `release` chain)
[private]
_step n text:
    #!/usr/bin/env bash
    # Bold cyan label plus an overall progress bar (0% at step 1, 100% at step 12); no colour if NO_COLOR is set or output is not a terminal
    n={{n}}; w=24; p=$(( (n - 1) * 100 / 11 )); f=$(( p * w / 100 )); bar=$(printf '%*s' "$f" '' | tr ' ' '#')$(printf '%*s' "$((w - f))" '' | tr ' ' '-')
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then c=$'\033[1;36m'; r=$'\033[0m'; else c=; r=; fi
    printf '%s=== STEP %s/12: %s === [%s] %s%%%s\n' "$c" "$n" "{{text}}" "$bar" "$p" "$r"

# Verify everything the release needs BEFORE anything is changed or pushed (both repos)
[private]
_preflight new:
    #!/usr/bin/env bash
    set -euo pipefail
    v="{{new}}"
    fail() { echo "PREFLIGHT FAILED: $*"; exit 1; }
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "version must look like 0.15.0"
    for d in "{{justfile_directory()}}" "{{cert_app_dir}}"; do
      [ -d "$d/.git" ] || fail "$d is not a git repo (clone it or set CERT_APP_DIR)"
      n=$(basename "$d")
      git -C "$d" fetch -q origin --tags || fail "$n: git fetch failed"
      [ "$(git -C "$d" branch --show-current)" = master ] || fail "$n: not on master"
      [ -z "$(git -C "$d" status --porcelain)" ] || { git -C "$d" status --short; fail "$n: working tree not clean"; }
      if [ "$(git -C "$d" rev-parse HEAD)" != "$(git -C "$d" rev-parse origin/master)" ]; then
        # sua-cert-app is also pushed to by others/Jenkins: a plain fast-forward is safe. sucm must be synced by hand (this justfile lives there).
        if [ "$d" = "{{cert_app_dir}}" ] && git -C "$d" merge-base --is-ancestor HEAD origin/master; then
          git -C "$d" merge -q --ff-only origin/master && echo "$n: fast-forwarded to origin/master"
        else
          fail "$n: master is not in sync with origin/master (pull or push first)"
        fi
      fi
    done
    git rev-parse -q --verify "refs/tags/$v" >/dev/null && fail "tag $v already exists" || true
    grep -qE '^version = "[^"]+"' pyproject.toml || fail "no version line in pyproject.toml"
    grep -qE '^sucm==' "{{cert_app_dir}}/requirements.txt" || fail "no sucm== line in sua-cert-app/requirements.txt"
    echo "preflight ok: both repos on master, clean, in sync; tag $v is free"

# Poll Jenkins until a build of <name> with parameter <key>=<value> exists and finishes; fail unless SUCCESS
[private]
wait-build name key value timeout="1200":
    #!/usr/bin/env python3
    import json, os, sys, time, urllib.parse, urllib.request, base64
    env = {}
    for line in open(os.environ.get("JENKINS_ENV", os.path.expanduser("~/.config/jenkins/env"))):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1)
            env[k] = v
    tree = "builds[number,result,building,timestamp,estimatedDuration,actions[parameters[name,value]]]{0,15}"
    url = env["JENKINS_URL"].rstrip("/") + "/job/{{name}}/api/json?tree=" + urllib.parse.quote(tree, safe=",")
    auth = base64.b64encode((env["JENKINS_USER_ID"] + ":" + env["JENKINS_API_TOKEN"]).encode()).decode()
    deadline = time.time() + int("{{timeout}}")
    seen = None
    tty = sys.stdout.isatty()
    drew = False
    while time.time() < deadline:
        req = urllib.request.Request(url, headers={"Authorization": "Basic " + auth})
        builds = json.load(urllib.request.urlopen(req, timeout=30))["builds"]
        match = [b for b in builds
                 if any(p.get("name") == "{{key}}" and p.get("value") == "{{value}}"
                        for a in b["actions"] for p in a.get("parameters", []))]
        if match:
            b = max(match, key=lambda x: x["number"])
            if seen != (b["number"], b["building"]):
                if tty and drew:
                    if not b["building"] and b["result"] == "SUCCESS":
                        print("\r  [%s] 100%%" % ("#" * 30), end="")
                    print()
                    drew = False
                print("{{name}} #%d %s" % (b["number"], "running" if b["building"] else b["result"]), flush=True)
                seen = (b["number"], b["building"])
            if b["building"]:
                # progress from Jenkins' own estimate of the build duration; plain dots when not on a terminal
                if tty:
                    est = max(b.get("estimatedDuration") or 0, 1)
                    frac = min((time.time() * 1000 - b["timestamp"]) / est, 0.99)
                    n = int(frac * 30)
                    print("\r  [%s%s] %3d%%" % ("#" * n, "-" * (30 - n), frac * 100), end="", flush=True)
                    drew = True
                else:
                    print(".", end="", flush=True)
                    drew = True
            if not b["building"]:
                if drew and not tty:
                    print(flush=True)
                    drew = False
                sys.exit(0 if b["result"] == "SUCCESS" else "build %s #%d finished with %s" % ("{{name}}", b["number"], b["result"]))
        elif seen is None:
            print("waiting for {{name}} build with {{key}}={{value}} to appear...", flush=True)
            seen = ()
        time.sleep(3)
    sys.exit("timeout waiting for {{name}} {{key}}={{value}}")

# Step 1-7: bump version, commit, tag, push master+tag together, wait for the tag build
release-test new:
    #!/usr/bin/env bash
    set -euo pipefail
    v="{{new}}"
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must look like 0.15.0"; exit 1; }
    [ "$(git branch --show-current)" = master ] || { echo "not on master"; exit 1; }
    [ -z "$(git status --porcelain)" ] || { echo "working tree not clean:"; git status --short; exit 1; }
    git fetch -q origin --tags
    [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/master)" ] || { echo "master is not in sync with origin/master"; exit 1; }
    ! git rev-parse -q --verify "refs/tags/$v" >/dev/null || { echo "tag $v already exists"; exit 1; }
    old=$(sed -n -E 's/^version = "([^"]+)"/\1/p' pyproject.toml | head -1)
    echo "current: $old"
    just _confirm "Bump to $v, push master, tag $v and push the tag?"
    just _step 2 "BUMP VERSION AND COMMIT"
    python3 - "$v" <<'PY'
    import re, sys
    p = "pyproject.toml"
    s = open(p).read()
    s, n = re.subn(r'(?m)^version = "[^"]+"', 'version = "%s"' % sys.argv[1], s, count=1)
    assert n == 1, "version line not found"
    open(p, "w").write(s)
    PY
    git add pyproject.toml
    git commit -m "Bump version $old -> $v"
    just _step 3 "TAG RELEASE $v"
    git tag -a "$v" -m "Release $v"
    just _step 4 "PUSH SUCM MASTER AND TAG"
    git push origin master "refs/tags/$v"
    just _step 5 "WAIT FOR SUCM TAG BUILD"
    # Only the tag build produces the release; the master build still runs via webhook but is not awaited
    just wait-build {{job}} branch "$v" || {
      echo "Tag build for $v failed. If the tag must be reused, remove it:"
      echo "  git tag -d $v && git push origin :refs/tags/$v"
      exit 1
    }
    echo "sucm $v built. Next: just update-cert-app $v"

# Step 8-9: pin the new sucm version in sua-cert-app, push, wait for its build
update-cert-app new:
    #!/usr/bin/env bash
    set -euo pipefail
    v="{{new}}"
    cd "{{cert_app_dir}}"
    [ "$(git branch --show-current)" = master ] || { echo "sua-cert-app: not on master"; exit 1; }
    [ -z "$(git status --porcelain)" ] || { echo "sua-cert-app: working tree not clean"; exit 1; }
    git pull -q --ff-only
    old=$(sed -n -E 's/^sucm==(.*)/\1/p' requirements.txt | head -1)
    echo "current: sucm==$old"
    just --justfile "{{justfile()}}" _confirm "Set sucm==$v in sua-cert-app/requirements.txt, commit and push?"
    just --justfile "{{justfile()}}" _step 6 "UPDATE SUA-CERT-APP REQUIREMENTS"
    sed -i.bak -E "s/^sucm==.*/sucm==$v/" requirements.txt && rm requirements.txt.bak
    git add requirements.txt
    git commit -m "Update sucm $old -> $v"
    just --justfile "{{justfile()}}" _step 7 "PUSH SUA-CERT-APP"
    git push origin master
    just --justfile "{{justfile()}}" _step 8 "WAIT FOR SUA-CERT-APP BUILD"
    just --justfile "{{justfile()}}" wait-build {{cert_app}} rev "$(git rev-parse HEAD)"
    echo "sua-cert-app built. Next: just deploy-test"

# Dry-run of salt (state.apply test=True) on a host; read-only
salt-dry host=test_host:
    ssh {{host}} 'sudo salt-call state.apply test=True' | tail -n 25

# Apply salt on a host and fail unless the summary says Failed: 0
[private]
_salt-apply host:
    #!/usr/bin/env bash
    set -euo pipefail
    out=$(ssh {{host}} 'sudo salt-call state.apply' 2>&1) || true
    echo "$out" | tail -n 12
    echo "$out" | grep -qE '^Failed: +0$' || { echo "salt reported failures"; exit 1; }

# Step 10: apply salt on sucm-test and restart apache
deploy-test: (salt-dry test_host) _deploy-test

# Salt apply + apache restart without the dry-run (used by `release`, which has already confirmed)
[private]
_deploy-test:
    @just _confirm "Apply salt and restart apache2 on {{test_host}}?"
    @just _step 9 "SALT APPLY ON TEST"
    @just _salt-apply {{test_host}}
    @just _step 10 "RESTART APACHE ON TEST"
    @ssh {{test_host}} 'sudo systemctl restart apache2.service && systemctl is-active apache2.service'

# Opt-in fast path: upgrade only the sua-cert-app package and restart apache (no salt, no other package upgrades; not used by `release`)
[private]
_upgrade-app host:
    ssh {{host}} 'sudo apt-get update -qq && sudo apt-get install -y --only-upgrade sua-cert-app && sudo systemctl restart apache2.service && systemctl is-active apache2.service'

# Quick deploy of the newest sua-cert-app build to test (for config changes in salt use deploy-test)
upgrade-test:
    just _confirm "Upgrade sua-cert-app and restart apache2 on {{test_host}}?"
    just _upgrade-app {{test_host}}

# Installed sucm version and apache state on a host (read-only)
sanity host=test_host:
    #!/usr/bin/env bash
    set -euo pipefail
    just _step 11 "SANITY CHECK"
    echo "installed: $(ssh {{host}} 'sudo /local/cert-app/bin/pip list 2>/dev/null | grep -i "^sucm "')"
    echo "apache2  : $(ssh {{host}} 'systemctl is-active apache2.service')"

# Prod promotion is an interactive Jenkins input step: prints the build form URL and what to do
promote-prod:
    #!/usr/bin/env bash
    set -euo pipefail
    set -a; . "${JENKINS_ENV:-$HOME/.config/jenkins/env}"; set +a
    echo "Open: ${JENKINS_URL%/}/job/{{cert_app}}/build?delay=0sec"
    echo "Build with parameters (branch=master, rest default), then answer the promotion prompt:"
    echo "choose the codename(s) to promote from test to prod. Watch with: just status {{cert_app}}"

# Deploy to prod with salt (needs SUCM_PROD_HOST), then restart apache
deploy-prod:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${SUCM_PROD_HOST:?set SUCM_PROD_HOST to the prod cert-app server fqdn}"
    just salt-dry "$SUCM_PROD_HOST"
    just _confirm "Apply salt and restart apache2 on PROD host $SUCM_PROD_HOST?"
    just _salt-apply "$SUCM_PROD_HOST"
    ssh "$SUCM_PROD_HOST" 'sudo systemctl restart apache2.service && systemctl is-active apache2.service'
    just sanity "$SUCM_PROD_HOST"

# If it stops half-way (a Jenkins build fails or times out), fix the cause and continue manually with
# the remaining steps (update-cert-app, deploy-test, sanity). One confirmation up front, stops at the first failure.
# Full test release: preflight, release-test, update-cert-app, salt apply + apache restart on test, sanity
release new:
    #!/usr/bin/env bash
    set -euo pipefail
    v="{{new}}"
    just _step 1 "PREFLIGHT CHECKS"
    just check
    just _preflight "$v"
    just version
    just _confirm "Release sucm $v to TEST (bump, tag, build, sua-cert-app, salt apply, apache restart)? Prod is not touched."
    export YES=1
    just release-test "$v"
    just update-cert-app "$v"
    just _deploy-test
    just sanity
    just _step 12 "DONE: RELEASE $v IS ON TEST"
    echo "Prod: just promote-prod, then just deploy-prod."
