# Read-only helpers for the SUCM Jenkins jobs (REST API via curl).
# Credentials are read from ~/.config/jenkins/env (override with JENKINS_ENV):
#   JENKINS_URL=https://ci.it.su.se/
#   JENKINS_USER_ID=<user>
#   JENKINS_API_TOKEN=<token>

set shell := ["bash", "-euo", "pipefail", "-c"]

job := "sucm"

default:
    @just --list

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
