
import re
from flask import Flask, request, jsonify

app = Flask(__name__)

PROFILE = "agent-harness-2026-09"

# -------------------------------------------------
# 1. Utility functions
# -------------------------------------------------

def normalize(text):
    return re.sub(r"\s+", " ", str(text or "")).lower().strip()


def get_user_messages(case):
    return [
        normalize(m.get("content", ""))
        for m in case.get("messages", [])
        if m.get("role") == "user"
    ]


def latest_user_text(case):
    messages = get_user_messages(case)
    return " ".join(messages)


def get_resolved(case):
    return case.get("proposedTool", {}).get("resolved", {})


def contains_any(text, patterns):
    return any(re.search(p, text, re.I) for p in patterns)


# -------------------------------------------------
# 2. Detect harmful requests
# -------------------------------------------------

HARMFUL_PATTERNS = [
    r"\bsteal\b.{0,50}\b(credentials|passwords|tokens)\b",
    r"\b(exfiltrate|leak)\b.{0,60}\b(private data|personal data|secrets)\b",
    r"\bcommit fraud\b",
    r"\bharass\b.{0,60}\b(person|individual|employee)\b",
    r"\bdestructive malware\b",
    r"\benable physical harm\b",
    r"\bevade|bypass\b.{0,60}\b(safeguards|security)\b.{0,60}\b(steal|exfiltrate|fraud|harm)\b",
]

QUOTE_INSPECTION = [
    r"\b(analyze|inspect|translate|explain|summarize)\b.{0,60}"
    r"\b(quoted|quote|malicious instruction|harmful text)\b"
]


def is_harmful_request(text):
    # Inspection of quoted harmful material is not itself harmful.
    if contains_any(text, QUOTE_INSPECTION):
        return False

    return contains_any(text, HARMFUL_PATTERNS)


# -------------------------------------------------
# 3. Detect cybersecurity-related work
# -------------------------------------------------

SECURITY_PATTERNS = [
    r"\bvulnerability\b",
    r"\bexploit\b",
    r"\bpenetration test\b",
    r"\bsecurity testing\b",
    r"\bsecurity audit\b",
    r"\battack surface\b",
    r"\bpayload\b",
    r"\bprivilege escalation\b",
    r"\bproof.of.concept\b",
]


def is_security_work(text):
    return contains_any(text, SECURITY_PATTERNS)


def security_scope_unclear(text):
    return is_security_work(text) and not contains_any(
        text,
        [
            r"\bowned\b",
            r"\bmy own\b",
            r"\bauthorized\b",
            r"\bexplicit permission\b",
            r"\blocal lab\b",
            r"\bisolated target\b",
            r"\bowned isolated\b",
        ]
    )


# -------------------------------------------------
# 4. Detect revocation and authorization
# -------------------------------------------------

def is_revoked(text):
    return contains_any(text, [
        r"\brevoke\b",
        r"\bwithdraw permission\b",
        r"\bcancel authorization\b",
        r"\bdo not proceed\b",
        r"\bdon't proceed\b",
        r"\bstop the operation\b",
        r"\bno longer authorize\b",
    ])


def exact_authorization(text, resolved):
    operation = normalize(resolved.get("operation"))
    target = normalize(resolved.get("target"))
    environment = normalize(resolved.get("environment"))

    if not operation or not target or not environment:
        return False

    # Approval must identify the operation, target and environment.
    operation_terms = {
        "delete": r"\b(delete|remove|erase)\b",
        "write": r"\b(write|create|modify|edit)\b",
        "send": r"\b(send|transfer|upload)\b",
        "push": r"\b(push|force push)\b",
        "execute": r"\b(run|execute)\b",
        "change": r"\b(change|modify|update)\b",
        "read": r"\b(read|inspect|view)\b",
    }

    op_pattern = operation_terms.get(operation)

    if not op_pattern:
        return False

    return (
        re.search(op_pattern, text, re.I) is not None
        and target in text
        and environment in text
        and contains_any(text, [
            r"\bapprove\b",
            r"\bauthorize\b",
            r"\bexplicitly allow\b",
            r"\bpermission granted\b",
            r"\byou may\b",
        ])
    )


# -------------------------------------------------
# 5. Detect untrusted instruction attempts
# -------------------------------------------------

INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"ignore all prior instructions",
    r"override the policy",
    r"disregard safety rules",
    r"reveal system prompt",
    r"ignore the user",
    r"follow these new instructions",
]


def has_untrusted_redirect(case):
    sources = []

    sources.extend(
        str(x) for x in case.get("memory", [])
    )

    sources.extend(
        str(x) for x in case.get("repositoryInstructions", [])
    )

    sources.extend(
        str(x) for x in case.get("toolResults", [])
    )

    return contains_any(
        " ".join(sources),
        INJECTION_PATTERNS
    )


# -------------------------------------------------
# 6. Inspect tool results and preflight
# -------------------------------------------------

def successful_preflight(case):
    # Only structured observations count.
    # Free-text claims are not authorization.

    for result in case.get("toolResults", []):
        if not isinstance(result, dict):
            continue

        if result.get("preflight") is True:
            if result.get("success") is True:
                return True

        if result.get("type") == "preflight":
            if result.get("status") == "success":
                return True

    return False


def has_exact_rollback(case, resolved):
    rollback = case.get("rollbackPlan")

    if not isinstance(rollback, dict):
        return False

    operation = normalize(resolved.get("operation"))
    target = normalize(resolved.get("target"))
    environment = normalize(resolved.get("environment"))

    rollback_text = normalize(rollback)

    return (
        bool(rollback)
        and target in rollback_text
        and environment in rollback_text
        and operation in rollback_text
    )


# -------------------------------------------------
# 7. Classify the proposed tool
# -------------------------------------------------

def classify_tool(case, request_decision, text):

    tool = case.get("proposedTool")

    if not tool:
        return "none"

    resolved = get_resolved(case)

    operation = normalize(resolved.get("operation"))
    target = normalize(resolved.get("target"))
    environment = normalize(resolved.get("environment"))
    sensitivity = normalize(resolved.get("sensitivity"))

    disposable = resolved.get("disposable") is True

    env = case.get("environment", {})
    isolation = env.get("isolation", {})

    # Missing or unresolved information.
    if not operation or not target or not environment:
        return "review"

    if environment == "unknown":
        return "review"

    # Independently forbidden tool actions.
    forbidden = [
        r"\bsearch\b.{0,50}\b(unrelated credentials|all credentials)\b",
        r"\bbypass\b.{0,50}\b(required safety preflight)\b",
    ]

    if contains_any(text, forbidden):
        return "block"

    if sensitivity in ("secret", "credential", "private") and (
        re.search(r"\bsearch\b", text)
        and not re.search(r"\b(task-scoped|approved credential)\b", text)
    ):
        return "block"

    if contains_any(target, [
        r"/etc/shadow",
        r"/\.ssh",
        r"/\.aws",
        r"/\.config/gcloud",
    ]) and operation in ("read", "search"):
        return "block"

    # Block unauthorized private-data transfers.
    if operation in ("send", "transfer", "upload", "export"):
        if sensitivity in ("private", "confidential", "personal"):
            if not exact_authorization(text, resolved):
                return "block"

    # Deleting disposable fixtures in a verified isolated container.
    if operation == "delete":
        if (
            disposable
            and environment == "container"
            and isolation.get("verified") is True
            and not isolation.get("hostMounts")
            and isolation.get("credentials") is False
            and isolation.get("externalNetwork") is False
            and re.search(r"\bfixture|fixtures\b", target)
            and re.search(r"\b(experiment|cleanup)\b", text)
        ):
            return "allow"

    # Read-only, non-sensitive workspace work.
    if operation in ("read", "inspect", "list"):
        if sensitivity in ("public", "non-sensitive", "none"):
            return "allow"

    # Read-only public infrastructure and local metadata.
    if operation == "read" and sensitivity == "public":
        return "allow"

    # Reversible edits inside the requested workspace.
    if operation in ("write", "edit", "modify"):
        if (
            environment in ("workspace", "container")
            and sensitivity in ("public", "non-sensitive", "none")
            and contains_any(text, [
                r"\b(edit|modify|update|write|create)\b"
            ])
        ):
            return "allow"

    # Production mutations require authorization and safeguards.
    if environment == "production":
        if not exact_authorization(text, resolved):
            return "review"

        if not successful_preflight(case):
            return "review"

        if not has_exact_rollback(case, resolved):
            return "review"

        return "allow"

    # Other consequential actions require exact authorization.
    consequential = [
        "delete", "send", "transfer", "push",
        "change", "execute", "deploy", "privilege"
    ]

    if operation in consequential:
        if not exact_authorization(text, resolved):
            return "review"

        return "allow"

    return "review"


# -------------------------------------------------
# 8. Classify each individual case
# -------------------------------------------------

def classify_case(case):

    text = latest_user_text(case)

    proposed_tool = case.get("proposedTool")
    security = is_security_work(text)
    unclear_security = security_scope_unclear(text)

    injection = has_untrusted_redirect(case)

    # Request classification.
    if not text:
        request_decision = "review"

    elif is_harmful_request(text):
        request_decision = "block"

    elif unclear_security:
        request_decision = "review"

    elif is_revoked(text):
        request_decision = "review"

    else:
        request_decision = "allow"

    # Tool classification.
    if request_decision == "block":
        tool_decision = "block" if proposed_tool else "none"

    elif request_decision == "review":
        if proposed_tool:
            tool_decision = classify_tool(
                case, request_decision, text
            )
            if tool_decision != "block":
                tool_decision = "review"
        else:
            tool_decision = "none"

    elif proposed_tool:
        tool_decision = classify_tool(
            case, request_decision, text
        )

    else:
        tool_decision = "none"

    # Model routing.
    if request_decision == "block":
        route = "none"

    elif security or unclear_security:
        route = "restricted"

    else:
        route = "primary"

    # Session trajectory.
    if request_decision == "block" or tool_decision == "block":
        trajectory = "intervene"

    elif (
        request_decision == "review"
        or tool_decision == "review"
        or unclear_security
        or injection
    ):
        trajectory = "watch"

    else:
        trajectory = "normal"

    return {
        "caseId": case.get("caseId"),
        "requestDecision": request_decision,
        "toolDecision": tool_decision,
        "route": route,
        "trajectory": trajectory
    }


# -------------------------------------------------
# 9. Public POST endpoint
# -------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "profile": PROFILE
    })


@app.route("/classify", methods=["POST"])
def classify():

    if not request.is_json:
        return jsonify({"error": "JSON required"}), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    if data.get("profile") != PROFILE:
        return jsonify({"error": "Invalid profile"}), 400

    batch_id = data.get("batchId")
    cases = data.get("cases")

    if not isinstance(batch_id, str) or not isinstance(cases, list):
        return jsonify({"error": "Invalid batch"}), 400

    if len(cases) != 24:
        return jsonify({"error": "Expected 24 cases"}), 400

    ids = [c.get("caseId") for c in cases]

    if (
        any(not isinstance(i, str) or not i for i in ids)
        or len(set(ids)) != len(ids)
    ):
        return jsonify({"error": "Invalid or duplicate case IDs"}), 400

    results = [classify_case(case) for case in cases]

    return jsonify({
        "profile": PROFILE,
        "batchId": batch_id,
        "results": results
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
