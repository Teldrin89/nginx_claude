"""app/routes.py — Calculator routes."""
import math
import operator
from flask import Blueprint, render_template, request, jsonify
from .flask_oidc_identity import current_user, require_auth

bp = Blueprint("main", __name__)


# ---------------------------------------------------------------------------
# Main page — authentication required
# ---------------------------------------------------------------------------

@bp.route("/")
@require_auth
def index():
    return render_template("calculator.html", user=current_user)


# ---------------------------------------------------------------------------
# API — evaluate a single arithmetic operation
# Input JSON: { "a": float, "op": str, "b": float }
# ---------------------------------------------------------------------------

_OPS = {
    "+": operator.add,
    "-": operator.sub,
    "×": operator.mul,
    "÷": operator.truediv,
    "%": operator.mod,
    "^": operator.pow,
    "√": None,   # unary
}

@bp.route("/api/calculate", methods=["POST"])
@require_auth
def calculate():
    data = request.get_json(silent=True) or {}
    op   = data.get("op", "+")
    b    = data.get("b")

    try:
        a = float(data.get("a", 0))

        if op == "√":
            if a < 0:
                return jsonify({"error": "√ of negative number"}), 400
            result = math.sqrt(a)
        else:
            if b is None:
                return jsonify({"error": "Missing operand b"}), 400
            b = float(b)
            fn = _OPS.get(op)
            if fn is None:
                return jsonify({"error": f"Unknown operator: {op}"}), 400
            if op == "÷" and b == 0:
                return jsonify({"error": "Division by zero"}), 400
            result = fn(a, b)

    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    # Trim excessive floating-point noise
    if isinstance(result, float) and result == int(result):
        result = int(result)
    elif isinstance(result, float):
        result = round(result, 10)

    return jsonify({
        "result": result,
        "computed_by": current_user.username,   # echo who calculated it
    })


# ---------------------------------------------------------------------------
# Whoami — returns the current user's identity as JSON (useful for debugging)
# ---------------------------------------------------------------------------

@bp.route("/api/whoami")
@require_auth
def whoami():
    return jsonify(current_user.to_dict())


# ---------------------------------------------------------------------------
# Health probe (unauthenticated — nginx passes this through)
# ---------------------------------------------------------------------------

@bp.route("/health")
def health():
    return "ok", 200


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@bp.app_errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Not authenticated"}), 401

@bp.app_errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Forbidden"}), 403
