"""app/callbacks.py

All Dash callbacks for the calculator.

Key design decisions
────────────────────
1.  A single ALL_BTNS pattern-match callback handles every button press.
    Keyboard input is funnelled through a clientside callback that writes
    a synthetic button ID into the kb-sink Input, which triggers the same
    server-side callback via a second Input.

2.  Calculator state lives in a dcc.Store (calc-state).  The callback
    reads the current state, applies the pressed action, and writes back
    new state + updated display props — all in one round trip.

3.  Identity is read from Flask's request context inside the callback
    (same request context as any plain Flask route) via get_current_user().
    The username is stamped into every calculation result.
"""
from __future__ import annotations

import math
import operator as op_module

from dash import Input, Output, State, ALL, callback, clientside_callback
from dash.exceptions import PreventUpdate

from .flask_oidc_identity import get_current_user


# ── Operator table ───────────────────────────────────────────────────────────

_OPS: dict = {
    "+": op_module.add,
    "-": op_module.sub,
    "×": op_module.mul,
    "÷": op_module.truediv,
    "%": op_module.mod,
}

_OP_KEYS = set(_OPS)      # {"+", "-", "×", "÷", "%"}
_DIGITS  = set("0123456789")


def _fmt(value: float | int) -> str:
    """Format a numeric result for display."""
    if isinstance(value, float) and value == int(value):
        return str(int(value))
    if isinstance(value, float):
        return str(round(value, 10))
    return str(value)


def _evaluate(a_str: str, operator: str, b_str: str):
    """Evaluate a binary operation. Returns (result_str, error_str)."""
    try:
        a = float(a_str)
        b = float(b_str)
        if operator == "÷" and b == 0:
            return None, "DIV / 0"
        result = _OPS[operator](a, b)
        return _fmt(result), None
    except Exception as exc:
        return None, str(exc)


def _apply_sqrt(a_str: str):
    try:
        a = float(a_str)
        if a < 0:
            return None, "√ of negative"
        return _fmt(math.sqrt(a)), None
    except Exception as exc:
        return None, str(exc)


# ── Main calculator callback ─────────────────────────────────────────────────

@callback(
    Output("calc-state",     "data"),
    Output("display-main",   "children"),
    Output("display-main",   "className"),
    Output("display-tape",   "children"),
    Output("display-author", "children"),
    Output("history-panel",  "children"),

    Input({"type": "calc-btn", "index": ALL}, "n_clicks"),
    Input("kb-sink", "value"),

    State("calc-state", "data"),
    State("identity-store", "data"),

    prevent_initial_call=True,
)
def handle_button(n_clicks_list, kb_value, state, identity):
    from dash import ctx

    # ── Determine which action was triggered ─────────────────────────────────
    triggered_id = ctx.triggered_id

    if triggered_id == "kb-sink":
        action = kb_value or ""
    elif isinstance(triggered_id, dict):
        action = triggered_id.get("index", "")
    else:
        raise PreventUpdate

    if not action:
        raise PreventUpdate

    # ── Clone state (dcc.Store returns a plain dict) ─────────────────────────
    s = dict(state)
    s["history"] = list(state.get("history", []))

    author_line = ""
    error_cls   = "display-main"
    error_cls_e = "display-main display-error"

    # ── Handle action ────────────────────────────────────────────────────────

    # Digits
    if action in _DIGITS:
        if s["fresh"]:
            s["display"] = action
            s["fresh"]   = False
        else:
            if len(s["display"].replace("-", "")) >= 14:
                pass  # silently cap
            elif s["display"] == "0":
                s["display"] = action
            else:
                s["display"] += action

    # Decimal point
    elif action == "dot":
        if s["fresh"]:
            s["display"] = "0."
            s["fresh"]   = False
        elif "." not in s["display"]:
            s["display"] += "."

    # Operators
    elif action.startswith("op_"):
        operator = action[3:]  # e.g. "op_+" → "+"

        # Chain: if there's already a pending op and a second operand, evaluate
        if s["op"] and not s["fresh"]:
            result, err = _evaluate(s["a"], s["op"], s["display"])
            if err:
                return s, err, error_cls_e, "", "", _render_history(s["history"])
            username = identity.get("name") or identity.get("username", "")
            expr = f"{s['a']} {s['op']} {s['display']}"
            s["history"].insert(0, {"expr": expr, "result": result, "by": username})
            if len(s["history"]) > 8:
                s["history"].pop()
            s["display"] = result
            author_line  = f"↳ {username}"

        s["a"]    = s["display"]
        s["op"]   = operator
        s["fresh"]= True

    # Equals
    elif action == "equals":
        if s["op"] is None or s["a"] is None:
            pass   # nothing pending
        else:
            result, err = _evaluate(s["a"], s["op"], s["display"])
            if err:
                s["op"] = None
                s["a"]  = None
                s["fresh"] = True
                return s, err, error_cls_e, "", "", _render_history(s["history"])

            username = identity.get("name") or identity.get("username", "")
            expr = f"{s['a']} {s['op']} {s['display']}"
            s["history"].insert(0, {"expr": expr, "result": result, "by": username})
            if len(s["history"]) > 8:
                s["history"].pop()

            author_line  = f"↳ computed for {username}"
            s["display"] = result
            s["a"]       = None
            s["op"]      = None
            s["fresh"]   = True

    # Square root
    elif action == "sqrt":
        result, err = _apply_sqrt(s["display"])
        if err:
            s["fresh"] = True
            return s, err, error_cls_e, "", "", _render_history(s["history"])
        username = identity.get("name") or identity.get("username", "")
        expr = f"√({s['display']})"
        s["history"].insert(0, {"expr": expr, "result": result, "by": username})
        if len(s["history"]) > 8:
            s["history"].pop()
        author_line  = f"↳ {username}"
        s["display"] = result
        s["a"]       = None
        s["op"]      = None
        s["fresh"]   = True

    # Clear
    elif action == "clear":
        s["display"] = "0"
        s["a"]       = None
        s["op"]      = None
        s["fresh"]   = True

    # Backspace
    elif action == "back":
        if s["fresh"] or len(s["display"]) <= 1:
            s["display"] = "0"
            s["fresh"]   = False
        else:
            s["display"] = s["display"][:-1]

    else:
        raise PreventUpdate

    # ── Assemble tape ────────────────────────────────────────────────────────
    tape = f"{s['a']} {s['op']}" if s["op"] and s["a"] is not None else ""

    return (
        s,
        s["display"],
        error_cls,
        tape,
        author_line,
        _render_history(s["history"]),
    )


def _render_history(entries: list) -> list:
    from dash import html as _html
    items = []
    for h in entries:
        items.append(
            _html.Div(className="history-row", children=[
                _html.Span(h["expr"],   className="h-expr"),
                _html.Span(f"= {h['result']}", className="h-result"),
            ])
        )
    return items


# ── Clientside callback: keyboard → kb-sink ──────────────────────────────────
# Maps physical key presses to the same action IDs the buttons use,
# then writes into the hidden kb-sink Input to trigger the server callback.

clientside_callback(
    """
    function(n) {
        if (!window._calcKbBound) {
            window._calcKbBound = true;
            document.addEventListener('keydown', function(e) {
                if (e.target.tagName === 'INPUT' && e.target.id !== 'kb-sink') return;
                const map = {
                    '0':'0','1':'1','2':'2','3':'3','4':'4',
                    '5':'5','6':'6','7':'7','8':'8','9':'9',
                    '.':'dot', ',':'dot',
                    '+':'op_+', '-':'op_-', '*':'op_×', 'x':'op_×',
                    '/':'op_÷', '%':'op_%',
                    'Enter':'equals', '=':'equals',
                    'Backspace':'back', 'Delete':'back', 'Escape':'clear',
                };
                const action = map[e.key];
                if (action) {
                    e.preventDefault();
                    const sink = document.getElementById('kb-sink');
                    if (sink) {
                        // Toggle a suffix to force a change event even for repeated keys
                        const toggle = sink.value.endsWith('_a') ? '_b' : '_a';
                        sink.value = action + toggle;
                        sink.dispatchEvent(new Event('input', {bubbles: true}));
                    }
                }
            });
        }
        return window.dash_clientside.no_update;
    }
    """,
    Output("kb-sink", "id"),   # dummy output — we just need the side-effect
    Input("kb-sink",  "n_submit"),
    prevent_initial_call=True,
)
