"""app/layout.py

Dash layout for the calculator.
Called once at startup; receives the boot-time identity snapshot
(extracted during the index_string hook, before any callback fires).

Aesthetic: art-deco geometric — cream + deep teal + gold rule lines,
           Cinzel display / DM Mono numeric face.
"""
from dash import dcc, html


# ── External font imports ────────────────────────────────────────────────────
FONTS = (
    "https://fonts.googleapis.com/css2?"
    "family=Cinzel:wght@400;700&"
    "family=DM+Mono:wght@300;400;500&"
    "display=swap"
)


def make_button(label: str, btn_id: str, extra_classes: str = "") -> html.Button:
    return html.Button(
        label,
        id={"type": "calc-btn", "index": btn_id},
        className=f"calc-btn {extra_classes}",
        n_clicks=0,
    )


def build_layout(user_name: str, user_email: str, user_sub: str) -> html.Div:
    """Return the full page layout, stamped with the authenticated identity."""

    return html.Div(
        className="page-root",
        children=[

            # ── Google Fonts ────────────────────────────────────────────────
            html.Link(rel="stylesheet", href=FONTS),

            # ── Hidden stores ───────────────────────────────────────────────
            # calc-state persists the calculator's machine state across callbacks
            dcc.Store(id="calc-state", data={
                "display": "0",
                "a": None,
                "op": None,
                "fresh": True,
                "history": [],
            }),
            # identity store — read-only, populated at layout build time
            dcc.Store(id="identity-store", data={
                "name": user_name,
                "email": user_email,
                "sub": user_sub,
            }),

            # ── Header ──────────────────────────────────────────────────────
            html.Header(className="site-header", children=[
                html.Div(className="header-left", children=[
                    html.Span("◈", className="logo-glyph"),
                    html.Span("ARITHMOS", className="wordmark"),
                ]),
                html.Div(className="header-right", children=[
                    html.Div(className="user-badge", children=[
                        html.Span("▪", className="status-dot"),
                        html.Span(user_name,  className="user-name"),
                        html.Span(user_email, className="user-email"),
                    ]),
                    html.A("SIGN OUT", href="/oidc/logout", className="signout-btn"),
                ]),
            ]),

            # ── Main ────────────────────────────────────────────────────────
            html.Main(className="main-area", children=[
                html.Div(className="calculator-frame", children=[

                    # Decorative corner marks
                    html.Div(className="corner tl"), html.Div(className="corner tr"),
                    html.Div(className="corner bl"), html.Div(className="corner br"),

                    # ── Display panel ────────────────────────────────────────
                    html.Div(className="display-panel", children=[
                        html.Div(id="display-tape",  className="display-tape",  children=""),
                        html.Div(id="display-main",  className="display-main",  children="0"),
                        html.Div(id="display-author",className="display-author",children=""),
                    ]),

                    # ── History ──────────────────────────────────────────────
                    html.Div(id="history-panel", className="history-panel", children=[]),

                    # ── Divider ──────────────────────────────────────────────
                    html.Div(className="gold-rule"),

                    # ── Button grid ──────────────────────────────────────────
                    html.Div(className="btn-grid", children=[

                        # Row 1 — functions
                        make_button("AC",  "clear",  "btn-fn btn-clr"),
                        make_button("⌫",   "back",   "btn-fn btn-clr"),
                        make_button("%",   "op_%",   "btn-op"),
                        make_button("÷",   "op_÷",   "btn-op"),

                        # Row 2
                        make_button("7",   "7"),
                        make_button("8",   "8"),
                        make_button("9",   "9"),
                        make_button("×",   "op_×",   "btn-op"),

                        # Row 3
                        make_button("4",   "4"),
                        make_button("5",   "5"),
                        make_button("6",   "6"),
                        make_button("−",   "op_-",   "btn-op"),

                        # Row 4
                        make_button("1",   "1"),
                        make_button("2",   "2"),
                        make_button("3",   "3"),
                        make_button("＋",  "op_+",   "btn-op"),

                        # Row 5
                        make_button("√x",  "sqrt",   "btn-fn"),
                        make_button("0",   "0"),
                        make_button("·",   "dot"),
                        make_button("=",   "equals", "btn-eq"),

                    ]),

                ]),
            ]),

            # ── Footer ──────────────────────────────────────────────────────
            html.Footer(className="site-footer", children=[
                html.Span(f"Microsoft Entra ID  ·  session {user_sub[:8]}…",
                          className="footer-note"),
            ]),

            # ── Keyboard listener (clientside) ───────────────────────────────
            # We piggyback on an invisible button that the clientside callback
            # writes the last key into, which then triggers the main callback.
            dcc.Input(id="kb-sink", type="hidden", value=""),

        ]
    )
