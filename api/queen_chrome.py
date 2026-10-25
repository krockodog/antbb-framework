"""Disabled: iframe chrome removed (same-origin queens)."""
def attach_queen_chrome(app):
    return {"ok": False, "disabled": True, "reason": "same-origin"}
