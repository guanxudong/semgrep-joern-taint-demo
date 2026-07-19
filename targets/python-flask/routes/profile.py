"""Profile routes: mass assignment, privilege escalation, unsafe deserialization."""
import pickle

from flask import Blueprint, request, jsonify


class User:
    def __init__(self):
        self.username = ""
        self.email = ""
        self.role = "user"


profile_bp = Blueprint("profile", __name__, url_prefix="/profile")

USERS = {"alice": User()}


# VULN: py-mass-assignment-01 (mass-assignment, cwe-915)
# VULN: py-priv-esc-01 (priv-esc, cwe-269) - role accepted from body and persisted
@profile_bp.route("/update", methods=["POST"])
def update_profile():
    username = request.json.get("username", "")
    user = USERS.setdefault(username, User())
    for key, value in request.json.items():
        setattr(user, key, value)
    return jsonify({"username": user.username, "email": user.email, "role": user.role})


# VULN: py-deserialization-01 (deserialization, cwe-502) [medium]
@profile_bp.route("/import", methods=["POST"])
def import_profile():
    data = request.get_data()
    user = pickle.loads(data)
    USERS[user.username] = user
    return jsonify({"imported": user.username})
