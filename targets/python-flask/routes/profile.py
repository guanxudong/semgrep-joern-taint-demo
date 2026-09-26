"""Profile routes."""
import pickle

from flask import Blueprint, request, jsonify


class User:
    def __init__(self):
        self.username = ""
        self.email = ""
        self.role = "user"


profile_bp = Blueprint("profile", __name__, url_prefix="/profile")

USERS = {"alice": User()}


@profile_bp.route("/update", methods=["POST"])
def update_profile():
    username = request.json.get("username", "")
    user = USERS.setdefault(username, User())
    for key, value in request.json.items():
        setattr(user, key, value)
    return jsonify({"username": user.username, "email": user.email, "role": user.role})


@profile_bp.route("/import", methods=["POST"])
def import_profile():
    data = request.get_data()
    user = pickle.loads(data)
    USERS[user.username] = user
    return jsonify({"imported": user.username})
