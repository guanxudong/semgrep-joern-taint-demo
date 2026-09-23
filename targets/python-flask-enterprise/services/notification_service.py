"""Notification rendering and delivery."""
from flask import render_template, render_template_string


class NotificationService:
    def render_preview(self, template_text):
        """Render an ad-hoc template so staff can preview e-mail copy."""
        return render_template_string(template_text)

    def render_welcome(self, username):
        return render_template("welcome.html", username=username)

    def send_welcome(self, user):
        body = self.render_welcome(user["username"])
        # delivery integration omitted; returns the rendered body
        return {"to": user["email"], "subject": "Welcome to OrderFlow",
                "body": body}


notification_service = NotificationService()
