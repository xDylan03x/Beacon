from flask_login import current_user
from flask_admin.contrib.sqla import ModelView
from flask import redirect, url_for, request


class SecureAdminView(ModelView):
    def is_accessible(self):
        return True
        # if current_user.is_authenticated:
        #     return current_user.get_role("admin")
        # return False

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for("core.login", next=request.url))
