from logging import Logger
from superset.security import SupersetSecurityManager

from flask_appbuilder.security.registerviews import BaseRegisterUser
from flask_appbuilder.forms import DynamicForm
from wtforms import PasswordField, StringField
from flask_babel import lazy_gettext
from wtforms.validators import DataRequired, Email, EqualTo
from flask_appbuilder.fieldwidgets import BS3PasswordFieldWidget, BS3TextFieldWidget


class RegisterUserDBFormNew(DynamicForm):
    username = StringField(
        lazy_gettext("User Name"),
        validators=[DataRequired()],
        widget=BS3TextFieldWidget(),
    )
    first_name = StringField(
        lazy_gettext("First Name"),
        validators=[DataRequired()],
        widget=BS3TextFieldWidget(),
    )
    last_name = StringField(
        lazy_gettext("Last Name"),
        validators=[DataRequired()],
        widget=BS3TextFieldWidget(),
    )
    email = StringField(
        lazy_gettext("Email"),
        validators=[DataRequired(), Email()],
        widget=BS3TextFieldWidget(),
    )
    password = PasswordField(
        lazy_gettext("Password"),
        description=lazy_gettext(
            "Please use a good password policy,"
            " this application does not check this for you"
        ),
        validators=[DataRequired()],
        widget=BS3PasswordFieldWidget(),
    )
    conf_password = PasswordField(
        lazy_gettext("Confirm Password"),
        description=lazy_gettext("Please rewrite the password to confirm"),
        validators=[EqualTo("password", message=lazy_gettext("Passwords must match"))],
        widget=BS3PasswordFieldWidget(),
    )

import logging
from flask_appbuilder.views import expose, PublicFormView
from flask_appbuilder import const as c
from flask_appbuilder._compat import as_unicode
from flask import flash, redirect

log = logging.getLogger(__name__)

class CustomRegisterUserDBView(BaseRegisterUser):
    """
    View for Registering a new user, auth db mode
    """

    form = RegisterUserDBFormNew
    redirect_url = "/"

    def send_email(self, register_user):
        logging.debug(f"\n\n================================== {register_user.registration_hash}")
        reg = self.appbuilder.sm.find_register_user(register_user.registration_hash)
        self.appbuilder.sm.add_user(
            username=reg.username,
            email=reg.email,
            first_name=reg.first_name,
            last_name=reg.last_name,
            role=self.appbuilder.sm.find_role(self.appbuilder.sm.auth_user_registration_role),
            hashed_password=reg.password,
        )
        self.appbuilder.sm.del_register_user(reg)
        return True

    def form_get(self, form):
        self.add_form_unique_validations(form)

    def form_post(self, form):
        self.add_form_unique_validations(form)
        self.add_registration(
            username=form.username.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            password=form.password.data,
        )

class MySecurityManager(SupersetSecurityManager):
    registeruserdbview = CustomRegisterUserDBView

    def __init__(self, appbuilder):
        super(MySecurityManager, self).__init__(appbuilder)