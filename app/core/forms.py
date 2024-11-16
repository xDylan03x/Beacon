from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, PasswordField, BooleanField, EmailField, SelectMultipleField
from wtforms.fields.simple import TelField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(""), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Log In')


class VerificationCodeForm(FlaskForm):
    code = StringField('Authentication Code', validators=[DataRequired()])
    submit = SubmitField('Submit')


class VerificationMethodForm(FlaskForm):
    method = SelectField('Method', validators=[DataRequired()])
    submit = SubmitField('Send Code')


class ForgotPasswordForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    submit = SubmitField('Submit')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


class ChangePasswordForm(FlaskForm):
    password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')


class ProfileSettingsForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    phone_number = TelField('Phone Number')
    submit = SubmitField('Save')


class SecuritySettingsForm(FlaskForm):
    two_factor_auth = BooleanField('Two-Factor Authentication')
    submit = SubmitField('Save')


class NewUserForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(""), Length(1, 64), Email()])
    submit = SubmitField('Create User')


class CreateAccountForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(""), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Create Account')


class EditUserForm(FlaskForm):
    admin = BooleanField('Admin')
    doctor = BooleanField('Doctor')
    patient = BooleanField('Patient')
    active = BooleanField('Active')
    submit = SubmitField('Save User')


class NewConversationForm(FlaskForm):
    doctors = SelectMultipleField('Doctors', coerce=str, choices=[], validators=[DataRequired()], validate_choice=False)
    patient = SelectField('Patient', coerce=str, choices=[], validate_choice=False)
    submit = SubmitField('Create Conversation')


class MessageForm(FlaskForm):
    message = StringField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')


class NoteForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Save')
