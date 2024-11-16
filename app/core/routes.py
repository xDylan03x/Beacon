import os
from datetime import timedelta
from functools import wraps
from twilio.twiml.voice_response import VoiceResponse, Dial
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash, abort, make_response, session, Response,
)
from flask_login import login_user, current_user, logout_user, login_required, fresh_login_required
import phonenumbers
from twilio.base.exceptions import TwilioRestException
from app import app, twilio_client
from app.models import *  # TODO optimize
from .forms import *  # TODO optimize
from .utils import clean_args, validate_next_url, verify_tab_request, send_email, transcribe_audio, summarize_audio

core = Blueprint("core", __name__, template_folder="templates")


def track_user(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        response = f(*args, **kws)
        response = make_response(response)

        identifier = request.cookies.get("device_identifier", None)
        device_id = request.cookies.get("device_id", None)

        if device_id:
            device = Device.query.filter_by(alternate_id=device_id).first()
            if device:
                if identifier != device.identifier and identifier is not None:
                    device.identifier = identifier
                    db.session.commit()
            else:
                device = Device()
                db.session.add(device)
                db.session.commit()
                response.set_cookie(
                    "device_id",
                    device.alternate_id,
                    expires=datetime.now(tz=timezone.utc) + timedelta(days=365),
                    httponly=True,
                )
        else:
            device = Device.query.filter_by(identifier=identifier).first()
            if device:
                response.set_cookie(
                    "device_id",
                    device.alternate_id,
                    expires=datetime.now(tz=timezone.utc) + timedelta(days=365),
                    httponly=True,
                )
            else:
                if identifier:
                    device = Device(identifier=identifier)
                    db.session.add(device)
                    db.session.commit()
                    response.set_cookie(
                        "device_id",
                        device.alternate_id,
                        expires=datetime.now(tz=timezone.utc) + timedelta(days=365),
                        httponly=True,
                    )

        return response
    return decorated_function


@app.context_processor
def utility_processor():
    def get_system_setting(name):
        setting_record = SystemSetting.query.filter_by(name=name).first()
        if setting_record is None:
            return False
        else:
            return setting_record.value

    return dict(get_system_setting=get_system_setting)


@app.context_processor
def utility_processor():
    def get_system_setting_time(name):
        setting_record = SystemSetting.query.filter_by(name=name).first()
        if setting_record is None:
            return False
        else:
            return setting_record.last_updated_timestamp

    return dict(get_system_setting_time=get_system_setting_time)


@core.route("/")
@track_user
def index():
    return render_template("index.html")


@core.route("/dashboard")
@track_user
@login_required
def dashboard():
    conversations = Conversation.query.filter(Conversation.users.any(id=current_user.id)).all()
    return render_template("admin/dashboard.html", title="Dashboard", conversations=conversations)


@core.route("/conversations/<alt_id>")
@track_user
@login_required
def conversation(alt_id):
    conversation_record = Conversation.query.filter_by(alternate_id=alt_id).first_or_404()
    if (not current_user.get_role("admin")) and (current_user not in conversation_record.users):
        abort(403)
    if conversation_record.phone_call_id:
        phone_call = PhoneCall.query.get(conversation_record.phone_call_id)
    else:
        phone_call = None
    return render_template("conversation.html", conversation=conversation_record, phone_call=phone_call, title="Conversation")


@core.route("/conversations/<alt_id>/messages", methods=["GET", "POST"])
@track_user
@login_required
def conversation_messages(alt_id):
    conversation_record = Conversation.query.filter_by(alternate_id=alt_id).first_or_404()
    if (not current_user.get_role("admin")) and (current_user not in conversation_record.users):
        abort(403)

    messages = Message.query.filter_by(conversation_id=conversation_record.id).all()
    return render_template("conversation-messages.html", messages=messages)


@core.route("/conversations/<alt_id>/send", methods=["GET", "POST"])
@track_user
@login_required
def conversation_form(alt_id):
    conversation_record = Conversation.query.filter_by(alternate_id=alt_id).first_or_404()
    if (not current_user.get_role("admin")) and (current_user not in conversation_record.users):
        abort(403)

    form = MessageForm()
    if form.validate_on_submit():
        message = Message(
            content=form.message.data,
            user_id=current_user.id,
            conversation_id=conversation_record.id
        )
        db.session.add(message)
        conversation_record.conversation_last_updated_timestamp = datetime.now(tz=timezone.utc)
        db.session.commit()

    return render_template("conversation-form.html", form=form, conversation=conversation_record)


@core.route("/conversations/<alt_id>/notes", methods=["GET", "POST"])
@track_user
@login_required
def conversation_notes(alt_id):
    conversation_record = Conversation.query.filter_by(alternate_id=alt_id).first_or_404()
    if (not current_user.get_role("admin")) and (current_user not in conversation_record.users):
        abort(403)
    note = Note.query.filter_by(conversation_id=conversation_record.id, user_id=current_user.id).first()

    form = NoteForm()
    if form.validate_on_submit():
        if note:
            note.content = form.content.data
        else:
            note = Note(
                content=form.content.data,
                user_id=current_user.id,
                conversation_id=conversation_record.id
            )
            db.session.add(note)
        db.session.commit()

    form.content.data = note.content
    return render_template("conversation-notes.html", form=form, note=note, conversation=conversation_record)


@core.route("/conversations/new", methods=["GET", "POST"])
@track_user
@login_required
def new_conversation():
    form = NewConversationForm()
    if form.validate_on_submit():
        conversation = Conversation()
        db.session.add(conversation)
        db.session.commit()
        for doctor in form.doctors.data:
            doctor_record = User.query.filter_by(alternate_id=doctor).first()
            if doctor_record:
                conversation.users.append(doctor_record)
        patient = User.query.filter_by(alternate_id=form.patient.data).first()
        if patient:
            conversation.users.append(patient)
        else:
            conversation.users.append(current_user)
        db.session.commit()
        for user in conversation.users:
            note = Note(conversation_id=conversation.id, user_id=user.id)
            db.session.add(note)
        db.session.commit()
        flash("Conversation has been created.", "success")
        return redirect(url_for("core.conversation", alt_id=conversation.alternate_id))

    doctors = User.query.join(Role).filter(
        Role.name == "doctor",
        Role.value == True,
        User.active == True,
        User.deleted != True
    ).all()
    form.doctors.choices = [(doctor.alternate_id, doctor.name) for doctor in doctors]

    patients = User.query.join(Role).filter(
        Role.name == "patient",
        Role.value == True,
        User.active == True,
        User.deleted != True
    ).all()
    form.patient.choices = [(patient.alternate_id, patient.name) for patient in patients]
    if current_user.get_role('patient'):
        form.patient.choices = [(current_user.alternate_id, current_user.name)]

    return render_template("new-conversation.html", form=form, title="New Conversation")


@core.route("/incoming-call", methods=["POST"])
def receive_call():
    incoming_call = PhoneCall()
    incoming_call.populate_from_request(request.form)
    db.session.add(incoming_call)
    db.session.commit()
    response = VoiceResponse()
    dial = Dial(
        record="record-from-answer",
        recordingStatusCallback=url_for("core.log_recording"),
    )
    dial.number("+12294123111", statusCallback=url_for("core.update_call_status"))
    response.append(dial)
    return str(response)


@core.route("/log-recording", methods=["POST"])
def log_recording():
    sid = request.form.get("CallSid")
    call = PhoneCall.query.filter_by(call_sid=sid).first()
    if call:
        call.recording_sid = request.form.get("RecordingSid")
        call.recording_url = request.form.get("RecordingUrl")
        call.recording_status = request.form.get("RecordingStatus")
        call.recording_duration = request.form.get("RecordingDuration")
        # Create transcription, conversation, and notes. Add transcription to conversation summary, add AI summary to all notes
        transcription = transcribe_audio(call.recording_url, os.path.join(app.config["UPLOAD_FOLDER"], f"{sid}.wav"))
        summary = summarize_audio(transcription)
        call.transcription = transcription
        conversation_record = Conversation(summary=transcription, phone_call_id=call.id)
        db.session.add(conversation_record)
        db.session.commit()
        doctors = User.query.join(Role).filter(
            Role.name == "doctor",
            Role.value == True,
            User.active == True,
            User.deleted != True
        ).all()
        for doctor in doctors:
            conversation_record.users.append(doctor)
        patient = User.query.filter_by(phone_number=call.from_number).first()
        if patient:
            conversation_record.users.append(patient)
        db.session.commit()
        for user in conversation_record.users:
            note = Note(conversation_id=conversation_record.id, user_id=user.id, content=summary)
            db.session.add(note)
        db.session.commit()
    return Response(status=204)


@core.route("/update-call-status", methods=["POST"])
def update_call_status():
    parent_sid = request.form.get("ParentCallSid")
    final_sid = request.form.get("CallSid")
    final_to_number = request.form.get("To")
    status = request.form.get("CallStatus")
    call = PhoneCall.query.filter_by(call_sid=parent_sid).first()
    if call:
        call.call_status = status
        call.final_call_sid = final_sid
        call.final_to_number = final_to_number
        db.session.commit()
    return Response(status=201)


@core.route("/settings", methods=["GET", "POST"])
@track_user
@fresh_login_required
def settings():
    tab = request.args.get("tab", "profile")
    htmx = 'HX-Request' in request.headers
    verify_tab_request(["profile", "security"], tab)

    user = User.query.get(current_user.id)

    if tab == "profile":
        form = ProfileSettingsForm()
        if form.validate_on_submit():
            user.name = form.name.data
            try:
                pn = phonenumbers.parse(form.phone_number.data, "US")
                if phonenumbers.is_valid_number(pn):
                    user.phone_number_verified = True  # TODO verify phone number via secondary step (send code/verify)
                    user.phone_number_verified_timestamp = datetime.now(tz=timezone.utc)
                else:
                    flash("Phone number is not valid", "warning")
                    user.phone_number_verified = False
                user.phone_number = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)
            except phonenumbers.NumberParseException:
                flash("Error validating phone number", "error")
            db.session.commit()
            flash("Your settings have been saved", "success")
    elif tab == "security":
        form = SecuritySettingsForm()
        if form.validate_on_submit():
            user.two_factor_auth = form.two_factor_auth.data
            db.session.commit()
            flash("Your settings have been saved", "success")

    if tab == "profile" and htmx:
        form.name.data = current_user.name
        form.phone_number.data = current_user.phone_number
        return render_template("admin/settings/profile.html", form=form)
    elif tab == "security" and htmx:
        form.two_factor_auth.data = current_user.two_factor_auth
        return render_template("admin/settings/security.html", form=form)
    return render_template("admin/settings/settings.html", title="Account Settings")


@core.route("/users", methods=["GET", "POST"])
@track_user
@login_required
def users():
    if not current_user.get_role("admin"):
        abort(403)

    tab = request.args.get("tab", "all-users")
    htmx = 'HX-Request' in request.headers
    verify_tab_request(["all-users", "new", "edit"], tab)
    alt_id = request.args.get("alt_id", None)

    if tab == "new":
        form = NewUserForm()
        if form.validate_on_submit():
            user = User(
                username=''.join(e for e in form.name.data if e.isalpha()).lower(),
                email=form.email.data,
                name=form.name.data,
                password_reset=True
            )
            db.session.add(user)
            db.session.commit()
            db.session.add(Role(name="admin", value=False, user_id=user.id))
            db.session.add(Role(name="doctor", value=False, user_id=user.id))
            db.session.add(Role(name="patient", value=False, user_id=user.id))
            db.session.commit()
            token = Token(user_id=user.id)
            token.value = str(uuid.uuid4())
            db.session.add(token)
            db.session.commit()
            flash("User has been created.", "success")
            return redirect(url_for("core.users", tab="all-users"))
    elif tab == "edit":
        form = EditUserForm()
        if form.validate_on_submit():
            user = User.query.filter_by(alternate_id=alt_id).first_or_404()
            if not (not current_user.get_role("admin") and user.get_role("admin")):
                user.set_role("admin", form.admin.data)
            user.set_role("doctor", form.doctor.data)
            user.set_role("patient", form.patient.data)
            if user.active and not form.active.data:
                user.refresh_alt_id()
            user.active = form.active.data
            db.session.commit()
            flash("User has been saved.", "success")
            return redirect(url_for("core.users", tab="all-users"))

    if tab == "all-users" and htmx:
        all_users = User.query.filter(User.deleted != True).all()
        return render_template("admin/users/all-users.html", all_users=all_users)
    elif tab == "new" and htmx:
        return render_template("admin/users/new.html", form=form)
    elif tab == "edit" and htmx:
        user = User.query.filter_by(alternate_id=alt_id).first_or_404()
        form.admin.data = user.get_role("admin")
        form.doctor.data = user.get_role("doctor")
        form.patient.data = user.get_role("patient")
        form.active.data = user.active
        return render_template("admin/users/edit.html", form=form, user=user)
    return render_template("admin/users/users.html", title="Users")


@core.route("/settings/change-password", methods=["GET", "POST"])
@track_user
@login_required
def change_password():
    next_url = request.args.get("next", None)
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            current_user.set_password(form.new_password.data)
            current_user.password_last_changed_timestamp = datetime.now(tz=timezone.utc)
            current_user.refresh_alt_id()
            db.session.commit()
            login_user(current_user)
            flash("Your password has been changed.", "success")
            return redirect(validate_next_url(next_url) or url_for("core.settings", tab="security"))
        else:
            flash("Your password is incorrect.", "error")
    return render_template("admin/settings/change-password.html", form=form, title="Change Password")


@core.route("/sign-up", methods=["GET", "POST"])
@track_user
def sign_up():
    form = CreateAccountForm()
    if form.validate_on_submit():
        user = User(
            username=''.join(e for e in form.name.data if e.isalpha()).lower(),
            email=form.email.data,
            name=form.name.data,
            password_reset=True
        )
        db.session.add(user)
        db.session.commit()
        user.set_password(form.password.data)
        user.password_reset = False
        user.password_last_changed_timestamp = datetime.now(tz=timezone.utc)
        db.session.add(Role(name="admin", value=False, user_id=user.id))
        db.session.add(Role(name="doctor", value=False, user_id=user.id))
        db.session.add(Role(name="patient", value=True, user_id=user.id))
        db.session.commit()
        login_user(user)
        flash("Your account has been created. Welcome to Beacon! You can setup your account in settings.", "success")
        return redirect(url_for("core.settings"))
    return render_template("sign-up.html", form=form, title="Sign Up")


@core.route("/login", methods=["GET", "POST"])
@track_user
def login():
    next_url = request.args.get("next", None)
    device_alt_id = request.cookies.get("device_id", None)

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        password = form.password.data
        remember = form.remember_me.data

        user = User.query.filter_by(email=email).first()
        if user and not user.deleted:
            if user.active:
                if not user.password_reset and user.verify_password(password):
                    if user.two_factor_auth:
                        token = Token(user_id=user.id)
                        token.value = str(uuid.uuid4())
                        db.session.add(token)
                        db.session.commit()
                        return redirect(
                            url_for(
                                "core.verification",
                                alt_id=user.alternate_id,
                                token=token.value,
                                remember=remember,
                                **clean_args(request.args, ["remember", "token"])
                            )
                        )
                    else:
                        if device_alt_id:
                            device = Device.query.filter_by(
                                alternate_id=device_alt_id
                            ).first()
                            logins = Login.query.filter_by(user_id=user.id).all()
                            for login_record in logins:
                                if login_record.user_id == user.id:
                                    login_record = Login(
                                        user_id=user.id, device_id=device.id
                                    )
                                    db.session.add(login_record)
                                    db.session.commit()
                                    login_user(user, remember)
                                    return redirect(
                                        validate_next_url(next_url)
                                        or url_for("core.dashboard")
                                    )
                            token = Token(user_id=user.id)
                            token.value = str(uuid.uuid4())
                            db.session.add(token)
                            db.session.commit()
                            return redirect(
                                url_for(
                                    "core.verification",
                                    alt_id=user.alternate_id,
                                    token=token.value,
                                    remember=remember,
                                    **clean_args(request.args, ["remember", "token"])
                                )
                            )
                        else:
                            token = Token(user_id=user.id)
                            token.value = str(uuid.uuid4())
                            db.session.add(token)
                            db.session.commit()
                            return redirect(
                                url_for(
                                    "core.verification",
                                    alt_id=user.alternate_id,
                                    token=token.value,
                                    remember=remember,
                                    **clean_args(request.args, ["remember", "token"])
                                )
                            )
                else:
                    flash("Email or password is incorrect.", "error")
            else:
                flash(
                    "Account is not active. Contact an administrator for help.", "error"
                )
        else:
            flash("Email or password is incorrect.", "error")
    if current_user.is_authenticated:
        form.email.data = current_user.email
    return render_template("admin/login.html", form=form, next=next_url, title="Log In")


@core.route("/verification/<alt_id>", methods=["GET", "POST"])
@track_user
def verification(alt_id):
    user = User.query.filter_by(alternate_id=alt_id).first_or_404()
    token_value = request.args.get("token", None)
    next_url = request.args.get("next", None)
    device_alt_id = request.cookies.get("device_id", None)
    remember = request.args.get("remember", False)
    remember = True if remember == "True" else False
    method = request.args.get("method", None)
    reset = request.args.get("reset", None)
    code_sent = request.args.get("code_sent", False)

    if not token_value:
        return redirect(url_for("core.login"))
    else:
        token = Token.query.filter_by(value=token_value).first()
        if not token or token.used:
            return redirect(url_for("core.login"))

    if code_sent:
        form = VerificationCodeForm()
        if form.validate_on_submit():
            if len(form.code.data) == 6:
                if method:
                    to = user.email
                    if method == "Text" and user.phone_number_verified:
                        to = user.phone_number
                    try:
                        verify = twilio_client.verify.v2.services(
                            app.config["TWILIO_VERIFY_SERVICE_SID"]
                        ).verification_checks.create(to=to, code=form.code.data)
                        if verify.status == "approved":
                            if reset:
                                user.password_reset = True
                                db.session.commit()
                                return redirect(
                                    url_for(
                                        "core.reset_password",
                                        alt_id=alt_id,
                                        token=token_value,
                                        next=next_url,
                                    )
                                )
                            else:
                                if device_alt_id:
                                    device = Device.query.filter_by(
                                        alternate_id=device_alt_id
                                    ).first()
                                    login_record = Login(
                                        user_id=user.id, device_id=device.id
                                    )
                                else:
                                    login_record = Login(user_id=user.id)
                                token.used = True
                                db.session.add(login_record)
                                db.session.commit()
                                login_user(user, remember)
                                return redirect(
                                    validate_next_url(next_url)
                                    or url_for("core.dashboard")
                                )
                        else:
                            flash("The authentication code is incorrect.", "error")
                    except TwilioRestException as e:
                        flash("The authentication code is incorrect.", "error")
            else:
                flash("The authentication code is incorrect.", "error")
        resend_url = url_for(
            "core.verification",
            alt_id=alt_id,
            token=token_value,
            remember=remember,
            reset=reset,
            next=next_url,
        )
        return render_template(
            "admin/verification-code.html",
            form=form,
            resend_url=resend_url,
            title="Multi-Factor Authentication",
        )

    else:
        form = VerificationMethodForm()
        form.method.choices = ["Email"]
        if user.phone_number_verified:
            form.method.choices.append("Text")
        if form.validate_on_submit():
            if form.method.data == "Email":
                twilio_client.verify.v2.services(
                    app.config["TWILIO_VERIFY_SERVICE_SID"]
                ).verifications.create(channel="email", to=user.email)
            elif form.method.data == "Text":
                twilio_client.verify.v2.services(
                    app.config["TWILIO_VERIFY_SERVICE_SID"]
                ).verifications.create(channel="sms", to=user.phone_number)
            flash(
                "A verification code has been sent. This code will expire in 10 minutes.",
                "success",
            )
            return redirect(
                url_for(
                    "core.verification",
                    alt_id=alt_id,
                    token=token_value,
                    method=form.method.data,
                    code_sent=True,
                    reset=reset,
                    remember=remember,
                    next=next_url,
                )
            )
        return render_template(
            "admin/verification-method.html",
            form=form,
            title="Multi-Factor Authentication",
        )


@core.route("/forgot-password", methods=["GET", "POST"])
@track_user
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        user = User.query.filter_by(email=email).first()
        if user and not user.deleted:
            if user.active:
                token = Token(user_id=user.id)
                token.value = str(uuid.uuid4())
                db.session.add(token)
                db.session.commit()
                return redirect(
                    url_for(
                        "core.verification",
                        alt_id=user.alternate_id,
                        token=token.value,
                        reset=True,
                        **clean_args(request.args)
                    )
                )
            else:
                flash("Account is not active. Contact an administrator for help.", "error")
        else:
            flash("There is no account associated with that email.", "error")
    return render_template("admin/forgot-password.html", form=form, title="Forgot Password")


@core.route("/reset-password/<alt_id>", methods=["GET", "POST"])
@track_user
def reset_password(alt_id):
    token_value = request.args.get("token", None)
    user = User.query.filter_by(alternate_id=alt_id).first_or_404()
    if not user.password_reset:
        flash("There was an error resetting your password.", "error")
        return redirect(url_for("core.login", **clean_args(request.args)))

    if not token_value:
        return redirect(url_for("core.login"))
    else:
        token = Token.query.filter_by(value=token_value).first()
        if not token or token.used:
            return redirect(url_for("core.login"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.password_reset = False
        user.password_last_changed_timestamp = datetime.now(tz=timezone.utc)
        user.refresh_alt_id()
        token.used = True
        db.session.commit()
        send_email(
            "Password Reset",
            "Your password has been reset. If this was not you, please take action to secure your account.",
            [user.email],
            "Please take action to secure your account",
        )
        flash("Your password has been reset.", "success")
        return redirect(url_for("core.login", **clean_args(request.args, ["token"])))
    return render_template(
        "admin/reset-password.html", form=form, title="Reset Password"
    )


@core.route('/lockdown-account/<alt_id>')
@track_user
@login_required
def lockdown_account(alt_id):
    if not (current_user.get_role("admin") or current_user.get_role(
            "patient")) and current_user.alternate_id != alt_id:
        abort(403)
    user = User.query.filter_by(alternate_id=alt_id).first_or_404()
    user.phone_number_verified = False
    user.active = False
    user.refresh_alt_id()
    roles = Role.query.filter_by(user_id=user.id).all()
    for role in roles:
        role.value = False
    db.session.commit()
    logout_user()
    admins = []
    for role in Role.query.filter_by(name="admin").all():
        admin_user = User.query.get(role.user_id)
        if admin_user.active and not admin_user.deleted:
            admins.append(admin_user.email)
    send_email("An account has been locked down.", f"{user.name} ({user.email}) just locked down their account.",
               admins, "An account has been locked down.")
    flash("Your account has been secured", "success")
    return redirect(url_for("core.login"))


@core.route("/logout")
def logout():
    next_url = request.args.get("next", None)
    logout_user()
    return redirect(validate_next_url(next_url) or url_for("core.index"))


@core.route("/setup")
def setup():
    user = User.query.filter_by(username="dylanc").first()
    if not user:
        user = User(
            username="dylanc",
            email="xdylan2003x@gmail.com",
            name="Dylan Caldwell",
        )
        db.session.add(user)
        db.session.commit()
    admin_role = Role(name="admin", value=True, user_id=user.id)
    db.session.add(admin_role)

    listing_role = Role(name="doctor", value=True, user_id=user.id)
    db.session.add(listing_role)

    db.session.commit()
    return redirect(url_for("core.login"))


@core.route("/external-redirect")
def external_redirect():
    next_url = request.args.get("next", None)
    return render_template("admin/external-redirect.html", url=next_url)


# Error Handling
@core.errorhandler(404)
def not_found_error(error):
    return render_template("errors/404.html"), 404


@core.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template("errors/500.html"), 500
