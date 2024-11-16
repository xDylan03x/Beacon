# Created by Dylan Caldwell
# Database models for the ORM and other helper classes
from datetime import datetime, timezone
from sqlalchemy import desc
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import uuid
from app import db, login_manager, admin
from app.admin_manager import SecureAdminView

conversation_user = db.Table('conversation_user',
                             db.Column('conversation_id', db.Integer, db.ForeignKey('conversation.id')),
                             db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
                             )


class User(UserMixin, db.Model):
    id: int = db.Column(db.Integer, primary_key=True, nullable=False)
    alternate_id: str = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    account_created_timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(tz=timezone.utc)
    )
    active: bool = db.Column(db.Boolean, default=True, nullable=False)
    deleted: bool = db.Column(db.Boolean, default=False, nullable=False)

    username: str = db.Column(db.String(64), unique=True, nullable=False)
    name: str = db.Column(db.String(128), nullable=False)
    email: str = db.Column(db.String(256), unique=True, nullable=False)
    phone_number: str = db.Column(db.String(16))
    phone_number_verified: bool = db.Column(db.Boolean, default=False, nullable=False)
    phone_number_verified_timestamp: datetime = db.Column(db.DateTime)

    password_hash: str = db.Column(db.Text)
    password_reset: bool = db.Column(db.Boolean)
    password_last_changed_timestamp: datetime = db.Column(db.DateTime)
    two_factor_auth: bool = db.Column(db.Boolean, default=False, nullable=False)

    notes = db.relationship("Note", backref="user", lazy=True)
    messages = db.relationship("Message", backref="user", lazy=True)
    logins = db.relationship("Login", backref="user", lazy=True)
    settings = db.relationship("Setting", backref="user", lazy=True)
    roles = db.relationship("Role", backref="user", lazy=True)
    tokens = db.relationship("Token", backref="user", lazy=True)
    known_devices = db.relationship("Device", backref="user", lazy=True)
    events = db.relationship("Event", backref="user", lazy=True)

    @property
    def last_login(self):
        return Login.query.filter_by(user_id=self.id).order_by(desc(Login.timestamp)).first()

    def __repr__(self) -> str:
        return f"<User - {self.username}>"

    def __eq__(self, other) -> bool:
        return self.alternate_id == other.alternate_id

    def get_id(self) -> str:
        return self.alternate_id

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def refresh_alt_id(self) -> None:
        self.alternate_id = str(uuid.uuid4())

    def get_role(self, name: str):
        role_record = Role.query.filter_by(name=name, user_id=self.id).first()
        if role_record is None:
            return False
        else:
            return role_record.value

    def set_role(self, name: str, value: bool) -> None:
        role_record = Role.query.filter_by(name=name, user_id=self.id).first()
        if role_record is None:
            role_record = Role(name=name, value=value, user_id=self.id)
            db.session.add(role_record)
        else:
            role_record.value = value


class Login(db.Model):
    id: int = db.Column(db.Integer, primary_key=True, nullable=False)
    alternate_id: str = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(tz=timezone.utc)
    )

    user_id: int = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    device_id: int = db.Column(db.Integer, db.ForeignKey("device.id"))

    def __repr__(self) -> str:
        return f"<Login - {self.id}>"

    def __eq__(self, other) -> bool:
        return self.alternate_id == other.alternate_id


class Setting(db.Model):
    id: int = db.Column(db.Integer, primary_key=True, nullable=False)
    alternate_id: str = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    name: str = db.Column(db.String(128), nullable=False)
    value: str = db.Column(db.String(128), nullable=False)
    last_updated_timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(tz=timezone.utc)
    )

    user_id: int = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def __repr__(self) -> str:
        return f"<Setting - {self.id}>"

    def __eq__(self, other) -> bool:
        return self.alternate_id == other.alternate_id


class SystemSetting(db.Model):
    id: int = db.Column(db.Integer, primary_key=True, nullable=False)
    alternate_id: str = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    name: str = db.Column(db.String(128), nullable=False)
    value: str = db.Column(db.String(256), nullable=False)
    last_updated_timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(tz=timezone.utc)
    )

    def __repr__(self) -> str:
        return f"<SystemSetting - {self.id}>"

    def __eq__(self, other) -> bool:
        return self.alternate_id == other.alternate_id


class Role(db.Model):
    id: int = db.Column(db.Integer, primary_key=True, nullable=False)
    alternate_id: str = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    name: str = db.Column(db.String(128), nullable=False)
    value: bool = db.Column(db.Boolean, nullable=False)
    last_updated_timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(tz=timezone.utc)
    )

    user_id: int = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    @property
    def formatted_name(self):
        return ' '.join(word.capitalize() for word in self.name.split('_'))

    def __repr__(self) -> str:
        return f"<Role - {self.id}>"

    def __eq__(self, other) -> bool:
        return self.alternate_id == other.alternate_id


class Token(db.Model):
    id: int = db.Column(db.Integer, primary_key=True, nullable=False)
    alternate_id: str = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    value: str = db.Column(db.String(32), nullable=False)
    used: bool = db.Column(db.Boolean, default=False)
    timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(tz=timezone.utc)
    )

    user_id: int = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __repr__(self) -> str:
        return f"<Token - {self.id}>"

    def __eq__(self, other) -> bool:
        return self.alternate_id == other.alternate_id


class Event(db.Model):
    id: int = db.Column(db.Integer, primary_key=True, nullable=False)
    alternate_id: str = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    event_type: str = db.Column(db.String(128), nullable=False)
    description: str = db.Column(db.String(256), nullable=False)
    timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(tz=timezone.utc)
    )

    user_id: int = db.Column(db.Integer, db.ForeignKey("user.id"))
    device_id: int = db.Column(db.Integer, db.ForeignKey("device.id"))

    def __repr__(self) -> str:
        return f"<Event - {self.id}>"

    def __eq__(self, other) -> bool:
        return self.alternate_id == other.alternate_id


class Device(db.Model):
    id: int = db.Column(db.Integer, primary_key=True, nullable=False)
    alternate_id: str = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    identifier: str = db.Column(db.String(256))

    events = db.relationship("Event", backref="device", lazy=True)
    user_id: int = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __repr__(self) -> str:
        return f"<Device - {self.id}>"

    def __eq__(self, other) -> bool:
        return self.alternate_id == other.alternate_id


class Conversation(db.Model):
    id: int = db.Column(db.Integer, primary_key=True, nullable=False)
    alternate_id: str = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    deleted: bool = db.Column(db.Boolean, default=False, nullable=False)
    conversation_created_timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(tz=timezone.utc)
    )
    conversation_last_updated_timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(tz=timezone.utc)
    )
    summary: str = db.Column(db.Text)

    users = db.relationship("User", secondary=conversation_user, backref="conversations")
    messages = db.relationship("Message", backref="conversation", lazy=True)
    phone_call_id: int = db.Column(db.Integer, db.ForeignKey("phone_call.id"))

    @property
    def formatted_users(self):
        return ', '.join(user.name for user in self.users)

    def __repr__(self) -> str:
        return f"<Conversation - {self.id}>"

    def __eq__(self, other) -> bool:
        return self.alternate_id == other.alternate_id


class Note(db.Model):
    id: int = db.Column(db.Integer, primary_key=True, nullable=False)
    alternate_id: str = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    deleted: bool = db.Column(db.Boolean, default=False, nullable=False)
    conversation_created_timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(tz=timezone.utc)
    )
    content = db.Column(db.Text, default="")

    user_id: int = db.Column(db.Integer, db.ForeignKey("user.id"))
    conversation_id: int = db.Column(db.Integer, db.ForeignKey("conversation.id"))

    def __repr__(self) -> str:
        return f"<Note - {self.id}>"

    def __eq__(self, other) -> bool:
        return self.alternate_id == other.alternate_id


class Message(db.Model):
    id: int = db.Column(db.Integer, primary_key=True, nullable=False)
    alternate_id: str = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    deleted: bool = db.Column(db.Boolean, default=False, nullable=False)
    content = db.Column(db.Text)

    user_id: int = db.Column(db.Integer, db.ForeignKey("user.id"))
    conversation_id: int = db.Column(db.Integer, db.ForeignKey("conversation.id"))

    def __repr__(self) -> str:
        return f"<Message - {self.id}>"

    def __eq__(self, other) -> bool:
        return self.alternate_id == other.alternate_id


class PhoneCall(db.Model):
    id: int = db.Column(db.Integer, primary_key=True, nullable=False)
    alternate_id: str = db.Column(
        db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    call_sid: str = db.Column(db.String(34), nullable=False)
    final_call_sid: str = db.Column(db.String(34))
    call_status: str = db.Column(db.String(16))
    recording_sid: str = db.Column(db.String(34))
    recording_url: str = db.Column(db.String(2048))
    recording_status: str = db.Column(db.String(16))
    recording_duration: int = db.Column(db.Integer)
    transcription: str = db.Column(db.Text)
    summary: str = db.Column(db.Text)
    timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(tz=timezone.utc)
    )

    from_number: str = db.Column(db.String(15))
    from_city: str = db.Column(db.String(32))
    from_state: str = db.Column(db.String(32))
    from_zip: str = db.Column(db.String(32))
    from_country: str = db.Column(db.String(32))

    to_number: str = db.Column(db.String(15))
    final_to_number: str = db.Column(db.String(15))

    conversation = db.relationship("Conversation", backref="phone_call", uselist=False, lazy=True)

    def __repr__(self) -> str:
        return f"<PhoneCall - {self.id}>"

    def __eq__(self, other) -> bool:
        return self.alternate_id == other.alternate_id

    def populate_from_request(self, form):
        self.call_sid = form.get("CallSid", None)
        self.call_status = form.get("CallStatus", None)
        self.recording_sid = form.get("", None)
        self.recording_url = form.get("", None)
        self.recording_status = form.get("", None)
        self.recording_duration = form.get("", None)
        self.from_number = form.get("From", None)
        self.from_city = form.get("FromCity", None)
        self.from_state = form.get("FromState", None)
        self.from_zip = form.get("FromZip", None)
        self.from_country = form.get("FromCountry", None)
        self.to_number = form.get("To", None)


admin.add_view(SecureAdminView(User, db.session, category="Users"))
admin.add_view(SecureAdminView(Login, db.session, category="Users"))
admin.add_view(SecureAdminView(Setting, db.session, category="Users"))
admin.add_view(SecureAdminView(Role, db.session, category="Users"))
admin.add_view(SecureAdminView(Token, db.session, category="Users"))
admin.add_view(SecureAdminView(Event, db.session, category="Users"))
admin.add_view(SecureAdminView(Conversation, db.session, category="Conversations"))
admin.add_view(SecureAdminView(Message, db.session, category="Conversations"))
admin.add_view(SecureAdminView(Note, db.session, category="Conversations"))
admin.add_view(SecureAdminView(PhoneCall, db.session, category="Conversations"))

# User loader for flask_login
@login_manager.user_loader
def load_user(id):
    return User.query.filter_by(alternate_id=id).first()
