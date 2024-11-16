# Created by Dylan Caldwell
# Initialization and configuration of Flask application
from flask import Flask
from flask_admin import Admin
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData
import os.path
from twilio.rest import Client
import sendgrid
import openai

# App configuration
app = Flask(__name__)

DEPLOYMENT = "DEV"
if DEPLOYMENT == "DEV":
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////Users/dylancaldwell/PycharmProjects/beacon/app/beacon.db"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = "secret"
    app.config['UPLOAD_FOLDER'] = "app/core/static/uploads/"
    app.config['BASE_URL'] = "127.0.0.1:8080"
    app._template_dir = os.path.join(os.getcwd(), "app", "core", "templates")
    app._static_folder = os.path.join(os.getcwd(), "app", "core", "static")
elif DEPLOYMENT == "PROD":
    app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://xDylan03x:<pwd>@xDylan03x.mysql.pythonanywhere-services.com/xDylan03x$Beacon"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = ""  # TODO Secure
    app.config['UPLOAD_FOLDER'] = "app/core/static/uploads/"
    app._template_dir = os.path.join(os.getcwd(), "app", "core", "templates")
    app._static_folder = os.path.join(os.getcwd(), "app", "core", "static")
    app.config['BASE_URL'] = "beacon-xdylan03x.pythonanywhere.com"
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_recycle': 280,
        'pool_pre_ping': True
    }
else:
    raise ValueError("Invalid deployment environment")


# Login manager configuration
login_manager = LoginManager(app)
login_manager.login_view = "core.login"
login_manager.login_message = "You must login to view this page."
login_manager.login_message_category = "error"
login_manager.refresh_view = "core.login"
login_manager.needs_refresh_message = (
    "For security reasons, please login again to view this page."
)
login_manager.needs_refresh_message_category = "error"

# Database configuration
metadata = MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)
db = SQLAlchemy(metadata=metadata)
migrate = Migrate(app, db)
migrate.init_app(app, db)
db.init_app(app)

# Twilio configuration
twilio_account_sid = ""  # TODO Secure
twilio_auth_token = ""  # TODO Secure
app.config["TWILIO_VERIFY_SERVICE_SID"] = ""  # TODO Add to configuration
twilio_client = Client(twilio_account_sid, twilio_auth_token)

# SendGrid configuration
sendgrid_client = sendgrid.SendGridAPIClient(api_key="")  # TODO Secure

# OpenAI configuration
openAI_client = openai.Client(api_key="")  # TODO Secure in production

# Admin configuration
app.config["FLASK_ADMIN_SWATCH"] = "default"
admin = Admin(
    app, name="Admin", template_mode="bootstrap4"
)


# Routing configuration
from .core.routes import core, not_found_error, internal_error

app.register_blueprint(core, url_prefix="/")

# Errors
app.register_error_handler(404, not_found_error)
app.register_error_handler(500, internal_error)


# Initialize database
with app.app_context():
    db.create_all()
