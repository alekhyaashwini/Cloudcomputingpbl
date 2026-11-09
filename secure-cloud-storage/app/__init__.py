import os
from flask import Flask, render_template
from config import Config
from app.models.models import Database
from app.services.key_management import KeyManagementService
from app.services.storage import get_storage_adapter

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize components
    app.db = Database(app.config['DATABASE_PATH'])
    app.key_service = KeyManagementService(app.config['MASTER_ENCRYPTION_KEY'])
    app.storage_adapter = get_storage_adapter(app.config)

    # Register blueprints
    from app.auth.routes import auth_bp
    from app.files.routes import files_bp
    from app.security.routes import security_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(security_bp)

    @app.route('/')
    def index():
        from flask import session
        is_authenticated = 'user_id' in session
        return render_template('index.html', is_authenticated=is_authenticated)

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('base.html', content="<div class='alert alert-warning'>404: Page or resource not found.</div>"), 404

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return render_template('base.html', content="<div class='alert alert-danger'>Upload failed: File exceeds the maximum allowed size limit.</div>"), 413

    return app
