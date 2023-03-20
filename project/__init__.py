import os
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore
from flask_sqlalchemy import SQLAlchemy

# Creamos una instancia de SQLAlchemy
db = SQLAlchemy()
from .models import User, Role 
#creamos un objeto de sqlalchemyuserdatastore
userDataStore=SQLAlchemyUserDatastore(db,User,Role)

# Método inicio de la aplicación
def create_app():
    # Creamos nuestra aplicación de Flask
    app = Flask(__name__)

    #Configuraciones necesarias.
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = os.urandom(24)
    app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:1234@localhost/examen2parcial"
    app.config["SECURITY_PASSWORD_HASH"] = 'pbkdf2_sha512'
    app.config["SECURITY_PASSWORD_SALT"] = 'secretsalt'
    
    
    db.init_app(app)
    #Método para crear la BD de la primera petición
    @app.before_first_request
    def create_all():
        db.create_all()
    
    
    #conectando los modelos de flask-security usando SQLAlchemyUserDataStore
    security=Security(app,userDataStore)

    # Registramos dos blueprints
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
