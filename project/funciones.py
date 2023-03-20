from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_security import login_required
from flask_security.utils import login_user, logout_user, hash_password, encrypt_password
from .models import User
from . import db, userDataStore

formu = Blueprint("formu",__name__ , url_prefix='/productos')

@formu.route("/formulario",methods=["POST"])
def formulario():
    return render_template("formulario.html")
