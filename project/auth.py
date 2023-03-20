from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_security import login_required
from flask_security.utils import login_user, logout_user, hash_password, encrypt_password
from .models import User
from .models import Productos
import base64


from . import db, userDataStore

auth = Blueprint("auth",__name__ , url_prefix='/security')

@auth.route("/login")
def login():
    return render_template("/security/login.html")

@auth.route("/login", methods=["POST"])
def login_post():
    email = request.form.get("email")
    password = request.form.get("password")
    remember = True if request.form.get("remember") else False

    # Consultemos si existe un usuario ya registrado con ese email.
    user = User.query.filter_by(email=email).first()

    #Verificamos si el usuario existe y comprobamos el password
    if not user or not check_password_hash(user.password, password):
        flash("El usuario y/o contraseña son incorrectos")
        return redirect(url_for("auth.login")) #Rebotamos a la página de login
    
    # Si llegamos aqui los datos son correctos y creamos un sesión para el usuario
    login_user(user, remember=remember)
    return redirect(url_for("main.profile"))

@auth.route("/register")
def register():
    return render_template("/security/register.html")


@auth.route("/comentarios")
def comentarios():
    return render_template("comentarios.html")


@auth.route("/register",methods=["POST"])
def register_post():
    email = request.form.get("email")
    name = request.form.get("name")
    password = request.form.get("password")

    #Consultamos si existe un usuario ya registrado con ese email
    user = User.query.filter_by(email=email).first()

    if user:
        flash("El correo electronico ya está en uso")
        return redirect(url_for("auth.register"))
    
    #Creamos un nuevo usuario y lo guardamos en la bd
    userDataStore.create_user(name=name,email=email, password=generate_password_hash(password, method='sha256'))


    db.session.commit()
    
    return redirect(url_for("auth.login"))



@auth.route("/logout")
@login_required
def logout():
    #Cerramos sesión
    logout_user()
    return redirect(url_for("main.index"))




@auth.route("/productos")
@login_required
def productos():
    return render_template("/security/formulario.html", resultado = "", id=0, nombre ="", descripcion="", img="")

@auth.route("/registrarProductos", methods=["POST"])
def registrarProductos():
    id=request.form['id']
    nombre = str(request.form['nombre'])
    descripcion = str(request.form['descripcion'])
    img = request.files['imagen'].read()
    imagen_base64 = base64.b64encode(img)

    if int(id) > 0:
        producto = Productos.query.filter_by(id=int(id)).first()
        producto.nombre = nombre
        producto.descripcion = descripcion
        producto.img = imagen_base64
        db.session.commit()
    else:
        mi_registro = Productos(nombre=nombre, descripcion=descripcion, img=imagen_base64)
        db.session.add(mi_registro)
        db.session.commit()
    

    return render_template("/security/formulario.html", resultado = "")



 
@auth.route("/modificarProducto", methods=["GET","POST"])
@login_required
def modificarProducto():
    id = request.form['id']
    nombre = request.form['nombre']
    descripcion = request.form['descripcion']
    img = request.form['img']
    
    return render_template("/security/formulario.html", resultado = "", id=id, nombre =nombre, descripcion=descripcion, img=img)   


@auth.route("/eliminarProducto", methods=["GET","POST"])
@login_required
def eliminarProducto():
    id = request.form['id']
    
    productos = Productos.query.filter_by(id=int(id)).first()
    db.session.delete(productos)
    db.session.commit()

    return render_template("/security/formulario.html", resultado = "")   

@auth.route("/obtenerProductos", methods=["POST"])
@login_required
def obtenerProductos():
    productos = Productos.query.all()
    return render_template("/security/formulario.html", resultado = productos)