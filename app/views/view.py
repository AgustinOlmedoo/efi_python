from datetime import datetime, timedelta

from flask import (
    jsonify,
    render_template,
    request,
    redirect,
    url_for,
    session,
)

from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity, get_jwt

from sqlalchemy import or_

from werkzeug.security import generate_password_hash, check_password_hash

from app import app, db, jwt


from app.models.models import Usuario, Categoria, Comentario, Entrada

from app.schemas.schema import CategorySchema, PostSchema, CommentSchema, UserSchema


from flask.views import MethodView


def allData():
    data = {
        "posts": Entrada.query.all(),
        "users": Usuario.query.all(),
        "categories": Categoria.query.all(),
    }
    return data


@app.context_processor
def listCategories():
    categories = Categoria.query.all()
    return dict(categories=categories)


@app.route("/")
def secIndex():
    return render_template(
        "index.html",
    )


@app.route("/inicio") 
def secInicio():  
    return render_template(
        "index.html",
    )


@app.route("/signUp")
def secRegister():
    return render_template(
        "signUp.html",
    )


@app.route("/logIn")
def secLogIn():
    return render_template(
        "logIn.html",
    )


@app.route("/btn_register")
def btnRegister():
    return render_template("signUp.html")


@app.route("/logoPostLogIn")
def clickOnLogo():
    data = allData()
    return render_template("inicio.html", data=data)


@app.route("/register_user", methods=["POST"])
def registerUserOnDb():
    usuarioForm = request.form["nameUser"]
    passwordForm = request.form["passwordUser"]
    correoElectronicoForm = request.form["emailUser"]

    passwordHash = generate_password_hash(passwordForm, method="pbkdf2", salt_length=16)

    newUser = Usuario(
        nombreUsuario=usuarioForm, contrasenia=passwordHash, correoElectronico=correoElectronicoForm
    )

    db.session.add(newUser)
    db.session.commit()

    return render_template(
        "index.html",
    )


@app.route("/userLogIn", methods=["POST"])
def logUser():
    usernameLogIn = request.form["nameUserLogin"]
    passwordLogIn = request.form["passwordUserLogin"]

    user = Usuario.query.filter_by(
        nombreUsuario=usernameLogIn
    ).first()  # La función .first() obtiene el primer resultado que cumpla con los criterios especificados.
    # Retorna una lista si encuentra el usuario filtrado por nombre de usuario. En caso de no encontrarlo, devuelve "None".

    if user and check_password_hash(user.contrasenia, passwordLogIn):
        access_token = create_access_token(
            identity=user.nombreUsuario,
            expires_delta=timedelta(seconds=30),
            additional_claims={"userID": user.idUsuario},
        )

        session["userID"] = user.idUsuario

        print(access_token)
        return redirect(url_for("secInicioPostLogin"))

    return render_template("logIn.html")  # render_template recibe archivos HTML como parámetros.

from flask import redirect, url_for, session

@app.route("/logout")
def logout():
    return redirect(url_for('secIndex'))


@app.route("/inicioPostLogin")
def secInicioPostLogin():
    data = allData()
    if "userID" in session:
        return render_template("inicio.html", data=data)

    else:
        return redirect(url_for("secLogIn"))


@app.route("/secCreatePost")
def secCreatePost():
    return render_template("createPost.html")


@app.route("/createPost", methods=["POST"])
def createPostOnDb():
    data = allData()
    titlePost = request.form["titlePost"]
    idAuthorPost = session["userID"]
    datePost = datetime.now()
    categoryPost = request.form["categorySelector"]

    newPost = Entrada(
        titulo=titlePost,
        autorEntrada=idAuthorPost,
        fechaEntrada=datePost,
        idCategoriaEntrada=categoryPost,
    )

    db.session.add(newPost)
    db.session.commit()

    return render_template(
        "createPost.html",
    )


@app.route("/del_post/<int:postId>", methods=["POST"])
def deletePost(postId):
    post = Entrada.query.get(postId)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for("secInicioPostLogin"))


#Schemas#


class LoginApi(MethodView):
    def post(self):
        dataLogin = request.get_json()
        usernameJson = dataLogin.get("username")
        passwordJson = dataLogin.get("password")

        user = Usuario.query.filter_by(nombreUsuario=usernameJson).first()

        if user and check_password_hash(user.contrasenia, passwordJson):
            accessToken = create_access_token(
                identity=user.idUsuario,
                expires_delta=timedelta(seconds=120),
                additional_claims={"userID": user.idUsuario},
            )

            session["userID"] = user.idUsuario

            return {"Datos correctos": "Usuario logeado", "Token de acceso": accessToken}, 202

        else:
            return jsonify(Mensaje=f"Datos de logeo incorrectos. Intente otra vez."), 400


app.add_url_rule("/loginApi", view_func=LoginApi.as_view("login"))

#Usuarios#


class UserApi(MethodView):
    def get(self, userId=None):
        if userId is None:
            users = Usuario.query.all()

            if len(users) == 0:
                return jsonify(Mensaje=f"La lista de usuarios está vacía."), 404

            schemaUsers = UserSchema().dump(users, many=True)

            if len(users) > 0:
                newSchemaUsers = []
                for user in schemaUsers:
                    newSchemaUser = {
                        "Nombre": user["nombreUsuario"],
                        "Correo Electrónico": user["correoElectronico"],
                        "Contraseña": user["contrasenia"],
                        "Posteos": user["posteosUsuario"],
                    }

                    newSchemaUsers.append(newSchemaUser)

                return jsonify(newSchemaUsers), 200


        if userId is not None:
            user = Usuario.query.get(userId)

            if user is not None:
                schemaUser = UserSchema().dump(user)
                return jsonify(Mensaje=f"Usuario ID {userId}: {schemaUser}"), 200

            else:
                return jsonify(Mensaje=f"Usuario ID {userId} no existe."), 404

    def post(self):
        data = request.get_json()
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        dataUser = Usuario.query.filter(
            or_(Usuario.nombreUsuario == username, Usuario.correoElectronico == email)
        ).first()  

        if dataUser is None:
            passwordHash = generate_password_hash(password, method="pbkdf2", salt_length=16)

            newUser = Usuario(
                nombreUsuario=username,
                correoElectronico=email,
                contrasenia=passwordHash,
            )

            dataNewUser = {
                "Username": newUser.nombreUsuario,
                "Email": newUser.correoElectronico,
                "Password": newUser.contrasenia,
            }

            db.session.add(newUser)
            db.session.commit()

            return (
                jsonify(Mensaje=f"Se creó el usuario: {dataNewUser}"),
                201,
            )  

        return (
            jsonify(
                Mensaje=f"El usuario {username} con el correo electrónico {email} ya existe. Introduce los datos nuevamente."
            ),
            404,
        )  

    def put(self, userId=None):
        if userId is not None:
            user = Usuario.query.get(userId)

            if user is not None:
                oldData = user.nombreUsuario
                dataUser = request.get_json()  
                newData = dataUser.get("username")  

                filterDataUser = Usuario.query.filter(
                    Usuario.nombreUsuario == newData
                ).first()  

                if filterDataUser is None:
                    user.nombreUsuario = newData  
                    db.session.commit()

                    return jsonify(Mensaje=f"Dato anterior: {oldData} | Nuevo dato: {newData}"), 200

                return (
                    jsonify(
                        Mensaje=f"El usuario {newData} ya existe. Introduce un nuevo usuario."
                    ),
                    400,
                )

            if user is None:
                return jsonify(Mensaje=f"El usuario con ID {userId} no existe."), 404

        if userId is None:
            return (
                jsonify(
                    Mensaje=f"Error: El ID {userId} no es válido. Proporciona un ID para continuar."
                ),
                400,
            )

    def delete(self, userId):
        user = Usuario.query.get(userId)

        if user is not None:
            db.session.delete(user)
            db.session.commit()
            return (
                jsonify(
                    Mensaje=f"El usuario {user.nombreUsuario} con ID {userId} fue borrado."
                ),
                200,
            )  

        if user is None:
            return jsonify(Mensaje=f"El usuario con ID {userId} no se encontró."), 404



app.add_url_rule("/user", view_func=UserApi.as_view("user"))
app.add_url_rule("/user/<userId>", view_func=UserApi.as_view("userById"))

#Posteos#


class PostApi(MethodView):
    def get(self, postId=None):
        if postId is None:
            posts = Entrada.query.all()

            if len(posts) == 0:
                return jsonify(Mensaje=f"La lista de posteos está vacía."), 404

            if len(posts) > 0:
                schemaPosts = PostSchema().dump(posts, many=True)

                newSchemaPosts = []
                for post in schemaPosts:
                    newSchemaPost = {
                        "Título": post["titulo"],
                        "Autor": post["autorEntrada"],
                        "Contenido": post["contenido"],
                        "Fecha": post["fechaEntrada"],
                        "Categoría": post["idCategoriaEntrada"],
                    }

                    newSchemaPosts.append(newSchemaPost)

                return jsonify(newSchemaPosts), 200

        if postId is not None:
            post = Entrada.query.get(postId)

            if post is not None:
                schemaPost = PostSchema().dump(post)
                return jsonify(schemaPost), 200


            else:
                return jsonify(Mensaje=f"El posteo con ID {postId} no existe."), 404


    def post(self):
        dataPost = request.get_json()
        title = dataPost.get("title")
        idAuthor = session["userID"]
        datePost = datetime.now()
        content = dataPost.get("content")
        idCategory = dataPost.get("idCategoria")

        newPost = Entrada(
            titulo=title,
            autorEntrada=idAuthor,
            fechaEntrada=datePost,
            idCategoriaEntrada=idCategory,
            contenido=content,
        )

        dataNewPost = {
            "Título del posteo": newPost.titulo,
            "Autor": newPost.autorEntrada,
            "Fecha de publicación": newPost.fechaEntrada,
            "Contenido": newPost.contenido,
            "Categoría": newPost.idCategoriaEntrada,
        }

        db.session.add(newPost)
        db.session.commit()

        return (
            jsonify(Mensaje=f"Se creó con éxito la publicación: {dataNewPost}"),
            201,
        )  

    def put(self, postId=None):
        if postId is not None:
            post = Entrada.query.get(postId)

            if post is not None:
                oldData = (
                    post.contenido
                )  
                dataPost = request.get_json()  
                newContent = dataPost.get("content")  

                post.contenido = newContent  
                db.session.commit()

                newDataPost = (
                    post.contenido
                )  

                return (
                    jsonify(
                        Mensaje=f"Anterior contenido: {oldData} | Nuevo contenido: {newDataPost}"
                    ),
                    200,
                )

            if post is None:
                return jsonify(Mensaje=f"El posteo con ID {postId} no existe."), 404

        if postId is None:
            return (
                jsonify(Mensaje=f"¡Tenés que especificar el ID del posteo que querés modificar!"),
                400,
            )

    
    def delete(self, postId):
        post = Entrada.query.get(postId)

        if post is not None:
            db.session.delete(post)
            db.session.commit()
            return (
                jsonify(
                    Mensaje=f"El posteo que se titula '{post.titulo}' con ID {post.idEntrada} fue borrado con éxito."
                ),
                200,
            )

        if post is None:
            return jsonify(Mensaje=f"El posteo que intentabas borrar no existe."), 404


app.add_url_rule("/post", view_func=PostApi.as_view("post"))
app.add_url_rule("/post/<postId>", view_func=PostApi.as_view("postById"))



#Categorías#


class CategoryApi(MethodView):
    def get(self, categoryId=None):
        if categoryId is None:
            categories = Categoria.query.all()

            if len(categories) == 0:
                return jsonify(Mensaje=f"¡Listado de categorías vacío!"), 404

            if len(categories) > 0:
                schemaCategories = CategorySchema().dump(categories, many=True)

                newSchemaCategories = []
                for category in schemaCategories:
                    newSchemaCategory = {
                        "ID de la categoría": category["idCategoria"],
                        "Nombre de la categoría": category["etiquetaCategoria"],
                    }

                    newSchemaCategories.append(newSchemaCategory)

                return jsonify(newSchemaCategories), 200

        if categoryId is not None:
            category = Categoria.query.get(categoryId)

            if category is not None:
                schemaCategory = CategorySchema().dump(category)
                return jsonify(schemaCategory), 200

            if category is None:
                return jsonify(Mensaje=f"La categoría con ID {categoryId} no existe."), 404

    def post(self):
        dataNewCategory = request.get_json()
        nameCategory = dataNewCategory.get("name")

        filterDataCategory = Categoria.query.filter(
            Categoria.etiquetaCategoria == nameCategory
        ).first()

        if filterDataCategory is None:
            newCategory = Categoria(etiquetaCategoria=nameCategory)

            db.session.add(newCategory)
            db.session.commit()

            return (
                jsonify(Mensaje=f"Se creó con éxito la categoría: {nameCategory}"),
                201,
            )  

        return jsonify(Mensaje=f"La categoría '{nameCategory}' ya existe."), 400

    def put(self, categoryId=None):
        if categoryId is not None:
            category = Categoria.query.get(categoryId)

            if category is not None:
                oldData = (
                    category.etiquetaCategoria
                )  
                dataNewCategory = request.get_json()  
                newName = dataNewCategory.get("name") 

                filterDataCategory = Categoria.query.filter(
                    Categoria.etiquetaCategoria == newName
                ).first()  

                if filterDataCategory is None:
                    category.etiquetaCategoria = newName
                    db.session.commit()

                    return jsonify(Mensaje=f"Dato anterior: {oldData} | Nuevo dato: {newName}"), 200

                
                return (
                    jsonify(
                        Mensaje=f"La categoría '{newName}' ya existe. Introduce una categoría distinta."
                    ),
                    400,
                )

            if category is None:
                return jsonify(Mensaje=f"La categoría con ID {categoryId} no existe."), 404

        if categoryId is None:
            return jsonify(Mensaje=f"¡Debés especificar la categoría que querés modificar!"), 400

    def delete(self, categoryId=None):
        if categoryId is not None:
            category = Categoria.query.get(categoryId)

            if category is not None:
                db.session.delete(category)
                db.session.commit()
                return (
                    jsonify(
                        Mensaje=f"La categoría que se titula '{category.etiquetaCategoria}' con ID {category.idCategoria} fue borrada con éxito."
                    ),
                    200,
                )

            if category is None:
                return jsonify(Mensaje=f"La categoría que intentabas borrar no existe"), 404

        if categoryId is None:
            return (
                jsonify(
                    Mensaje=f"ID de categoría no válido. Debes especificarlo para poder borrar la categoría deseada."
                ),
                400,
            )

app.add_url_rule("/category", view_func=CategoryApi.as_view("category"))
app.add_url_rule("/category/<categoryId>", view_func=CategoryApi.as_view("categoryById"))