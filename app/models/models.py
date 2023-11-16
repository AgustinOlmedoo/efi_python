from app import db
from sqlalchemy import ForeignKey

class Usuario(db.Model):
    __tablename__ = 'usuario'
    
    idUsuario = db.Column(db.Integer, primary_key = True)
    nombreUsuario = db.Column(db.String(100), nullable = False) 
    correoElectronico = db.Column(db.String(100), unique = True, nullable = False)
    contrasenia = db.Column(db.String(200), nullable = False)
    posteosUsuario = db.relationship('Entrada', backref='author', lazy='dynamic')

    def __str__(self):
        return f"- ID usuario: {self.idUsuario}\n- Nombre usuario: {self.nombreUsuario}\n- Correo electrónico: {self.correoElectronico}\n- Contraseña: {self.contrasenia}"

class Categoria(db.Model):
    __tablename__ = 'categoria'

    idCategoria = db.Column(db.Integer, primary_key = True)
    etiquetaCategoria = db.Column(db.String(100), nullable=False)

    def __str__(self):
        return f"{self.etiquetaCategoria}"

class Entrada(db.Model):
    __tablename__ = 'entrada'
    
    idEntrada = db.Column(db.Integer, primary_key = True)
    titulo = db.Column(db.String(100), nullable = False)
    autorEntrada = db.Column(db.Integer, ForeignKey('usuario.idUsuario'), nullable = False)
    contenido = db.Column(db.String(300), nullable = False) 
    fechaEntrada = db.Column(db.Date, nullable = False)
    idCategoriaEntrada = db.Column(db.Integer, ForeignKey('categoria.idCategoria'), nullable = False) 
    comentarios = db.relationship('Comentario', backref='entrada', lazy=True, cascade='all, delete-orphan') # Lazy determina cuando se cargarán los objetos relacionados entre tablas.
    
    def _str_(self):
        return f"- ID entrada: {self.idEntrada}\n- Título: {self.titulo}\n- Autor: {self.autorEntrada}\n- Contenido: {self.contenido}\n- Fecha de creación: {self.fechaEntrada}"

class Comentario(db.Model):
    __tablename__ = 'comentario'

    idComentario = db.Column(db.Integer, primary_key = True)
    textoComentario = db.Column(db.String(100), nullable=False)
    fechaComentario = db.Column(db.Date, nullable=False)
    autorComentario = db.Column(db.Integer, ForeignKey('usuario.idUsuario'), nullable = False)
    idEntradaComentario = db.Column(db.Integer, ForeignKey('entrada.idEntrada'), nullable = False)

    def __str__(self):
        return f"ID comentario: {self.idComentario}\n- Texto: {self.textoComentario}\n- Fecha comentario: {self.fechaComentario}\n- ID autor: {self.autorComentario}"