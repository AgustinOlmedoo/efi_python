from app import ma
from marshmallow import fields

class CategorySchema(ma.Schema):
    idCategoria = fields.Integer(dump_only = True)
    etiquetaCategoria = fields.String()

class CommentSchema(ma.Schema):
    idComentario = fields.Integer(dump_only = True)
    textoComentario = fields.String()
    fechaComentario = fields.Date()
    autorComentario = fields.String()
    idEntradaComentario = fields.Integer()
    
class PostSchema(ma.Schema):
    idEntrada = fields.Integer(dump_only = True)
    titulo = fields.String()
    autorEntrada = fields.String()
    contenido = fields.String()
    fechaEntrada = fields.Date()
    idCategoriaEntrada = fields.Integer()
    comentarios = fields.Nested(CommentSchema, many = True)

class UserSchema(ma.Schema):
    idUsuario = fields.Integer(dump_only = True)
    nombreUsuario = fields.String()
    correoElectronico = fields.String()
    contrasenia = fields.String()
    posteosUsuario = fields.Nested(PostSchema, many = True)