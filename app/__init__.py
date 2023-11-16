import os

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user
from dotenv import load_dotenv

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI') # Conecto con la base de datos local (db_practicoSemestre)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
ma = Marshmallow(app)

load_dotenv() # Trae las variables del archivo .env

from app.views import view


