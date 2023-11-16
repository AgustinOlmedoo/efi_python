FROM python:3.9-alpine

COPY . /efi_mati
WORKDIR /efi_mati

RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install Flask-Login # Agrego este comando porque si no me da error de que no encuentra el módulo.

EXPOSE 5005

ENV FLASK_APP=app/__init__.py
ENV FLASK_RUN_HOST=0.0.0.0

CMD ["sh", "run.sh"]
