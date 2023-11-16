echo 'sleep 10 secs'
sleep 10

echo 'run migrations db'

echo 'run flask db init'
flask db init

echo 'run flask db migrate'
flask db migrate -m "initial migration"

echo 'run flask db upgrade'
flask db upgrade

echo 'start gunicorn server'
gunicorn app:app --bind 0.0.0.0:5005
