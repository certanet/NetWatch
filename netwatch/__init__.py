from flask import Flask
from socket import gethostname


app = Flask(__name__)
app.config.from_object('config')
app.config['ABOUT_APP'] = gethostname()
app.config['ABOUT_VER'] = '0.4'

if 'DB_NAME' not in app.config:
    from peewee import SqliteDatabase
    app.config['ABOUT_DB'] = 'N/A (SQLITE)'
    db = SqliteDatabase('netwatch.db')
else:
    from peewee import PostgresqlDatabase
    app.config['ABOUT_DB'] = app.config['DB_NAME']
    db = PostgresqlDatabase(app.config['DB_NAME'],
                            user=app.config['DB_USER'],
                            password=app.config['DB_PASS'],
                            host=app.config['DB_HOST'],
                            port=app.config['DB_PORT'])
