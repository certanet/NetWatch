from flask import Flask


app = Flask(__name__)
app.config.from_object('config')


if 'DB_NAME' not in app.config:
    from peewee import SqliteDatabase
    db = SqliteDatabase('netwatch.db')
else:
    from peewee import PostgresqlDatabase
    db = PostgresqlDatabase(app.config['DB_NAME'],
                            user=app.config['DB_USER'],
                            password=app.config['DB_PASS'],
                            host=app.config['DB_HOST'],
                            port=app.config['DB_PORT'])
