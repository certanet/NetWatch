from flask import Flask
from socket import gethostname
import os
import sys


app = Flask(__name__)


def get_env_var_set_config(setting):
    env_var = os.environ.get('NETWATCH_' + setting)
    if env_var is not None:
        app.config[setting] = env_var


# Env vars take priority over config file, so try setting first:
get_env_var_set_config('SECRET_KEY')

# If a secret key env var is set, then try to load remaining settings:
if app.config['SECRET_KEY'] is not None:
    settings = ['DUMMY_DATA', 'DB_NAME', 'DB_USER',
                'DB_PASS', 'DB_HOST', 'DB_PORT']
    for setting in settings:
        get_env_var_set_config(setting)
else:
    # If a secret key env var is not set, then try a config file:
    try:
        app.config.from_object('data.config')
        if app.config['SECRET_KEY'] is None:
            raise ImportError
    except ImportError:
        # If config file doesn't exist or the SECRET_KEY is not set, exit
        sys.exit('No config file found or secret set!')

# Check whether to load in dummy data or not
if 'DUMMY_DATA' not in app.config:
    app.config['DUMMY_DATA'] = False

# Set app about info
app.config['ABOUT_APP'] = gethostname()
app.config['ABOUT_VER'] = '0.4'

# Check if external psql db should be used, if not use SQLite
if 'DB_NAME' not in app.config:
    from peewee import SqliteDatabase
    app.config['ABOUT_DB'] = 'N/A (SQLITE)'
    db = SqliteDatabase('data/netwatch.db')
else:
    from peewee import PostgresqlDatabase
    app.config['ABOUT_DB'] = app.config['DB_NAME']
    db = PostgresqlDatabase(app.config['DB_NAME'],
                            user=app.config['DB_USER'],
                            password=app.config['DB_PASS'],
                            host=app.config['DB_HOST'],
                            port=app.config['DB_PORT'])
