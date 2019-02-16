from netwatch import app, db
from netwatch.models import *
from netwatch.routes import *
from netwatch.secrets import *
from netwatch import poller


db.create_tables([Rule, Node, NodeRule, Settings, ConnectionProfile, Config, Log],
                 safe=True)

try:
    refresh = app.config['PAGE_REFRESH_SECS']
except KeyError:
    refresh = 60
try:
    poll = app.config['POLL_INTERVAL_MINS']
except KeyError:
    poll = 60
try:
    dummy = app.config['DUMMY_DATA']
except KeyError:
    dummy = False

add_settings(refresh, poll, dummy)

poller.poller_init()

if __name__ == '__main__':
    app.run(host='0.0.0.0')
