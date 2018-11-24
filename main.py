from netwatch import app, db
from netwatch.models import *
from netwatch.routes import *
from netwatch.secrets import *
from netwatch import poller


db.create_tables([Rule, Node, NodeRule, Settings, ConnectionProfile, Config],
                 safe=True)

try:
    refresh = app.config['PAGE_REFRESH_SECS']
except:
    refresh = 60
try:
    poll = app.config['POLL_INTERVAL_MINS']
except:
    poll = 60
try:
    dummy = app.config['DUMMY_DATA']
except:
    dummy = False
try:
    pause = app.config['PAUSE_POLLER']
except:
    pause = False

add_settings(refresh, poll, dummy, pause)

poller.poller_init()

if __name__ == '__main__':

    app.run(host='0.0.0.0')
