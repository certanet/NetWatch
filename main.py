from netwatch import app, db
from netwatch.models import *
from netwatch.routes import *
from netwatch.secrets import *
from threading import Thread
import time


def run_poller():
    def call_poller():
        while True:
            print("Placeholder for poller...")
            time.sleep(10)

    thread = Thread(target=call_poller)
    thread.daemon = True  # This kills the thread when the main proc dies
    thread.start()


db.create_tables([Rule, Node, NodeRule, Settings, ConnectionProfile],
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
add_settings(refresh, poll, dummy)

run_poller()


if __name__ == '__main__':

    app.run(host='0.0.0.0')
