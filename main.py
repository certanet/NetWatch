from netwatch import app, db
from netwatch.models import *
from netwatch.routes import *
from netwatch.secrets import *
from netwatch import poller
from threading import Thread
import time


def run_poller():
    def call_poller(node):
        while True:
            print("Placeholder for poller...")
            print("{0.node_name}".format(node))
            poller.run(node)
            # Testing sleep timer:
            time.sleep(60)
            # This is the correct sleep time (mins in settings,
            # but sleep takes secs so *60).
            # Can remove the int(), as the Model now has this:
            #
            # time.sleep(int(models.get_settings('poll_interval_mins')) * 60)

    for node in models.list_all_nodes():
        thread = Thread(target=call_poller, args=(node,))
        thread.daemon = True  # This kills the thread when the main proc dies
        thread.start()
        time.sleep(30)


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
add_settings(refresh, poll, dummy)

run_poller()


if __name__ == '__main__':

    app.run(host='0.0.0.0')
