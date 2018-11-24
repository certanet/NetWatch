from netwatch import app, db
from netwatch.models import *
from netwatch.routes import *
from netwatch.secrets import *
from netwatch import poller
from threading import Thread
import time


def run_poller():
    def call_poller(node):
        print("Started poller for {0.node_name}...".format(node))
        poller.run(node)

    def init_poller():
        while True:
            print("Initialising Poller...")
            while models.get_settings('pause_poller') == "True":
                print("Poller paused!")
                time.sleep(60)
                print("Checking Poller status...")
            for node in models.list_all_nodes():
                print("Starting poller for {0.node_name}...".format(node))
                thread = Thread(target=call_poller, args=(node,), name='Poller-' + node.node_name)
                # IS THIS NEEDED NOW THE TASK ENDS?? IF SO, USE daemon=None:
                thread.daemon = True  # This kills the thread when the main proc dies
                thread.start()
                time.sleep(10)

            # Testing sleep timer:
            time.sleep(60)
            # This is the correct sleep time (mins in settings,
            # but sleep takes secs so *60).
            # Can remove the int(), as the Model now has this:
            #
            # time.sleep(int(models.get_settings('poll_interval_mins')) * 60)

    thread = Thread(target=init_poller, name='Poller_Init')
    thread.daemon = True
    thread.start()


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

run_poller()


if __name__ == '__main__':

    app.run(host='0.0.0.0')
