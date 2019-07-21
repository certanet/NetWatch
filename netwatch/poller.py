from datetime import datetime
import re
import time
import os
import platform
from threading import Thread, enumerate

from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, \
    NetMikoAuthenticationException

from netwatch import models
from netwatch.secrets import Secrets


class Poller:
    def __init__(self, node):
        self.node = node
        self.device_profile = self.build_device_profile()

    def run(self):
        print("Started poller for {0.name}...".format(self.node))
        models.set_last_poll(datetime.now().strftime('%H:%M:%S'))

        if self.ping():
            self.node.set_node_status(True)  # Also sets last_seen to now()

            # True if next poll is before now(), this prevents rechecking a recently checked node
            if self.node.is_next_poll_now():
                # Set next_poll to now()+15mins to allow for the rest to complete before running again
                self.node.set_next_poll_relative(15)
                self.logme("\n:::::::::::::" + self.node.ip_address + ":::::::::::::")
                backup_config = self.ssh_return_config()
                if backup_config is None:
                    # Stop current node and wait for poll setting timeout
                    # Need to set node status to ERROR here, so can display on dash
                    return
                self.node.create_config(backup_config + "\n")
                backup_again = False

                for rule in self.node.list_rules_for_node():
                    check_compliance = self.check_config_compliance(rule)
                    # Only backs up config again once, rather than after each rule is remediated:
                    if check_compliance['backup_again']:
                        backup_again = True

                if backup_again:
                    new_config = self.ssh_return_config()
                    self.node.create_config(new_config + "\n")

                # Set next_poll to now()+24hrs...
                self.node.set_next_poll_relative(1440)
                # This also sets last_seen to now()...
                self.node.set_node_status(True)

        else:
            self.node.set_node_status(False)
            # True if next poll is before now(), this prevents setting a recently checked node to a sooner poll time
            if self.node.is_next_poll_now():
                # Set next_poll to now()+0mins, will not be checked until upto 5mins anyway as the Celery task should
                # run 5mins, if set to now()+5mins the next Celery job may be before it
                self.node.set_next_poll_relative(0)

    def ping(self):
        ping_str = "-n 1" if platform.system().lower() == "windows" else "-c 1"

        # Returns True if host responds to a ping request
        # Adding  '+ " -w 1"' to the ping command changes the timeout to
        # 1 second on Windows, so improves results time, but may not be
        # cross platform:
        return os.system("ping " + ping_str + " " + self.node.ip_address + " -w 1") == 0

    def build_device_profile(self):
        device_profile = {'ip': self.node.ip_address,
                          'device_type': self.node.connection_profile.device_os,
                          'username': self.node.connection_profile.ssh_username,
                          'password': Secrets().decrypt(self.node.connection_profile.ssh_password),
                          'secret': Secrets().decrypt(self.node.connection_profile.ssh_enable),
                          'port': self.node.connection_profile.port_num}
        return device_profile

    def setup_ssh(self):
        self.logme('Connecting to device {0.name}'.format(self.node))
        try:
            net_connect = ConnectHandler(**self.device_profile)
            self.logme('Successfully connected to: "{}"!'.format(self.node.name))
            return net_connect
        except NetMikoAuthenticationException as e:
            self.logme(str(e))
            return("Authentication failed.")
        except NetMikoTimeoutException as e:
            self.logme(str(e))
            self.logme("Device is unreachable.")
            return("Device is unreachable.")
        except Exception as e:
            self.logme("\nOops! A general error occurred, here's the message:")
            self.logme(str(e))
        # If any exception has occured return None:
        return None

    def ssh_return_config(self):
        net_connect = self.setup_ssh()

        if net_connect is not None:
            net_connect.enable()
            cfg_req_output = net_connect.send_command(self.node.connection_profile.config_command)
            net_connect.disconnect()
            self.logme('Got config for node: "{}"!'.format(self.node.name))
            return cfg_req_output

    def ssh_remediate_config(self, raw_remediation_config):
        net_connect = self.setup_ssh()

        if net_connect is not None:
            net_connect.enable()
            remediation_config = raw_remediation_config.split("\n")
            self.logme(net_connect.send_config_set(remediation_config))

            net_connect.exit_config_mode()
            # self.logme(net_connect.send_command("copy run start"))
            self.logme(net_connect.send_command("\n"))
            net_connect.disconnect()

    def check_config_compliance(self, rule):
        compliant = False
        backup_again = False
        node_config = self.node.get_latest_config()
        noderule = models.get_noderule(self.node, rule)

        # NEED TO CHECK rule.regex Boolean and
        # rule.found_in_config Boolean
        # to see if it should be escaped and/or NOT found...

        # To RegEx escape Rule.config. use..
        #                  re.escape(rule.config)
        # or if not just rule.config

        if not rule.found_in_config:
            match = re.search(re.escape(rule.config),
                              node_config.config)  # Gets latest config!

            if match is None:
                self.logme("{0.name} - Not Compliant!".format(rule))
                noderule.set_noderule_status(compliant)
                # Checks if NR is enabled for auto remediate and executes:
                if noderule.auto_remediate:
                    self.ssh_remediate_config(rule.remediation_config)
                    backup_again = True
                    compliant = True
            else:
                self.logme("{0.name} - Compliant!".format(rule))
                backup_again = False
                compliant = True
        else:
            match = re.search(re.escape(rule.config),
                              node_config.config)

            if match is None:
                self.logme("{0.name} - Compliant!".format(rule))
                backup_again = False
                compliant = True
            else:
                self.logme("{0.name} - Not Compliant!".format(rule))
                noderule.set_noderule_status(compliant)
                # Checks if NR is enabled for auto remediate and executes:
                if noderule.auto_remediate:
                    self.ssh_remediate_config(rule.remediation_config)
                    backup_again = True
                    compliant = True

        noderule.set_noderule_status(compliant)

        return {"backup_again": backup_again}

    def logme(self, message):
        run_time = datetime.now().strftime('%Y%m%d-%H%M')
        log_file = './logs/POLLING-' + run_time + '.log'

        logger = open(log_file, 'a')
        logger.write(message + "\n")
        print(message)


class PollerService:
    def run(self):
        print("Initialising Poller...")
        thread = Thread(target=self.poller_service,
                        name='Poller_Service_Thread',
                        daemon=True)
        thread.start()

    def poller_service(self):
        models.set_setting("poller_status", "STARTED")
        print("Poller service started...")
        while True:
            while models.get_settings('pause_poller') == "True":
                models.set_setting("poller_status", "PAUSED")
                time.sleep(5)
            models.set_setting("poller_status", "RUNNING")
            for node in models.list_all_nodes():
                # Stop processing additional nodes if paused:
                if models.get_settings('pause_poller') == "True":
                    models.set_setting("poller_status", "PAUSING")
                    break
                print("Starting poller for {0.name}...".format(node))
                poller = Poller(node)
                thread = Thread(target=poller.run,
                                name='Poller-' + node.name)
                thread.start()
                # FOR DEBUG
                # Stops all threads running in parallel so prints can be seen:
                time.sleep(3)
            if models.get_settings('pause_poller') == "True":
                    models.set_setting("poller_status", "PAUSED")
            else:
                models.set_setting("poller_status", "STARTED")

            # Sleep the poller until number of mins in settings, checking if paused
            # every second
            poll_interval = models.get_settings('poll_interval_mins')
            for check in range(1, (int(poll_interval) * 60)):
                time.sleep(1)
                if models.get_settings('pause_poller') == "True":
                    break


def get_active_pollers():
    threads = enumerate()
    poller_threads = 0

    for thread in threads:
        if "Poller-" in thread.name:
            poller_threads += 1
    return poller_threads


if __name__ == '__main__':
    print("Poller is no longer stand-alone!")
