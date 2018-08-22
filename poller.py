from netwatch import models

from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, \
    NetMikoAuthenticationException
from datetime import datetime
import re


def ping(ip_address):
    import os, platform
    ping_str = "-n 1" if platform.system().lower() == "windows" else "-c 1"

    # Returns True if host responds to a ping request
    # Adding  '+ " -w 1"' to the ping command changes the timeout to
    # 1 second on Windows, so improves results time, but may not be
    # cross platform:
    return os.system("ping " + ping_str + " " + ip_address + " -w 1") == 0


def ssh_save_return_backup_config(node, remediated=False):
    device_profile = build_device_profile(node)
    run_time = datetime.now().strftime('%Y%m%d-%H%M')

    try:
        net_connect = ConnectHandler(**device_profile)
        net_connect.enable()
        output = net_connect.send_command(node.connection_profile.config_command)
        net_connect.disconnect()
        if remediated:
            backup_file =\
                './configs/' + device_profile['ip'] + "-" + run_time + '-RMD' + '.cfg'
        else:
            backup_file =\
                './configs/' + device_profile['ip'] + "-" + run_time + '.cfg'

        logme('Saving config to "{}" ...'.format(backup_file))
        backup = open(backup_file, 'a')
        backup.write(output + "\n")
        backup.close()

        # config_backup_contents = open(backup_file, 'r')
        # contents = config_backup_contents.read()
        # config_backup_contents.close()
        # return contents
        return output

    except NetMikoAuthenticationException as e:
        z = str(e)
        logme(z)
        return("Authentication failed.")
    except NetMikoTimeoutException as e:
        z = str(e)
        logme(z)
        logme("Device is unreachable.")
        return("Device is unreachable.")
    except Exception as e:
        z = str(e)
        logme("\nOops! A general error occurred, here's the message:")
        logme(z)


def ssh_remediate_config(node, raw_remediation_config):
    device_profile = build_device_profile(node)

    try:
        net_connect = ConnectHandler(**device_profile)
        net_connect.enable()

        remediation_config = raw_remediation_config.split("\n")
        logme(net_connect.send_config_set(remediation_config))

        net_connect.exit_config_mode()
        logme(net_connect.send_command("copy run start"))
        logme(net_connect.send_command("\n"))

        net_connect.disconnect()

    except NetMikoAuthenticationException as e:
        z = str(e)
        logme(z)
    except NetMikoTimeoutException as e:
        z = str(e)
        logme(z)
        logme("Device is unreachable.")
    except Exception as e:
        z = str(e)
        logme("\nOops! A general error occurred, here's the message:")
        logme(z)


def check_config_file_compliance(node, config_file, rule):
    compliant = False
    # To RegEx escape Rule.config. use..
    #                  re.escape(rule.config)
    # or if not just rule.config
    match = re.search(re.escape(rule.config),
                      config_file)
    if match is None:
        logme("{0.rule_name} - Not Compliant!".format(rule))
        models.set_noderule_status(node, rule, False)
        ssh_remediate_config(node, rule.remediation_config)
        backup_again = True
        compliant = True
    else:
        logme("{0.rule_name} - Compliant!".format(rule))
        backup_again = False
        compliant = True

    return {"backup_again": backup_again, "compliant": compliant}


def logme(output):
    logger = open(log_file, 'a')
    logger.write(output + "\n")
    print(output)


def build_device_profile(node):
    device_profile = {'ip': node.ip_address,
                      'device_type': node.connection_profile.device_os,
                      'username': node.connection_profile.ssh_username,
                      'password': models.decrypt_creds(node.connection_profile.ssh_password),
                      'secret': models.decrypt_creds(node.connection_profile.ssh_enable)
                      }
    return device_profile


if __name__ == '__main__':
    run_time = datetime.now().strftime('%Y%m%d-%H%M')
    log_file = './logs/POLLING-' + run_time + '.log'
    models.set_last_poll(datetime.now().strftime('%H:%M:%S'))

    for node in models.list_all_nodes():
        if ping(node.ip_address):
            models.set_node_status(node, True)  # Also sets last_seen to now()

            if models.is_next_poll_now(node):  # True if next poll is before now(), this prevents rechecking a recently checked node
                models.set_node_next_poll_relative(node, 15)  # Set next_poll to now()+15mins to allow for the rest tom complete before running again
                logme("\n:::::::::::::" + node.ip_address + ":::::::::::::")
                backup_config = ssh_save_return_backup_config(node)
                if (backup_config == "Device is unreachable.") or\
                        (backup_config == "Authentication failed."):
                    # Stop current node and continue to next...
                    continue
                backup_again = False

                for rule in models.list_rules_for_node(node.id):
                    check_compliance = check_config_file_compliance(
                        node,
                        backup_config,
                        rule)
                    if check_compliance['backup_again']:
                        backup_again = True
                    if check_compliance['compliant']:
                        models.set_noderule_status(node, rule, True)

                if backup_again:
                    ssh_save_return_backup_config(node, remediated=True)

                # Set next_poll to now()+24hrs...
                models.set_node_next_poll_relative(node, 1440)
                # This also sets last_seen to now()...
                models.set_node_status(node, True)

        else:
            models.set_node_status(node, False)
            if models.is_next_poll_now(node): #True if next poll is before now(), this prevents setting a recently checked node to a sooner poll time
                models.set_node_next_poll_relative(node, 0) #Set next_poll to now()+0mins, will not be checked until upto 5mins anyway as the Celery task should run 5mins, if set to now()+5mins the next Celery job may be before it
