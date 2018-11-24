from peewee import *
import datetime
import json
from netwatch import db
from netwatch import secrets


class DBModel(Model):

    class Meta:
        database = db


def percent_calc(totalX, totalY):
    """
    Takes 2 integers, uses totalX to get 1% and totalY to get final percentage
    Returns the final percentage as an int or 0 if not divisible e.g. if X is 0
    """
    try:
        percent = int((100 / totalX) * totalY)
    except ZeroDivisionError:
        percent = 0
    return percent


def number_files_in_dir(path, extension):
    """
    Takes a directory path (relative to run.py) and a file extension.
    e.g. for logs use './logs/', '.log' and for all files, use extension ''
    Returns the number of files in that directory
    """
    import os
    import os.path
    try:
        number_files = len([name for name in os.listdir(path)
                            if os.path.isfile(os.path.join(path, name)) &
                            os.path.join(path, name).endswith(extension)])
    except:
        number_files = 0
    return number_files


def list_columns_for(model):
    """
    Takes a string, which should be the name of a Model e.g. Node
    Returns the fields names for the Model e.g. id, node_name, ip_addess
    """
    return eval(model)._meta.sorted_field_names


"""

~~~END OF MODELS-TOP~~~


~~~START OF CONNECTIONPROFILE~~~

"""


class ConnectionProfile(DBModel):
    # Credentials attached to a Node, used to connect to devices via Netmiko...

    profile_name = CharField(unique=True, max_length=50)
    # Used to set the Netmiko device type:
    device_os = CharField(max_length=50)
    ssh_username = CharField(max_length=50)
    ssh_password = CharField(max_length=200)
    ssh_enable = CharField(max_length=50)
    config_command = CharField(max_length=60)
    # save_config_cmd = CharField(max_length=60)
    port_num = IntegerField(default=22)

    def __repr__(self):
        return self.profile_name


def list_all_connectionprofiles():
    all_profiles = ConnectionProfile.select().order_by(ConnectionProfile.profile_name)
    """
    record_set = ConnectionProfile.select()
    all_profiles = []

    for record in record_set:
        all_profiles.append(record)
    """
    return all_profiles


def get_connectionprofile(profile_id):
    prof_obj = ConnectionProfile.get(ConnectionProfile.id == profile_id)
    return prof_obj


def update_connectionprofile(profile):
    data_dict = dict(profile_name=profile.profile_name,
                     device_os=profile.device_os,
                     ssh_username=profile.ssh_username,
                     ssh_password=profile.ssh_password,
                     ssh_enable=profile.ssh_enable,
                     config_command=profile.config_command)

    try:
        query = ConnectionProfile.update(**data_dict).where(ConnectionProfile.id == profile.id)
        query.execute()
        result = ["Connection Profile \"{0.profile_name}\" Updated!".format(profile), 'success']
    except:
        result = ["Update Failed!", 'danger']
    return result


def delete_connectionprofile(profile_id):
    try:
        prof_obj = ConnectionProfile.get(ConnectionProfile.id == profile_id)
        prof_obj.delete_instance()
        result = ["Connection Profile \"{0.profile_name}\" Deleted!".format(prof_obj), 'success']
    except:
        result = ["Delete Failed!", 'danger']
    return result


def create_connectionprofile(profile_dict):

    try:
        profile_dict['ssh_password'] =\
            str(encrypt_creds(profile_dict['ssh_password']))
        profile_dict['ssh_enable'] =\
            str(encrypt_creds(profile_dict['ssh_enable']))

        profile = ConnectionProfile.create(**profile_dict)
        profile.save()
        result = ["Connection Profile \"{0.profile_name}\" Created!"
                  .format(profile), 'success']
    except:
        result = ["Create Failed!", 'danger']
    return result


def encrypt_creds(pt):
    # FOR TESTING:
    # pt = get_connectionprofile(connectionprofile_id).ssh_password
    salt = eval(get_settings("secret_salt"))

    ct = secrets.encrypt(pt, salt)

    return ct


def decrypt_creds(ct):
    # FOR TESTING:
    # ct = eval(get_connectionprofile(connectionprofile_id).ssh_password)
    ct = eval(ct)
    salt = eval(get_settings("secret_salt"))

    pt = str(secrets.decrypt(ct, salt))

    return pt


"""

~~~END OF CONNECTIONPROFILE~~~


~~~START OF RULES~~~

"""


class Rule(DBModel):
    rule_name = CharField(unique=True, max_length=30)
    rule_desc = CharField(null=True)
    config = TextField()
    regex = BooleanField(default=False)
    # If True a rule config match = NOT compliant,
    # If False a config match = compliant:
    found_in_config = BooleanField(default=False)
    remediation_config = TextField()
    # These should both be normalised (re escaped)
    # so Netmiko can parse them in poller.py


def list_all_rules():
    record_set = Rule.select()
    all_rules = []

    for record in record_set:
        all_rules.append(record)

    return all_rules


def get_rule(rule_id):
    rule_obj = Rule.get(Rule.id == rule_id)
    return rule_obj


def set_rule_config(rule_id, config):
    q = Rule.update(config=config).where(Rule.id == rule_id)
    q.execute()
    return


def set_rule_remediationconfig(rule_id, config):
    q = Rule.update(remediation_config=config).where(Rule.id == rule_id)
    q.execute()
    return


def update_rule(rule):
    data_dict = dict(rule_name=rule.rule_name,
                     rule_desc=rule.rule_desc,
                     config=rule.config,
                     regex=rule.regex,
                     found_in_config=rule.found_in_config,
                     remediation_config=rule.remediation_config)

    try:
        query = Rule.update(**data_dict).where(Rule.id == rule.id)
        query.execute()
        result = ["Rule \"{0.rule_name}\" Updated!".format(rule), 'success']
    except:
        result = ["Update Failed!", 'danger']
    return result


def create_rule(rule_dict):

    try:
        rule = Rule.create(**rule_dict)
        rule.save()
        result = ["Rule \"{0.rule_name}\" Created!"
                  .format(rule), 'success']
    except:
        result = ["Create Failed!", 'danger']
    return result


"""

~~~END OF RULES~~~


~~~START OF NODES~~~

"""


class Node(DBModel):
    node_name = CharField(max_length=10, unique=True)
    ip_address = CharField(max_length=15, unique=True)
    node_status = BooleanField(default=False)
    last_seen = DateTimeField(null=True)
    next_poll = DateTimeField(default=datetime.datetime.strftime(datetime.datetime.now(),
                                                                 '%Y-%m-%d %H:%M:%S'))
    connection_profile = ForeignKeyField(ConnectionProfile, default=1)

    def create_config(self, config):
        Config.create(node=self, config=config)
        return

    def get_latest_config(self):
        # Get configs for node and order from newest to oldest, return newest:
        list_configs = Config.select().join(Node).where(Node.id == self.id).order_by(Config.saved_time.desc())
        return list_configs[0]


def list_rules_for_node(called_node_id):
    called_node_rules = []

    record_set = (NodeRule
                  .select(NodeRule, Rule)
                  .join(Node)
                  .switch(NodeRule)
                  .join(Rule)
                  .where(Node.id == called_node_id))

    for record in record_set:
        called_node_rules.append(record.rule)

    return called_node_rules


def list_online_nodes():
    record_set = Node.select().where(Node.node_status == True)
    nodes = []

    for record in record_set:
        nodes.append(record)

    return nodes


def list_all_nodes():
    record_set = Node.select()
    nodes = []

    for record in record_set:
        nodes.append(record)

    return nodes


def list_compliant_noderules():
    nodes = []

    record_set = (NodeRule
                  .select(NodeRule)
                  .join(Node)
                  .where(NodeRule.nr_status == True))

    for record in record_set:
        nodes.append(record.node.node_name)

    return nodes


def list_noncompliant_noderules():
    nodes = []

    record_set = (NodeRule
                  .select(NodeRule)
                  .join(Node)
                  .where(NodeRule.nr_status == False,
                         Node.node_status == False))

    for record in record_set:
        nodes.append(record.node.node_name)

    return nodes


def list_pending_noderules():
    nodes = []

    record_set = (NodeRule
                  .select(NodeRule)
                  .join(Node)
                  .where(NodeRule.nr_status == False,
                         Node.node_status == True))

    for record in record_set:
        nodes.append(record.node.node_name)

    return nodes


def list_compliant_nodes():
    """
    Returns a list of generator objects for nodes that have all NodeRules with True nr_status
    The generator object can be expanded as a list, to show the rule numbers that are True
    for each given totally compliant node
    """
    compliant_nodes = []

    query = (NodeRule
             .select(NodeRule, Node, Rule)
             .join(Rule)
             .switch(NodeRule)
             .join(Node))

    last = None
    for node_rule in query:
        node = node_rule.node
        if node != last:
            last = node

            query = (NodeRule
                     .select(NodeRule, Node, Rule)
                     .join(Rule)
                     .switch(NodeRule)
                     .join(Node)
                     .where(Node.id == node.id))

            if all(node_rule.nr_status for node_rule in query):
                # print('Node: {0.node_name} is totally compliant. Matching rules are:'.format(node))
                # print([record.rule.id for record in query])
                compliant_nodes.append(record.rule.id for record in query)

    return compliant_nodes


def set_node_status(node_obj, status_bool):
    if status_bool:
        q = Node.update(last_seen=datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')).where(Node.id == node_obj.id)
        q.execute()
    q = Node.update(node_status=status_bool).where(Node.id == node_obj.id)
    q.execute()
    return


def set_node_next_poll_relative(node, relative_time_in_mins):
    now = datetime.datetime.now()
    new_poll_time = now + datetime.timedelta(minutes=relative_time_in_mins)

    q = Node.update(next_poll=new_poll_time).where(Node.id == node.id)
    q.execute()
    return


def is_next_poll_now(node):
    now = datetime.datetime.now()
    if node.next_poll < now:
        poll_now = True
    else:
        poll_now = False
    return poll_now


def create_node(node_name, ip_address):
    data_dict = dict(node_name=node_name,
                     ip_address=ip_address)

    try:
        created = Node.get_or_create(**data_dict)
        if created[1] is True:
            result = ["Node \"{0}\" Created!".format(node_name), 'success']
        else:
            result = ["Node already exists!", 'danger']
    except:
        result = ["ERROR!", 'danger']
    return result


def get_node(node_id):
    # node_obj = get_object_or_404(Node, Node.id == node_id)
    node_obj = Node.get(Node.id == node_id)
    return node_obj


def update_node(node):
    data_dict = dict(node_name=node.node_name,
                     ip_address=node.ip_address)

    try:
        query = Node.update(**data_dict).where(Node.id == node.id)
        query.execute()
        result = ["Node \"{0.node_name}\" Updated!".format(node), 'success']
    except:
        result = ["Update Failed!", 'danger']
    return result


def delete_node(id):
    try:
        obj = Node.get(Node.id == id)
        obj.delete_instance()
        result = ["Node \"{0.node_name}\" Deleted!".format(obj), 'success']
    except:
        result = ["Delete Failed!", 'danger']
    return result


"""

~~~END OF NODES~~~


~~~START OF NODERULES~~~

"""


class NodeRule(DBModel):
    node = ForeignKeyField(Node)
    rule = ForeignKeyField(Rule)
    nr_status = BooleanField(default=False)
    auto_remediate = BooleanField(default=False)

    class Meta:
        indexes = (
            (('node', 'rule'), True),)


def add_node_rules(node_id, rule_ids):
    """
    Takes a Node.id and a list of rule nums
    Creates a NodeRule for each in the list (attaches each Rule to the Node)
    """

    node_obj = Node.get(Node.id == node_id)

    for rule_id in rule_ids:
        rule_obj = Rule.get(Rule.id == rule_id)
        nr_status = False

        created = NodeRule.get_or_create(node=node_obj,
                                         rule=rule_obj,
                                         defaults={'nr_status': nr_status})
        if created[1] == False:
            query = created[0].update(nr_status=nr_status).where(NodeRule.id == created[0].id)
            query.execute()


def list_all_node_rules():
    record_set = NodeRule.select()
    node_rules = []

    for record in record_set:
        node_rules.append(record)

    return node_rules


def dict_node_table():
    from collections import defaultdict
    node_table = defaultdict(list)

    query_all_rules = Rule.select()
    query_all_nodes = Node.select()

    for node in query_all_nodes:
        node_name_dict = node.node_name

        for rule in query_all_rules:
            query = (NodeRule
                     .select(NodeRule, Node, Rule)
                     .join(Rule)
                     .switch(NodeRule)
                     .join(Node)
                     .where(Rule.id == rule.id,
                            Node.id == node.id))
            if not query:
                node_table[node_name_dict].append("-")
            for node_rule in query:
                node_table[node_name_dict].append(str(node_rule.nr_status))

    return node_table


def set_noderule_status(node, rule, nr_status):
    """
    Example of the 3 variables required:
    Object{Node3}, Object{Rule100}, True

    This would set node 3's rule 100 nr_status to True
    """
    try:
        node_rule = NodeRule.get(NodeRule.node == node,
                                 NodeRule.rule == rule)

        query = NodeRule.update(
            nr_status=nr_status).where(NodeRule.id == node_rule.id)
        query.execute()
    except:
        print("Object doesn't exist")
    return


def delete_noderule(node_id, rule_id):
    """
    Takes a Node.id and a rule num
    Removes a NodeRule from a Node
    """

    node_obj = Node.get(Node.id == node_id)
    rule_obj = Rule.get(Rule.id == rule_id)

    query = (NodeRule
             .select(NodeRule)
             .join(Rule)
             .switch(NodeRule)
             .join(Node)
             .where(Rule.id == rule_obj.id,
                    Node.id == node_obj.id))
    for nr in query:
        print(nr.nr_status)
        nr.delete_instance()
    return


def get_noderule_auto_remediate(node, rule):
    try:
        node_rule = NodeRule.get(NodeRule.node == node,
                                 NodeRule.rule == rule)
        auto = node_rule.auto_remediate
    except:
        auto = False
        print("Object doesn't exist")
    return auto


"""

~~~END OF NODERULES~~~


~~~START OF SETTINGS~~~

"""


class Settings(DBModel):
    # Contains the required settings for customising the app

    setting_name = CharField(unique=True, max_length=50)
    setting_value = CharField(max_length=100)


def add_settings(refresh, poll, dummy):
    try:
        current_salt = get_settings("secret_salt")
        print("Loaded existing settings!")
    except:
        print("No existing settings found...")
        secret_salt = secrets.generate_salt()

        """
        db_secrets = secrets.generate_secrets()

        if db_secrets['error']:
            print("ERROR: Creating secrets failed")
            return
        """

        check_running_instead_of_startup = False  # not req due to config_cmd

        settings = [
            # Used in head of index.html to set page refresh rate...
            {'setting_name': 'dash_refresh_rate_secs',
             'setting_value': int(refresh)
             },
            # This is for ICMP only as SSH poll is set auto via node.next_poll:
            {'setting_name': 'poll_interval_mins',
             'setting_value': int(poll)
             },
            # Used in poller.py to check compliance against start or
            # running config  - startup is preffered:
            {'setting_name': 'check_running_instead_of_startup',
             'setting_value': check_running_instead_of_startup
             },
            # Referenced in index.html and updated via poller.py
            {'setting_name': 'last_poll',
             'setting_value': '--:--:--'
             },
            # Used as a random string during encryption of secrets:
            {'setting_name': 'secret_salt',
             'setting_value': secret_salt
             }
        ]

        for data_dict in settings:
            created = Settings.get_or_create(**data_dict)

            if created[1] is False:
                print("ERROR: Setting already exists, need to update")

        if dummy:
            with open('dummy-data.json') as f:
                json_data = json.load(f)
            bulk_add(json_data)
            print("Loaded dummy data!")

        print("DB tables successfully populated!")
    return


def get_settings(setting_name):
    # To get a setting use get_settings(SETTING_NAME)
    # e.g. to get the ssh username, use:
    # get_settings("ssh_username")
    settings_obj = Settings.get(Settings.setting_name == setting_name)
    try:
        settings_value = getattr(settings_obj, 'setting_value')
    except:
        settings_value = "INVALID_SETTING"
    return settings_value


def set_last_poll(time):
    query = Settings.update(setting_value=time).where(Settings.setting_name == "last_poll")
    query.execute()
    return


"""

~~~END OF SETTINGS~~~


~~~START OF CONFIG~~~

"""


class Config(DBModel):
    # Number of configs need to be limited to 10 per node and then rotated
    node = ForeignKeyField(Node, backref='configs')
    config_name = CharField(max_length=500, unique=True, default=datetime.datetime.strftime(datetime.datetime.now(),
                                                                 '%Y%m%d-%H%M%S') + ".cfg")
    config = TextField()
    saved_time = DateTimeField(default=datetime.datetime.strftime(datetime.datetime.now(),
                                                                 '%Y-%m-%d %H:%M:%S'))


def create_config(config_dict):
    # config_dict example:
    # {"node": 1, "config": "hostname SWITCH01"}

    try:
        config = Config.create(**config_dict)
        config.save()
        result = ["Config \"{0.config_name}\" Created!"
                  .format(config), 'success']
    except:
        result = ["Create Failed!", 'danger']
    return result


def create_config2(node_id, config):
    Config.create(node=node_id, config=config)
    return


def list_all_configs():
    record_set = Config.select()
    configs = []

    for record in record_set:
        configs.append(record)

    return configs


"""

~~~END OF CONFIG~~~


~~~START OF BULK~~~

"""


def bulk_add(json_data):
    for data_dict in json_data["dummy-data"]["connectionprofiles"]:
        ConnectionProfile.get_or_create(**data_dict)
    print("[1/4] Added Connection Profiles")
    for data_dict in json_data["dummy-data"]["rules"]:
        Rule.get_or_create(**data_dict)
    print("[2/4] Added Rules")
    for data_dict in json_data["dummy-data"]["nodes"]:
        Node.get_or_create(**data_dict)
    print("[3/4] Added Nodes")
    for data_dict in json_data["dummy-data"]["noderules"]:
        NodeRule.get_or_create(**data_dict)
    print("[4/4] Added Node Rules")
    return


"""

~~~END OF BULK~~~


"""
