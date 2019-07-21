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
    Returns the fields names for the Model e.g. id, name, ip_addess
    """
    return eval(model)._meta.sorted_field_names


"""

~~~END OF MODELS-TOP~~~


~~~START OF CONNECTIONPROFILE~~~

"""


class ConnectionProfile(DBModel):
    # Credentials attached to a Node, used to connect to devices via Netmiko...

    name = CharField(unique=True, max_length=50)
    # Used to set the Netmiko device type:
    device_os = CharField(max_length=50)
    ssh_username = CharField(max_length=50)
    ssh_password = CharField(max_length=200)
    ssh_enable = CharField(max_length=50)
    config_command = CharField(max_length=60)
    # save_config_cmd = CharField(max_length=60)
    port_num = IntegerField(default=22)

    def __repr__(self):
        return self.name

    def delete_self(self):
        try:
            self.delete_instance()
            result = ["Connection Profile \"{0.name}\" Deleted!".format(self),
                      'success']
        except:
            result = ["Delete Failed!", 'danger']
        return result

    def edit(self):
        data_dict = dict(name=self.name,
                         device_os=self.device_os,
                         ssh_username=self.ssh_username,
                         ssh_password=self.ssh_password,
                         ssh_enable=self.ssh_enable,
                         config_command=self.config_command)
        try:
            query = ConnectionProfile.update(**data_dict).where(ConnectionProfile.id == self.id)
            query.execute()
            result = ["Connection Profile \"{0.name}\" Updated!".format(self), 'success']
        except:
            result = ["Update Failed!", 'danger']
        return result


def list_all_connectionprofiles():
    all_profiles = ConnectionProfile.select().order_by(ConnectionProfile.name)
    return all_profiles


def get_connectionprofile(profile_id):
    prof_obj = ConnectionProfile.get(ConnectionProfile.id == profile_id)
    return prof_obj


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
    name = CharField(unique=True, max_length=30)
    rule_desc = CharField(null=True)
    config = TextField()
    regex = BooleanField(default=False)
    # If True a rule config match = NOT compliant,
    # If False a config match = compliant:
    found_in_config = BooleanField(default=False)
    remediation_config = TextField()
    # These should both be normalised (re escaped)
    # so Netmiko can parse them in poller.py

    def delete_self(self):
        try:
            self.delete_instance()
            result = ["Rule \"{0.name}\" Deleted!".format(self),
                      'success']
        except:
            result = ["Delete Failed!", 'danger']
        return result

    def edit(self):
        data_dict = dict(name=self.name,
                         rule_desc=self.rule_desc,
                         config=self.config,
                         regex=self.regex,
                         found_in_config=self.found_in_config,
                         remediation_config=self.remediation_config)
        try:
            query = Rule.update(**data_dict).where(Rule.id == self.id)
            query.execute()
            result = ["Rule \"{0.name}\" Updated!".format(self), 'success']
        except:
            result = ["Update Failed!", 'danger']
        return result

    def new(self):
        try:
            self.save()
            result = ["Rule \"{0.name}\" Created!".format(self), 'success']
        except:
            result = ["Create Failed!", 'danger']
        return result


def list_all_rules():
    record_set = Rule.select()
    all_rules = []

    for record in record_set:
        all_rules.append(record)

    return all_rules


def get_rule(rule_id):
    rule_obj = Rule.get(Rule.id == rule_id)
    return rule_obj


"""

~~~END OF RULES~~~


~~~START OF NODES~~~

"""


class Node(DBModel):
    name = CharField(max_length=10, unique=True)
    ip_address = CharField(max_length=15, unique=True)
    node_status = BooleanField(default=False)
    last_seen = DateTimeField(null=True)
    next_poll = DateTimeField(default=datetime.datetime.strftime(datetime.datetime.now(),
                                                                 '%Y-%m-%d %H:%M:%S'))
    connection_profile = ForeignKeyField(ConnectionProfile, default=1)

    def create_config(self, config, config_name=None):
        if config_name is None:
            config_name = self.name +\
                "-" +\
                datetime.datetime.strftime(
                    datetime.datetime.now(), '%Y%m%d-%H%M%S') +\
                ".cfg"

        now = datetime.datetime.strftime(datetime.datetime.now(),
                                         '%Y-%m-%d %H:%M:%S')
        Config.create(node=self,
                      config=config,
                      config_name=config_name,
                      saved_time=now)
        return

    def get_latest_config(self):
        # Get configs for node and order from newest to oldest, return newest:
        list_configs = Config.select().join(Node).where(Node.id == self.id).order_by(Config.saved_time.desc())
        return list_configs[0]

    def is_next_poll_now(self):
        now = datetime.datetime.now()
        if self.next_poll < now:
            poll_now = True
        else:
            poll_now = False
        return poll_now

    def set_node_status(self, status_bool):
        status = 'OFFLINE'
        log_level = 'ERR'
        if status_bool:
            q = Node.update(last_seen=datetime.datetime.strftime(datetime.datetime.now(),'%Y-%m-%d %H:%M:%S')).where(Node.id == self.id)
            status = 'ONLINE'
            log_level = 'INFO'

        if self.node_status != status_bool:
            q = Node.update(node_status=status_bool).where(Node.id == self.id)
            self.create_log('Node status changed to {}'.format(status), log_level)

        try:
            q.execute()
        except UnboundLocalError:
            pass
        return

    def set_next_poll_relative(self, relative_time_in_mins):
        now = datetime.datetime.now()
        new_poll_time = now + datetime.timedelta(minutes=relative_time_in_mins)

        q = Node.update(next_poll=new_poll_time).where(Node.id == self.id)
        q.execute()
        return

    def list_rules_for_node(self):
        rules = []

        record_set = (NodeRule
                      .select(NodeRule, Rule)
                      .join(Node)
                      .switch(NodeRule)
                      .join(Rule)
                      .where(Node.id == self.id))

        for record in record_set:
            rules.append(record.rule)

        return rules

    def list_node_rules_for_node(self):
        node_rules = []

        record_set = (NodeRule
                      .select(NodeRule, Rule)
                      .join(Node)
                      .switch(NodeRule)
                      .join(Rule)
                      .where(Node.id == self.id))

        for record in record_set:
            node_rules.append(record)

        return node_rules

    def list_configs_for_node(self):
        node_configs = Config.select().where(Config.node == self.id)\
            .order_by(Config.saved_time.desc())
        return node_configs

    def create_log(self, message, level='INFO'):
        log = Log.create(node=self,
                         date_time=datetime.datetime.strftime(datetime.datetime.now(),'%Y-%m-%d %H:%M:%S'),
                         message=message,
                         level=level)
        return log

    def delete_self(self):
        try:
            self.delete_instance()
            result = ["Node \"{0.name}\" Deleted!".format(self),
                      'success']
        except:
            result = ["Delete Failed!", 'danger']
        return result

    def edit(self):
        data_dict = dict(name=self.name,
                         ip_address=self.ip_address,
                         connection_profile=self.connection_profile)

        try:
            query = Node.update(**data_dict).where(Node.id == self.id)
            query.execute()
            result = ["Node \"{0.name}\" Updated!".format(self), 'success']
            self.create_log("Node edited!")
        except:
            result = ["Update Failed!", 'danger']
        return result


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
        nodes.append(record.node.name)

    return nodes


def list_noncompliant_noderules():
    nodes = []

    record_set = (NodeRule
                  .select(NodeRule)
                  .join(Node)
                  .where(NodeRule.nr_status == False,
                         Node.node_status == False))

    for record in record_set:
        nodes.append(record.node.name)

    return nodes


def list_pending_noderules():
    nodes = []

    record_set = (NodeRule
                  .select(NodeRule)
                  .join(Node)
                  .where(NodeRule.nr_status == False,
                         Node.node_status == True))

    for record in record_set:
        nodes.append(record.node.name)

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
                # print('Node: {0.name} is totally compliant. Matching rules are:'.format(node))
                # print([record.rule.id for record in query])
                compliant_nodes.append(record.rule.id for record in query)

    return compliant_nodes


def get_node(node_id):
    # node_obj = get_object_or_404(Node, Node.id == node_id)
    node_obj = Node.get(Node.id == node_id)
    return node_obj


"""

~~~END OF NODES~~~


~~~START OF NODERULES~~~

"""


class NodeRule(DBModel):
    node = ForeignKeyField(Node, backref='rules')
    rule = ForeignKeyField(Rule, backref='nodes')
    nr_status = BooleanField(default=False)
    auto_remediate = BooleanField(default=False)

    class Meta:
        indexes = (
            (('node', 'rule'), True),)

    def set_noderule_status(self, nr_status):
        query = NodeRule.update(nr_status=nr_status)\
            .where(NodeRule.id == self.id)
        query.execute()
        return

    def set_noderule_auto(self, auto_status):
        query = NodeRule.update(auto_remediate=auto_status)\
            .where(NodeRule.id == self.id)
        query.execute()
        return


def create_node_rule(node_obj, rule_obj):
    # Takes a Node and a Rule and creates a
    # NodeRule (attaches Rule to the Node)

    nr_status = False
    created = NodeRule.get_or_create(node=node_obj,
                                     rule=rule_obj)
    if created[1] == False:
        query = created[0].update(nr_status=nr_status).where(NodeRule.id == created[0].id)
        query.execute()



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
        node_name_dict = node.name

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


def get_noderule(node, rule):
    try:
        node_rule = NodeRule.get(NodeRule.node == node,
                                 NodeRule.rule == rule)
    except:
        print("Object doesn't exist")
        node_rule = None
    return node_rule


"""

~~~END OF NODERULES~~~


~~~START OF SETTINGS~~~

"""


class Settings(DBModel):
    # Contains the required settings for customising the app

    setting_name = CharField(unique=True, max_length=50)
    setting_value = CharField(max_length=100)


def add_settings(dummy):
    try:
        get_settings("secret_salt")
        print("Loaded existing settings!")
    except DoesNotExist:
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
             'setting_value': 60
             },
            # This is for ICMP only as SSH poll is set auto via node.next_poll:
            {'setting_name': 'poll_interval_mins',
             'setting_value': 60
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
             },
            # Used to pause the poller thread:
            {'setting_name': 'pause_poller',
             'setting_value': True
             },
            # Used to pause the poller thread:
            {'setting_name': 'poller_status',
             'setting_value': 'NOT STARTED'
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


def set_setting(setting_name, setting_value):
    query = Settings.update(setting_value=setting_value).where(Settings.setting_name == setting_name)
    query.execute()
    return


def list_dash_settings():
    record_set = Settings.select()
    settings = []
    excluded_settings = ['last_poll', 'secret_salt', 'poller_status']

    for record in record_set:
        if record.setting_name not in excluded_settings:
            settings.append(record)

    return settings


"""

~~~END OF SETTINGS~~~


~~~START OF CONFIG~~~

"""


class Config(DBModel):
    # Number of configs need to be limited to 10 per node and then rotated
    node = ForeignKeyField(Node, backref='configs')
    config_name = CharField(max_length=500,
                            unique=True,
                            default=node.name +
                            "-" +
                            datetime.datetime.strftime(datetime.datetime.now(), '%Y%m%d-%H%M%S') +
                            ".cfg")
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


def list_all_configs():
    record_set = Config.select()
    configs = []

    for record in record_set:
        configs.append(record)

    return configs


class Log(DBModel):
    node = ForeignKeyField(Node, backref='logs')
    date_time = CharField(max_length=50)
    level = CharField(max_length=10)
    message = TextField()


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
