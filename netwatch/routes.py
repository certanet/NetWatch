from flask import render_template, redirect, url_for, flash, request, make_response, Markup
from netwatch import app, models, forms, poller
from netwatch.secrets import Secrets
import datetime
import psutil


def getting_started(profile, node):
    if not profile:
        new_link = url_for('new_model', slug='connectionprofiles')
        message = Markup("Looks like you haven't created a Connection Profile! Click <a href=\"{}\">here</a> to get started...".format(new_link))
    elif not node:
        new_link = url_for('new_model', slug='nodes')
        message = Markup("Nearly there, but you haven't created any Nodes! Click <a href=\"{}\">here</a> to get started...".format(new_link))
    result = [message, 'warning']
    flash(*result)


@app.route('/')
def home():

    node_list = models.list_all_nodes()
    rule_list = models.list_all_rules()
    profile_list = models.list_all_connectionprofiles()
    node_table = models.dict_node_table()

    if not profile_list or not node_list:
        getting_started(profile_list, node_list)

    number_node_online = len(models.list_online_nodes())

    number_total_nodes = len(node_list)
    number_total_rules = len(rule_list)
    number_total_node_rules = len(models.list_all_node_rules())

    number_comp_rules = len(models.list_compliant_noderules())
    number_pend_rules = len(models.list_pending_noderules())
    number_fail_rules = len(models.list_noncompliant_noderules())

    number_totally_comp_nodes = len(models.list_compliant_nodes())

    percent_comp_rules = models.percent_calc(number_total_node_rules, number_comp_rules)
    percent_fail_rules = models.percent_calc(number_total_node_rules, number_fail_rules)

    percent_totally_comp_nodes = models.percent_calc(number_total_nodes, number_totally_comp_nodes)
    percent_pend_nodes = 0  # Not yet in use on Compliance by kit pie chart...
    percent_not_totally_comp_nodes = int(100 - percent_totally_comp_nodes)

    percent_online_nodes = models.percent_calc(number_total_nodes, number_node_online)
    percent_offline_nodes = int(100 - percent_online_nodes)

    number_config_backups = models.number_files_in_dir('./configs/', '.cfg')
    number_logs = models.number_files_in_dir('./logs/', '.log')

    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.datetime.now() - boot_time
    pretty_uptime = "{}d {}h {}m {}s".format(uptime.days,
                                                    uptime.seconds // 3600,
                                                    (uptime.seconds // 60) % 60,
                                                    uptime.seconds % 60)

    num_total_configs = len(models.list_all_configs())

    return render_template('index.html',
                           title='Dashboard',
                           node_table=node_table,
                           node_list=node_list,
                           rule_list=rule_list,
                           number_total_nodes=number_total_nodes,
                           number_node_online=number_node_online,
                           number_comp_rules=number_comp_rules,
                           number_pend_rules=number_pend_rules,
                           number_fail_rules=number_fail_rules,
                           percent_comp_rules=percent_comp_rules,
                           percent_fail_rules=percent_fail_rules,
                           percent_totally_comp_nodes=percent_totally_comp_nodes,
                           percent_pend_nodes=percent_pend_nodes,
                           percent_not_totally_comp_nodes=percent_not_totally_comp_nodes,
                           percent_online_nodes=percent_online_nodes,
                           percent_offline_nodes=percent_offline_nodes,
                           refresh_rate=models.get_settings("dash_refresh_rate_secs"),
                           last_poll=models.get_settings("last_poll"),
                           number_config_backups=number_config_backups,
                           number_logs=number_logs,
                           uptime=pretty_uptime,
                           no_active_pollers=poller.get_active_pollers(),
                           poller_status=models.get_settings("poller_status"),
                           num_total_configs=num_total_configs
                           )


@app.route('/poller_status')
def poller_status():
    status = models.get_settings('poller_status')
    return status


@app.route('/poller', methods=['GET', 'POST'])
def pollpage():
    if request.method == 'POST':
        if request.form.get('poller-button') == 'Pause':
            models.set_setting('pause_poller', True)
            # Set status manually, as it wan't refreshing on dashboard quickly:
            models.set_setting('poller_status', "PAUSING")
            result = ["Pausing Poller...", 'danger']
        elif request.form.get('poller-button') == 'Resume':
            models.set_setting('pause_poller', False)
            models.set_setting('poller_status', "RUNNING")
            result = ["Resuming Poller...", 'success']
        flash(*result)
        return redirect(url_for('home'))

    return render_template('poller.html',
                           title='Poller Control',
                           poller_status=models.get_settings("poller_status"))


@app.route('/rules/', defaults={'model': 'rules'})
@app.route('/nodes/', defaults={'model': 'nodes'})
@app.route('/connectionprofiles/', defaults={'model': 'connectionprofiles'})
@app.route('/configs/', defaults={'model': 'configs'})
@app.route('/noderules/', defaults={'model': 'noderules'})
@app.route('/settings/', defaults={'model': 'settings'})
def modeltable(model):
    if model == "nodes":
        title = 'Nodes'
        columns = models.list_columns_for("Node")
        rows = models.list_all_nodes()
    elif model == "rules":
        title = 'Rules'
        columns = models.list_columns_for("Rule")
        rows = models.list_all_rules()
    elif model == "connectionprofiles":
        title = 'Connection Profiles'
        columns = models.list_columns_for("ConnectionProfile")
        rows = models.list_all_connectionprofiles()
    elif model == "configs":
        title = 'Configs'
        columns = models.list_columns_for("Config")
        rows = models.list_all_configs()
    elif model == "noderules":
        title = 'Node Rules'
        columns = models.list_columns_for("NodeRule")
        rows = models.list_all_node_rules()
    elif model == "settings":
        title = 'Settings'
        columns = models.list_columns_for("Settings")
        rows = models.list_dash_settings()

    return render_template('modeltable.html',
                           columns=columns,
                           rows=rows,
                           slug=model,
                           title=title
                           )


@app.route("/<slug>/new/", methods=('GET', 'POST'))
def new_model(slug):
    '''
    Create new Node/ConnectionProfile/Rule
    '''
    if slug == "nodes":
        title = "Node"
        form = forms.NodeForm()
        new_obj = models.Node()

        # Choices are populated on the fly to ensure new additions are listed
        profile_choices = []
        for profile in models.list_all_connectionprofiles():
            profile_choices.append((profile.id, profile.name))

        form.connection_profile.choices = profile_choices

    elif slug == "connectionprofiles":
        title = "Connection Profile"
        form = forms.ConnectionProfileForm()
        new_obj = models.ConnectionProfile()

    elif slug == "rules":
        title = "Rule"
        form = forms.RuleForm()
        new_obj = models.Rule()

    if form.validate_on_submit():
        # Populate the new object with the form data and try to save to DB:
        try:
            if slug == "connectionprofiles":
                form.ssh_password.data = str(Secrets().encrypt(form.ssh_password.data))
                form.ssh_enable.data = str(Secrets().encrypt(form.ssh_enable.data))

            form.populate_obj(new_obj)
            new_obj.save()
            result = ["{0} \"{1.name}\" Created!".format(title, new_obj), 'success']
        except:
            result = ["Create Failed!", 'danger']

        flash(*result)
        return redirect(url_for('modeltable', model=slug))

    return render_template('new_model.html',
                           title='New ' + title,
                           slug=slug,
                           form=form)


@app.route("/<slug>/edit/<id>", methods=('GET', 'POST'))
def edit_model(slug, id):
    if slug == "rules":
        my_model = models.get_rule(id)
        form = forms.RuleForm(obj=my_model)
    elif slug == "connectionprofiles":
        my_model = models.get_connectionprofile(id)
        form = forms.ConnectionProfileForm(obj=my_model)

    if form.validate_on_submit():
        form.populate_obj(my_model)
        try:
            result = my_model.edit()
            flash(*result)
            return redirect(url_for('modeltable', model=slug))
        except:
            pass

    return render_template('edit_model.html',
                           title='Edit: ' + my_model.name,
                           form=form,
                           my_model=my_model)


@app.route("/configs/view/<id>", methods=('GET', 'POST'))
def view_config(id):
    config_obj = models.Config.get(models.Config.id == id)
    form = forms.ConfigForm(obj=config_obj)
    config_length = len(config_obj.config.split('\n'))

    form.populate_obj(config_obj)

    if request.method == 'POST':
        if request.form['download'] == "Download":
            file_download = make_response(config_obj.config)
            file_download.headers["Content-Disposition"] =\
                "attachment; filename={}".format(config_obj.config_name)
            return file_download

    return render_template('config_detail.html',
                           title='Config Detail ',
                           form=form,
                           obj=config_obj,
                           config_length=config_length)


@app.route("/nodes/view/<id>")
def view_node(id):
    node_obj = models.Node.get(models.Node.id == id)
    configs = node_obj.list_configs_for_node()
    node_rule_list = node_obj.list_node_rules_for_node()

    num_comp_rules = 0
    num_pend_rules = 0
    num_fail_rules = 0

    for nrule in node_rule_list:
        if nrule.nr_status:
            num_comp_rules += 1
        elif not nrule.nr_status and node_obj.node_status:
            num_pend_rules += 1
        else:
            num_fail_rules += 1

    return render_template('node_detail.html',
                           title='Node Detail',
                           node=node_obj,
                           configs=configs,
                           rule_list=node_rule_list,
                           num_comp_rules=num_comp_rules,
                           num_pend_rules=num_pend_rules,
                           num_fail_rules=num_fail_rules)


@app.route("/<slug>/delete", methods=('POST',))
def delete_model(slug):
    if slug == "nodes":
        node_obj = models.get_node(request.form['id'])
        result = node_obj.delete_self()
        flash(*result)
        return redirect(url_for('modeltable', model='nodes'))
    if slug == "connectionprofiles":
        prof_obj = models.get_connectionprofile(request.form['id'])
        result = prof_obj.delete_self()
        flash(*result)
        return redirect(url_for('modeltable', model='connectionprofiles'))
    if slug == "rules":
        rule_obj = models.get_rule(request.form['id'])
        result = rule_obj.delete_self()
        flash(*result)
        return redirect(url_for('modeltable', model='rules'))


@app.route("/nodes/edit/<id>", methods=('GET', 'POST'))
def node_edit(id):
    node_obj = models.get_node(id)
    form = forms.NodeForm(obj=node_obj)

    # Choices are populated on the fly to ensure new additions are listed
    profile_choices = []
    for profile in models.list_all_connectionprofiles():
        profile_choices.append((profile.id, profile.name))

    form.connection_profile.choices = profile_choices

    rules = models.list_all_rules()
    noderule_list = node_obj.list_node_rules_for_node()
    noderule_list_rules = []
    noderule_dict_auto = {}

    for nr in noderule_list:
        noderule_list_rules.append(nr.rule)

    for nr in noderule_list:
        noderule_dict_auto[nr.rule] = nr.auto_remediate

    if form.validate_on_submit():
        form.populate_obj(node_obj)
        result = node_obj.edit()
        flash(*result)

        for rule_obj in rules:
            if request.form.get(str(rule_obj.id)):
                if rule_obj not in noderule_list_rules:
                    models.create_node_rule(node_obj, rule_obj)
            else:
                if rule_obj in noderule_list_rules:
                    models.delete_noderule(node_obj.id, rule_obj.id)

        for rule_obj in noderule_list_rules:
            nr = models.get_noderule(node_obj, rule_obj)
            if nr is not None:
                if request.form.get('auto{}'.format(rule_obj.id)):
                    nr.set_noderule_auto(True)
                else:
                    nr.set_noderule_auto(False)

        return redirect(url_for('node_edit', id=id))

    return render_template('node_edit.html',
                           title='Edit',
                           form=form,
                           node=node_obj,
                           rules=rules,
                           noderule_list_rules=noderule_list_rules,
                           noderule_dict_auto=noderule_dict_auto)


# Error page routes
@app.errorhandler(404)  # page not found (incorrect URL)
@app.errorhandler(405)  # method not allowed (no PUT etc.)
@app.errorhandler(500)  # internal server error (code/server error)
def http_error(e):
    return render_template('error.html',
                           title=e,
                           err_message=e), e.code
