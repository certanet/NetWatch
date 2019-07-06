from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SelectField, RadioField, TextAreaField
from wtforms.validators import DataRequired, Length, IPAddress


class NodeForm(FlaskForm):
    node_name = StringField('Node Name',
                            validators=[DataRequired(),
                                        Length(min=-1,
                                               max=20,
                                               message='You cannot have more than 20 characters')])
    ip_address = StringField('IP Address',
                             validators=[DataRequired(),
                                         IPAddress(message='Must be a valid IPv4 address')])
    # node_status = BooleanField('Status')
    # CANNOT GET THIS TO SHOW THE NODE'S CURRENT VALUE!!!!...
    connection_profile = SelectField('Connection Profile', coerce=int)


class RuleForm(FlaskForm):
    name = StringField('Rule Name',
                       validators=[DataRequired(),
                                   Length(min=-1,
                                          max=20,
                                          message='You cannot have more than 20 characters')])
    rule_desc = StringField('Rule Description',
                            validators=[DataRequired(),
                                        Length(min=-1,
                                               max=80,
                                               message='You cannot have more than 80 characters')])
    config = TextAreaField('Config',
                           validators=[DataRequired(),
                                       Length(min=-1,
                                              max=200,
                                              message='You cannot have more than 200 characters')])
    regex = BooleanField('Regex')
    # The coerce int allows the values to be set to True/False:
    found_in_config = RadioField('Match Type',
                                 coerce=bool,
                                 choices=[(1, 'Voilate if found'),
                                          (0, 'Voilate if NOT found')],
                                 default=0)
    remediation_config = TextAreaField('Remediation Config',
                                       validators=[DataRequired(),
                                                   Length(min=-1,
                                                          max=200,
                                                          message='You cannot have more than 200 characters')])


class ConnectionProfileForm(FlaskForm):
    name = StringField('Profile Name',
                       validators=[DataRequired(),
                                   Length(min=-1,
                                          max=40,
                                          message='You cannot have more than 40 characters')])
    device_os = SelectField('Device OS',
                            choices=[('cisco_ios', 'Cisco IOS'),
                                     ('juniper_junos', 'JUNOS'),
                                     ('arista_eos', 'Arista EOS')])
    ssh_username = StringField('SSH Username',
                               validators=[DataRequired(),
                                           Length(min=-1,
                                                  max=200,
                                                  message='You cannot have more than 200 characters')])
    ssh_password = StringField('SSH Password',
                               validators=[DataRequired(),
                                           Length(min=-1,
                                                  max=200,
                                                  message='You cannot have more than 200 characters')])
    ssh_enable = StringField('SSH Enable',
                             validators=[DataRequired(),
                                         Length(min=-1,
                                                max=200,
                                                message='You cannot have more than 200 characters')])
    config_command = StringField('Config Command',
                                 validators=[DataRequired(),
                                             Length(min=-1,
                                                    max=60,
                                                    message='You cannot have more than 60 characters')])


class ConfigForm(FlaskForm):
    # node = StringField('Node')
    # config_name = StringField('Config Name')
    config = TextAreaField('Config')
