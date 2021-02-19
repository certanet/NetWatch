![NetWatch](/netwatch/static/img/logo-blk.png?raw=true "NetWatch Logo")

NetWatch is a cross-platform tool for viewing and automatically remediating network device configuration compliance.

# Screenshots
![Screenshot](/screenshot.png?raw=true)


# Getting Started
### Windows
1. Create a virtual env to separate NetWatch dependencies from system packages:
`python -m venv venv`
2. Enter the virtual env:
`venv\Scripts\activate.bat`
3. Install the packages required to run NetWatch:
`pip install -r requirements.txt`
4. Create a secret key (see Configuration below)

### Ubuntu


# Installation
Ansible: TBC
Docker: TBC
Vagrant: TBC



# Configuration
There's two methods that allow you to set the required configuration to get you up and running with NetWatch; environment variables and the config file. Currently the only setting that's required is a SECRET_KEY.

SECRET_KEY plays an important role in regards to security. It is used by the underlying web framework for NetWatch (Flask) and also to encrypt various secrets within the app (such as passwords for your nodes). Therefore you should pick a very secure secret and NOT share it anywhere (except maybe your password manager!). If you backup/restore NetWatch to another server, ensure you use the same secret so you can decrypt your credentials.

**Note**: environment variables take precedence over a config file if both are created.
### Environment Variables
When setting env vars all should be prepended with NETWATCH_.
So instead of SECRET_KEY you must set NETWATCH_SECRET_KEY

To set the SECRET_KEY on Windows use:
`set NETWATCH_SECRET_KEY=your-very-secure-secret`  
To set the SECRET_KEY on Ubuntu use:
`export NETWATCH_SECRET_KEY=your-very-secure-secret`

### Config File
config.py is a settings file that lets NetWatch load your configuration, think of it as a .ini file. The file should be created in the data directory.  
**Note**: all settings keys in the config file should be entered in UPPERCASE


# Database
NetWatch uses a database to store ongoing activities. By default this is SQLite, but can be changed to a local or remote PostgreSQL instance.

### PostgreSQL
To start using a psql database enter the following configuration settings:
- DB_NAME
- DB_USER
- DB_PASS
- DB_HOST
- DB_PORT 



# Application Stack

NetWatch has been tested on Windows 10 and Ubuntu 16.04 with Python 3.5, but should work on newer versions.
The recommended/tested technology stack for NetWatch is...

| Service        | Technology        |
|----------------|-------------------|
| HTTP Server    | Nginx             |
| WSGI Interface | Gunicorn          |
| Application    | Python/Flask      |
| Database       | SQLite/PostgreSQL |
| Device Access  | Netmiko           |