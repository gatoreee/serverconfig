# serverconfig
Project: Server Configuration - [Enrique B]
================================

Required Libraries and Dependencies
-----------------------------------
The project presents an online guitar catalog. It uses SQLite, Python and Bootstap and allows users to log-in with their fb or google+ accounts. It is hosted using Amazon Lightsail and can be found at: http://http://52.55.87.238/

The server usues Ubuntu, Apache2 webserver, and Postgres for DB. In order to prep and configure the environment I had to:
- configure server to only accept ports 80,2200,123
- configure ssh to use port 2200
- create user grader with access to sudo
- create ssh key pair for users
- disable root access and password based SSH access
- enable firewall and block all incoming ports except 80,2200,123
- install and enable mod_wsgi
- install Flask
- install virtualenv
- clone my catalog project using git and adding it to /var/www/
- enable a new virtual host for my app by creating new configuration file in /etc/apache2/sites-available/
- create a wsgi file in the /var/www/CatalogApp directory to launch my app
- configure Postgres user catalog with limited access
- made changes to code to connect to postgres DB using catalog user
