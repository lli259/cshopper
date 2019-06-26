# cshopper


#apache2 server deploying on python3

#python flask install 
sudo su #use root to install package, or apache2 can't find the installed packages.
#if sudo su, the followings can run without sudo.
sudo apt-get update
sudo apt install python3-pip
sudo apt-get -y install python3 python3-flask

pip3 install -r requirements.txt
python3 __init__.py   #to test if the program work locally

#apach service
sudo apt-get -y install apache2

#wsgi loader tool
#sudo apt-get -y remove libapache2-mod-wsgi #remove python2 wsgi
sudo apt-get -y install libapache2-mod-wsgi-py3

#edit apache2 conf, where the wsgi and code are
sudo vim /etc/apache2/sites-available/FlaskApp.conf

sudo a2dissite 000-default.conf
sudo a2ensite FlaskApp.conf
sudo service apache2 restart


#-----------------------------
deploy https
change FlaskApp.conf to the new cshopperstore.conf
open both http https ssh in security group
add port 80 44 desciption in one cshopperstore.conf, 
this should be in availabe folder
run certbot
if success, it will write something to port 80 and 443.
the rewritten is in enable folder.
.
#some refers
https://www.digitalocean.com/community/tutorials/how-to-deploy-a-flask-application-on-an-ubuntu-vps
http://terokarvinen.com/2016/deploy-flask-python3-on-apache2-ubuntu
https://www.digitalocean.com/community/tutorials/how-to-secure-apache-with-let-s-encrypt-on-ubuntu-18-04
https://blog.csdn.net/qq_33421902/article/details/80237266
