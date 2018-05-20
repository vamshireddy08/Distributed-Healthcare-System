# Distributed-Healthcare-System
patient can schedule an appointment with a provider using this application.

install following packages :

sudo apt-get install libmysqlclient-dev 
sudo apt-get install openssl
sudo apt-get install libssl-dev
sudo apt-get install curl
sudo apt-get install libcurl4-gnutls-dev


setting up mysql database:
mysqldump -u cmpe207 -p cmpe207 > /home/vamshi/team3_Project/team3.sql	 //command to save mysql contents in team3.sql file


mysql -u root -p
enter password

Run following mysql commands:
CREATE USER 'cmpe207'@'localhost' IDENTIFIED BY 'Cmpe@207';
GRANT ALL PRIVILEGES ON *.* TO 'cmpe207'@'localhost';
show databases;
create database cmpe207;
use cmpe207;

// import the database, be careful of the file path

cd healthcare
mysql -u cmpe207 -p cmpe207 < team3.sql		// mysql -u <username> -p <databasename> < team3.sql

cd twilio_c_sms
make		// ignore warnings
cd bin
./server	// to start the server

open new terminal and go to file path healthcare\client
cd client
make
./client	// to start the client

Test cases:

1.patient login
username: vamshi08
password: cmpe207

2.Doctor login 
username: doc_0001
password: doc

3.Insurance company
username: AU_0002
password: p

4.Admin
username: team3
password: team3
