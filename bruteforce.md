Brute Force attack is gaining unauthorised access to the target system using the account credentials of the user in various combinations untill the attempt is successful.
Example, The attacker wants to log in to the user web application,DVWA and he knows the target's username through reconnaissance and he tries various password combination with the username to login untill he succeeds.
In our case, Meta is the target host who is logging into the web application and we the attacker knows his username. We have created a password list by default and stored in our system.
We are using hydra tool to crack his account.

Target Web Application: http://192.168.1.5/dvwa
Username:admin
Password:password
On succesful login, the application enters into the application
On failed login, we get Log in Failed

As an atatcker or pentester we are using the hydra tool

In our kali linux, we enter the following command,
hydra -l admin -P "the location of the password list" "domain name of the application" http-post-form "/the directory of the login in the url:username=^USER^&password=^PASS^&Login=Login:F=Login failed"

hydra= the tool to brute force attack
-l= list
admin = username that we know
-P= to address the password
"the location of the password list"= where the file is located in the OS.
"domain name of the application" = domain name of the web app
http-post-form= is how the post request applies to the web application<you find it by pressing ctl+shift+I and go to Network tab and press Raw
the directory of the login page in the url
username=^USER^&password=^PASS^&Login=Login:F= Login failed  this you will give as per the Post request

As per our project, 

hydra -l admin -P /home/kali/gokul 192.168.5.173 http-post-form "dvwa/login/php:username=^USER^&password=^PASS^^Login=Login:F= login Failed"

The hydra tool tries different combinations for the username "admin" and selects the correct password from the wordlist stored in the file "gokul" through  brute force in the application.


#bruteforce
