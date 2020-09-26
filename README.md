# webhookpam
Webhook PAM Module 

## How to use

* Create a config.ini, using config.ini.sample as a template
* build the .so file using `make` and install using `sudo make install` 
* Add the following line to `/etc/security/sshd`
  * `auth required pam_webhook.so conf_path=/path/to/config.ini`


## TODO

* Template engine for JSON data sent to the webhook target. So far PUBLIC_CODE, PRIVATE_CODE and USERNAME are implemented. Having SOURCE_IP, DESTINATION_IP, HOSTNAME, AUTH_METHOD would be nice for audit purposes
* Proxy Configuration for Webhook Call
* Logic when request times out
* Optional emergency backdoor (?)
* Customizable Echo message in config file
  

## Reference
[ben servoz's blog](https://ben.akrin.com/2FA/2ndfactor.c)
