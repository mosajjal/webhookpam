# webhookpam
Webhook PAM Module 

## How to use

* Create a config.ini, using config.ini.sample as a template
* build the .so file using `make` and install using `sudo make install` 
* Add the following line to `/etc/security/sshd`
  * `auth required pam_webhook.so conf_path=/path/to/config.ini`
