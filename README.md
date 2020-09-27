# webhookpam
Webhook PAM Module 

## Build requirements

* `libcurl` headers. in RHEL/Centos: `yum install libcurl-devel`
* `pam`  headers. in RHEL/Centos: `yum install pam-devel`

## How to use

* Create a config.ini, using config.ini.sample as a template
* build the .so file using `make` and install using `sudo make install`. If `sudo make install` gives `not a directory` error, you can manually copy the .so file in the same folder as your distro's pam module. For RHEL/CentOS, it's located at `/lib64/security/`.
* Add the following line to `/etc/security/sshd`
  * `auth required pam_webhook.so conf_path=/path/to/config.ini`

## I'm being spammed by MFA messages

There are two scenarios that can lead to this

* your `auth required pam_webhook.so conf_path=/path/to/config.ini` is not positioned well inside `/etc/security/sshd`. If the line is sitting at the top of your PAM module config, this webhook becomes the first layer of authentication rather than being an extra layer of protection
* The line above `auth required pam_webhook.so conf_path=/path/to/config.ini` is not `required` ( it's `substack` in CentOS8). In this case, you can make the auth process stop before hitting the webhook by changing the `substack` to `[default=die]substack `. This means if your "normal" interactive auth fails, don't bother with the second factor and die immediately. in this case, your  `/etc/security/sshd` might end up looking like this:

```
   #%PAM-1.0
   auth       [default=die]substack     password-auth
   auth       requisite pam_webhook.so conf_path=/path/to/your/config.ini
   auth       include      postlogin
   account    required     pam_sepermit.so
   ...
```


## Working with SSH key

 `sshd` prevents interactive MFA when authentication is being done via a public/private keypair. To enable this module even with a key-pair, use the following config in `/etc/ssh/sshd_config`:

```
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive:pam  
```

please refer to [Arch Wiki](https://wiki.archlinux.org/index.php/OpenSSH#Two-factor_authentication_and_public_keys) for more info on how to make sure your `sshd` configuration is set up correctly for this to work.

## TODO

* Template engine for JSON data sent to the webhook target. So far PUBLIC_CODE, PRIVATE_CODE, USERNAME and SOURCE_IP are implemented. Having DESTINATION_IP, and AUTH_METHOD would be nice for audit purposes
* Proxy Configuration for Webhook Call
* Logic when request times out
* Optional emergency backdoor (?)
* Customizable Echo message in config file
  

## Reference
[ben servoz's blog](https://ben.akrin.com/2FA/2ndfactor.c)
