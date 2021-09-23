# Webhook PAM
Webhook PAM Module 

## Build requirements

`libcurl` headers:

* RHEL/Centos: `yum install libcurl-devel`
* Debian/Ubuntu: `apt-get install libcurl4-openssl-dev`
* Arch: `pacman -S curl`

`pam` headers:
* RHEL/Centos: `yum install pam-devel`
* Debian/Ubuntu: `apt-get install libpam0g-dev`
* Arch: `pacman -S pam`

## How to use

* Create a `config.ini`, using `config.ini`.sample as a template.
* build the `.so` file using `make` and install using `sudo make install`. If `sudo make install` gives `not a directory` error, you can manually copy the `.so` file in the same folder as your distro's pam module. In general `/lib/security/` and `/lib64/security/`.
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

- [ ] Template engine for JSON data sent to the webhook target.
  - [x] PUBLIC_CODE
  - [x] PRIVATE_CODE
  - [x] USERNAME 
  - [x] SOURCE_IP
  - [ ] DESTINATION_IP
  - [ ] AUTH_METHOD
- [x] Proxy Configuration for Webhook Call
- [ ] Logic when request times out
- [ ] Optional emergency backdoor (?)
- [ ] Customizable Echo message in config file
- [ ] Test in LDAP Auth environment
- [x] Better install and uninstall support in the `Makefie`

## Reference
[ben servoz's blog](https://ben.akrin.com/2FA/2ndfactor.c)
