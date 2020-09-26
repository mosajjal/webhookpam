gcc -fPIC -lcurl -o pam_webhook.o -c pam_webhook.c
ld -lcurl -lc -lpam -shared -o pam_webhook.so pam_webhook.o