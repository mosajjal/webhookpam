CC=gcc
LD=ld

default:
	$(CC) -fPIC -lcurl -o pam_webhook.o -c pam_webhook.c
	$(LD) -lcurl -lc -lpam -shared -o pam_webhook.so pam_webhook.o

install:
	cp pam_webhook.so /lib/security/

clean:
	rm pam_webhook.so
	rm pam_webhook.o
