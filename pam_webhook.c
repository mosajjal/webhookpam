/*******************************************************************************
 * file:        pam_webhook.c
 * author:      Ali Mosajjal
 * description: PAM module to provide MFA using Webhook
 * notes:       instructions at http://blog.n0p.me
 * usage:		refer to blog
*******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <pwd.h>
#include <sys/types.h>

#include "inc/ini.c"

typedef struct
{
	int secret_code_size;
	int public_code_size;
	int timeout_seconds;
	bool authfail_on_httpfail;
	const char *url;
	const char *json_data;
	const char *proxy;

} configuration;

static int handler(void *config_profile, const char *section, const char *name,
				   const char *value)
{
	configuration *pconfig = (configuration *)config_profile;

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
	if (MATCH("general", "secret_code_size"))
	{
		pconfig->secret_code_size = atoi(value);
	}
	else if (MATCH("general", "public_code_size"))
	{
		pconfig->public_code_size = atoi(value);
	}
	else if (MATCH("general", "authfail_on_httpfail"))
	{
		pconfig->json_data = value;
	}
	else if (MATCH("general", "proxy"))
	{
		pconfig->proxy = strdup(value);
	}
	else if (MATCH("webhook", "url"))
	{
		pconfig->url = strdup(value);
	}
	else if (MATCH("webhook", "json_data"))
	{
		pconfig->json_data = strdup(value);
	}
	else
	{
		return 0; /* unknown section/name, error */
	}
	return 1;
}

// Function to replace a string with another string
char *replaceWord(const char *s, const char *oldW,
				  const char *newW)
{
	char *result;
	int i, cnt = 0;
	int newWlen = strlen(newW);
	int oldWlen = strlen(oldW);

	// Counting the number of times old word
	// occur in the string
	for (i = 0; s[i] != '\0'; i++)
	{
		if (strstr(&s[i], oldW) == &s[i])
		{
			cnt++;

			// Jumping to index after the old word.
			i += oldWlen - 1;
		}
	}

	// Making new string of enough length
	result = (char *)malloc(i + cnt * (newWlen - oldWlen) + 1);

	i = 0;
	while (*s)
	{
		// compare the substring with the result
		if (strstr(s, oldW) == s)
		{
			strcpy(&result[i], newW);
			i += newWlen;
			s += oldWlen;
		}
		else
			result[i++] = *s++;
	}

	result[i] = '\0';
	return result;
}

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

/* this function is ripped from pam_unix/support.c, it lets us do IO via PAM */
int converse(pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response)
{
	int retval;
	struct pam_conv *conv;

	retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	if (retval == PAM_SUCCESS)
	{
		retval = conv->conv(nargs, (const struct pam_message **)message, response, conv->appdata_ptr);
	}

	return retval;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;
	int i;

	/* these guys will be used by converse() */
	char *input;
	struct pam_message msg[1], *pmsg[1];
	struct pam_response *resp;

	char conf_path[256];
	int got_conf_path = 0;
	for (i = 0; i < argc; i++)
	{
		if (strncmp(argv[i], "conf_path=", 10) == 0)
		{
			strncpy(conf_path, argv[i] + 10, 256);
			got_conf_path = 1;
		}
	}
	if (!got_conf_path)
		return PAM_AUTH_ERR;

	configuration config;
	if (ini_parse(conf_path, handler, &config) < 0)
	{
		printf("Can't load the config\n");
		return PAM_AUTH_ERR;
	}

	// /* getting the username that was used in the previous authentication */
	// const char *username ;
	// 	if( (retval = pam_get_user(pamh,&username,"login: "))!=PAM_SUCCESS ) {
	// 	return retval ;
	// }

	/* Check user */
	const char *username;
	if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS ||
		(getpwnam(username)) == NULL)
	{
		return PAM_USER_UNKNOWN;
	}

	char *source_ip;
	pam_get_item(pamh, PAM_RHOST, (const void **)&source_ip);

	/* generating a random one-time code */
	char code[config.secret_code_size + 1];
	unsigned int random_number;
	FILE *urandom = fopen("/dev/urandom", "r");
	fread(&random_number, sizeof(random_number), 1, urandom);
	snprintf(code, config.secret_code_size + 1, "%u", random_number);
	code[config.secret_code_size] = 0; // because it needs to be null terminated

	char public_code[config.public_code_size + 1];
	unsigned int rn;
	fread(&rn, sizeof(rn), 1, urandom);
	fclose(urandom);
	snprintf(public_code, config.public_code_size + 1, "%u", rn);
	public_code[config.public_code_size] = 0; // because it needs to be null terminated

	CURL *curl = curl_easy_init();

	if (curl)
	{

		char *data;
		data = replaceWord(config.json_data, "PUBLIC_CODE", public_code);
		data = replaceWord(data, "PRIVATE_CODE", code);
		data = replaceWord(data, "USERNAME", username);
		data = replaceWord(data, "SOURCE_IP", source_ip);

		struct curl_slist *list = NULL;
		curl_easy_setopt(curl, CURLOPT_URL, config.url);
		/* add proxy option if configured (this line must be at top) */
		if (config.proxy)
		{
			curl_easy_setopt(curl, CURLOPT_PROXY, config.proxy);
		}
		/* size of the POST data */
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(data));
		/* pass in a pointer to the data - libcurl will not copy */
		list = curl_slist_append(list, "Content-Type:application/json");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
		curl_easy_perform(curl);
	}

	char prompt_data[29];
	strcpy(prompt_data, "OTA code for session ");
	strcat(prompt_data, public_code);
	strcat(prompt_data, ": ");

	/* setting up conversation call prompting for one-time code */
	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_PROMPT_ECHO_ON;
	msg[0].msg = prompt_data;

	resp = NULL;
	if ((retval = converse(pamh, 1, pmsg, &resp)) != PAM_SUCCESS)
	{
		// if this function fails, make sure that ChallengeResponseAuthentication in sshd_config is set to yes
		return retval;
	}

	/* retrieving user input */
	if (resp)
	{
		if ((flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL)
		{
			free(resp);
			return PAM_AUTH_ERR;
		}
		input = resp[0].resp;
		resp[0].resp = NULL;
	}
	else
	{
		return PAM_CONV_ERR;
	}

	/* comparing user input with known code */
	if (strcmp(input, code) == 0)
	{
		/* good to go! */
		free(input);
		return PAM_SUCCESS;
	}
	else
	{
		/* wrong code */
		free(input);
		return PAM_AUTH_ERR;
	}

	/* we shouldn't read this point, but if we do, we might as well return something bad */
	return PAM_AUTH_ERR;
}