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
#include <inc/ini.h>
#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS ;
}


/* this function is ripped from pam_unix/support.c, it lets us do IO via PAM */
int converse( pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response ) {
	int retval ;
	struct pam_conv *conv ;

	retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ; 
	if( retval==PAM_SUCCESS ) {
		retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr ) ;
	}

	return retval ;
}


/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval ;
	int i ;
    
	/* these guys will be used by converse() */
	char *input ;
	struct pam_message msg[1],*pmsg[1];
	struct pam_response *resp;
	
	/* retrieving parameters */
	int got_base_url  = 0 ;
	int got_code_size = 0 ;
	unsigned int code_size = 0 ;
	char base_url[256] ;
	for( i=0 ; i<argc ; i++ ) {
		if( strncmp(argv[i], "base_url=", 9)==0 ) {
			strncpy( base_url, argv[i]+9, 256 ) ;
			got_base_url = 1 ;
		} else if( strncmp(argv[i], "code_size=", 10)==0 ) {
			char temp[256] ;
			strncpy( temp, argv[i]+10, 256 ) ;
			code_size = atoi( temp ) ;
			got_code_size = 1 ;
		}
	}
	if( got_base_url==0 || got_code_size==0 ) {
		return PAM_AUTH_ERR ;
	}

	/* getting the username that was used in the previous authentication */
	const char *username ;
    	if( (retval = pam_get_user(pamh,&username,"login: "))!=PAM_SUCCESS ) {
		return retval ;
	}

	/* generating a random one-time code */
	char code[code_size+1] ;
  	unsigned int random_number ;
	FILE *urandom = fopen( "/dev/urandom", "r" ) ;
	fread( &random_number, sizeof(random_number), 1, urandom ) ;
	fclose( urandom ) ;
	snprintf( code, code_size+1,"%u", random_number ) ;
	code[code_size] = 0 ; // because it needs to be null terminated


    char public_code[6+1] ;
  	unsigned int rn ;
	FILE *urandom_pub = fopen( "/dev/urandom", "r" ) ;
	fread( &rn, sizeof(rn), 1, urandom_pub ) ;
	fclose( urandom_pub ) ;
	snprintf( public_code, 6+1,"%u", rn ) ;
	public_code[6] = 0 ; // because it needs to be null terminated

        CURL *curl = curl_easy_init();
        if(curl) {
        char data[code_size + 44];
        strcpy( data, "{\"text\":\"SSH MFA CODE for session ") ;
        strcat( data, public_code ) ;
        strcat( data, ": " ) ;
        strcat( data, code ) ;
        strcat( data, "\"}" ) ;
        struct curl_slist *list = NULL;
        
        curl_easy_setopt(curl, CURLOPT_URL, base_url);
        /* size of the POST data */
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(data));
        /* pass in a pointer to the data - libcurl will not copy */

        list = curl_slist_append(list, "Content-Type:application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_perform(curl);
        }

    char prompt_data[29];
    strcpy(prompt_data, "OTA code for session ") ;
    strcat(prompt_data, public_code);
    strcat(prompt_data, ": ");

	/* setting up conversation call prompting for one-time code */
	pmsg[0] = &msg[0] ;
	msg[0].msg_style = PAM_PROMPT_ECHO_ON ;
	msg[0].msg = prompt_data;

	resp = NULL ;
	if( (retval = converse(pamh, 1 , pmsg, &resp))!=PAM_SUCCESS ) {
		// if this function fails, make sure that ChallengeResponseAuthentication in sshd_config is set to yes
		return retval ;
	}

	/* retrieving user input */
	if( resp ) {
		if( (flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL ) {
	    		free( resp );
	    		return PAM_AUTH_ERR;
		}
		input = resp[ 0 ].resp;
		resp[ 0 ].resp = NULL; 		  				  
    	} else {
		return PAM_CONV_ERR;
	}
	
	/* comparing user input with known code */
	if( strcmp(input, code)==0 ) {
		/* good to go! */
		free( input ) ;
		return PAM_SUCCESS ;
	} else {
		/* wrong code */
		free( input ) ;
		return PAM_AUTH_ERR ;
	}

	/* we shouldn't read this point, but if we do, we might as well return something bad */
	return PAM_AUTH_ERR ;
}