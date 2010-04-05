/* Plain SASL plugin
 * Rob Siemborski
 * Tim Martin 
 * $Id: xoauth.c,v 1.64 2004/09/08 11:06:11 mel Exp $
 */
/* 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#if 0
#include <config.h>
#endif
#include <stdlib.h>

#include <stdio.h>
#include <string.h> 
#include <sasl.h>
#include <saslplug.h>

#include "plugin_common.h"

#ifdef macintosh 
#include <sasl_xoauth_plugin_decl.h> 
#endif 

/*****************************  Common Section  *****************************/

static const char plugin_id[] = "$Id: plain.c,v 1.64 2004/09/08 11:06:11 mel Exp $";

FILE *debugfp;

#if 0
/*****************************  Server Section  *****************************/


static int xoauth_server_mech_new(void *glob_context __attribute__((unused)), 
				 sasl_server_params_t *sparams,
				 const char *challenge __attribute__((unused)),
				 unsigned challen __attribute__((unused)),
				 void **conn_context)
{
    /* holds state are in */
    if (!conn_context) {
	PARAMERROR( sparams->utils );
	return SASL_BADPARAM;
    }
    
    *conn_context = NULL;
    
    return SASL_OK;
}

static int xoauth_server_mech_step(void *conn_context __attribute__((unused)),
				  sasl_server_params_t *params,
				  const char *clientin,
				  unsigned clientinlen,
				  const char **serverout,
				  unsigned *serveroutlen,
				  sasl_out_params_t *oparams)
{
    const char *author;
    const char *authen;
    const char *password;
    unsigned password_len;
    unsigned lup=0;
    int result;
    char *passcopy; 
    
    *serverout = NULL;
    *serveroutlen = 0;
    
    /* should have received author-id NUL authen-id NUL password */
    
    /* get author */
    author = clientin;
    while ((lup < clientinlen) && (clientin[lup] != 0)) ++lup;
    
    if (lup >= clientinlen) {
	SETERROR(params->utils, "Can only find author (no password)");
	return SASL_BADPROT;
    }
    
    /* get authen */
    ++lup;
    authen = clientin + lup;
    while ((lup < clientinlen) && (clientin[lup] != 0)) ++lup;
    
    if (lup >= clientinlen) {
	params->utils->seterror(params->utils->conn, 0,
				"Can only find author/en (no password)");
	return SASL_BADPROT;
    }
    
    /* get password */
    lup++;
    password = clientin + lup;
    while ((lup < clientinlen) && (clientin[lup] != 0)) ++lup;
    
    password_len = (unsigned) (clientin + lup - password);
    
    if (lup != clientinlen) {
	SETERROR(params->utils,
		 "Got more data than we were expecting in the PLAIN plugin\n");
	return SASL_BADPROT;
    }
    
    /* this kinda sucks. we need password to be null terminated
       but we can't assume there is an allocated byte at the end
       of password so we have to copy it */
    passcopy = params->utils->malloc(password_len + 1);    
    if (passcopy == NULL) {
	MEMERROR(params->utils);
	return SASL_NOMEM;
    }
    
    strncpy(passcopy, password, password_len);
    passcopy[password_len] = '\0';
   
    /* Canonicalize userid first, so that password verification is only
     * against the canonical id */
    if (!author || !*author)
	author = authen;
    
    result = params->canon_user(params->utils->conn,
				authen, 0, SASL_CU_AUTHID, oparams);
    if (result != SASL_OK) {
	_plug_free_string(params->utils, &passcopy);
	return result;
    }
    
    /* verify password - return sasl_ok on success*/
    result = params->utils->checkpass(params->utils->conn,
				      oparams->authid, oparams->alen,
				      passcopy, password_len);
    
    _plug_free_string(params->utils, &passcopy);
    
    if (result != SASL_OK) {
	params->utils->seterror(params->utils->conn, 0,
				"Password verification failed");
	return result;
    }

    /* Canonicalize and store the authorization ID */
    /* We need to do this after calling verify_user just in case verify_user
     * needed to get auxprops itself */
    result = params->canon_user(params->utils->conn,
				author, 0, SASL_CU_AUTHZID, oparams);
    if (result != SASL_OK) return result;

    /* set oparams */
    oparams->doneflag = 1;
    oparams->mech_ssf = 0;
    oparams->maxoutbuf = 0;
    oparams->encode_context = NULL;
    oparams->encode = NULL;
    oparams->decode_context = NULL;
    oparams->decode = NULL;
    oparams->param_version = 0;
    
    return SASL_OK;
}

static sasl_server_plug_t xoauth_server_plugins[] = 
{
    {
	"PLAIN",			/* mech_name */
	0,				/* max_ssf */
	SASL_SEC_NOANONYMOUS,		/* security_flags */
	SASL_FEAT_WANT_CLIENT_FIRST
	| SASL_FEAT_ALLOWS_PROXY,	/* features */
	NULL,				/* glob_context */
	&xoauth_server_mech_new,		/* mech_new */
	&xoauth_server_mech_step,	/* mech_step */
	NULL,				/* mech_dispose */
	NULL,				/* mech_free */
	NULL,				/* setpass */
	NULL,				/* user_query */
	NULL,				/* idle */
	NULL,				/* mech_avail */
	NULL				/* spare */
    }
};

int xoauth_server_plug_init(const sasl_utils_t *utils,
			   int maxversion,
			   int *out_version,
			   sasl_server_plug_t **pluglist,
			   int *plugcount)
{
    if (maxversion < SASL_SERVER_PLUG_VERSION) {
	SETERROR(utils, "PLAIN version mismatch");
	return SASL_BADVERS;
    }
    
    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = xoauth_server_plugins;
    *plugcount = 1;  
    
    return SASL_OK;
}
#endif

/*****************************  Client Section  *****************************/

typedef struct client_context {
    char *out_buf;
    unsigned out_buf_len;
} client_context_t;

static int xoauth_client_mech_new(void *glob_context __attribute__((unused)),
				 sasl_client_params_t *params,
				 void **conn_context)
{
    client_context_t *text;
    
    /* holds state are in */
    text = params->utils->malloc(sizeof(client_context_t));
    if (text == NULL) {
	MEMERROR( params->utils );
	return SASL_NOMEM;
    }
    
    memset(text, 0, sizeof(client_context_t));
    
    *conn_context = text;
    debugfp = fopen("/tmp/sasl_oauth.log","w");
    fprintf(debugfp, "in client mech new\n");
    return SASL_OK;
}

static int xoauth_client_mech_step(void *conn_context,
				  sasl_client_params_t *params,
				  const char *serverin __attribute__((unused)),
				  unsigned serverinlen __attribute__((unused)),
				  sasl_interact_t **prompt_need,
				  const char **clientout,
				  unsigned *clientoutlen,
				  sasl_out_params_t *oparams)
{
    client_context_t *text = (client_context_t *) conn_context;
    const char *user = NULL, *authid = NULL;
    sasl_secret_t *password = NULL;
    unsigned int free_password = 0; /* set if we need to free password */
    int user_result = SASL_OK;
    int auth_result = SASL_OK;
    int pass_result = SASL_OK;
    int result;
    char *p;

    char *credfn,xoauthstring[1024];
    FILE *credfp;
    
    *clientout = NULL;
    *clientoutlen = 0;
   
    fprintf(debugfp,"in xoath client enter\n");
    /* doesn't really matter how the server responds */
    
    /* check if sec layer strong enough */

    if (params->props.min_ssf > params->external_ssf) {
	SETERROR( params->utils, "SSF requested of PLAIN plugin");
	return SASL_TOOWEAK;
    }

    
    /* try to get the authid */    
    if (oparams->authid == NULL) {
	auth_result = _plug_get_authid(params->utils, &authid, prompt_need);
	
	if ((auth_result != SASL_OK) && (auth_result != SASL_INTERACT))
	    return auth_result;
    }		
    
    /* try to get the userid */
    if (oparams->user == NULL) {
	user_result = _plug_get_userid(params->utils, &user, prompt_need);
	
	if ((user_result != SASL_OK) && (user_result != SASL_INTERACT))
	    return user_result;
    }
    
#if 0
    /* try to get the password */
    if (password == NULL) {
	pass_result = _plug_get_password(params->utils, &password,
					 &free_password, prompt_need);
	
	if ((pass_result != SASL_OK) && (pass_result != SASL_INTERACT))
	    return pass_result;
    }
#endif
    
    /* free prompts we got */
    if (prompt_need && *prompt_need) {
	params->utils->free(*prompt_need);
	*prompt_need = NULL;
    }

#if 0    
    /* if there are prompts not filled in */
    if ((user_result == SASL_INTERACT) || (auth_result == SASL_INTERACT) ||
	(pass_result == SASL_INTERACT)) {
	/* make the prompt list */
	result =
	    _plug_make_prompts(params->utils, prompt_need,
			       user_result == SASL_INTERACT ?
			       "Please enter your authorization name" : NULL,
			       NULL,
			       auth_result == SASL_INTERACT ?
			       "Please enter your authentication name" : NULL,
			       NULL,
			       pass_result == SASL_INTERACT ?
			       "Please enter your password" : NULL, NULL,
			       NULL, NULL, NULL,
			       NULL, NULL, NULL);
	if (result != SASL_OK) goto cleanup;
	
	return SASL_INTERACT;
    }
    
    if (!password) {
	PARAMERROR(params->utils);
	return SASL_BADPARAM;
    }

#endif
    if (!user || !*user) {
	result = params->canon_user(params->utils->conn, authid, 0,
				    SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
    }
    else {
	result = params->canon_user(params->utils->conn, user, 0,
				    SASL_CU_AUTHZID, oparams);
	if (result != SASL_OK) goto cleanup;
	
	result = params->canon_user(params->utils->conn, authid, 0,
				    SASL_CU_AUTHID, oparams);
    }
    /*    if (result != SASL_OK) goto cleanup;*/

    if (result != SASL_OK){
      fprintf(debugfp, "err: %s\n", sasl_errstring(result, NULL, NULL));
      goto cleanup;
    }
    
    /* get cred filename from environment: XOAUTHCRED */
    credfn = getenv("XOAUTHCRED");
    if (credfn == NULL) {
      result = SASL_FAIL;
      goto cleanup;
    }
    
    credfp = fopen(credfn, "r");
    if (credfp == NULL) {
      result = SASL_FAIL;
      goto cleanup;
    }
    
    memset(xoauthstring, 0, 1024);
    if (fread(xoauthstring, 1023, 1, credfp) < 1 && ! feof(credfp) ) {
      fprintf(debugfp, "xoauth client, read cred fail\n");
      fprintf(debugfp, "cred is:%s===\n",xoauthstring);
      result = SASL_FAIL;
      goto cleanup;
    }
    if (*index(xoauthstring,'\n')) {
      *index(xoauthstring,'\n')=0;
    }
    
    /* send authorized id NUL authentication id NUL password */
    #if 0
    *clientoutlen = ((user && *user ? oparams->ulen : 0) +
		     1 + oparams->alen +
		     1 + password->len);
    #endif

    *clientoutlen = strlen(xoauthstring)+1;
    
    /* remember the extra NUL on the end for stupid clients */
    result = _plug_buf_alloc(params->utils, &(text->out_buf),
			     &(text->out_buf_len), *clientoutlen + 1);
    if (result != SASL_OK) goto cleanup;
    
    memset(text->out_buf, 0, *clientoutlen + 1);
    p = text->out_buf;
    
    #if 0
    if (user && *user) {
	memcpy(p, oparams->user, oparams->ulen);
	p += oparams->ulen;
    }
    memcpy(++p, oparams->authid, oparams->alen);
    p += oparams->alen;
    memcpy(++p, password->data, password->len);
    #endif
    
    memcpy(p, xoauthstring, *clientoutlen);
    
    *clientout = text->out_buf;
    
    /* set oparams */
    oparams->doneflag = 1;
    oparams->mech_ssf = 128;
    oparams->maxoutbuf = 0;
    oparams->encode_context = NULL;
    oparams->encode = NULL;
    oparams->decode_context = NULL;
    oparams->decode = NULL;
    oparams->param_version = 0;
    
    result = SASL_OK;

  cleanup:
    /* free sensitive info */
    if (free_password) _plug_free_secret(params->utils, &password);
    
    fprintf(debugfp, "xoauth client exit, error is %s", sasl_errstring(result, NULL, NULL));
    return result;
}

static void xoauth_client_mech_dispose(void *conn_context,
				      const sasl_utils_t *utils)
{
    client_context_t *text = (client_context_t *) conn_context;
    
    if (!text) return;
    
    if (text->out_buf) utils->free(text->out_buf);
    
    utils->free(text);
}

static sasl_client_plug_t xoauth_client_plugins[] = 
{
    {
	"XOAUTH",			/* mech_name */
	56,				/* max_ssf */
	SASL_SEC_NOACTIVE|SASL_SEC_NOANONYMOUS|SASL_SEC_NOPLAINTEXT|SASL_SEC_MUTUAL_AUTH,		/* security_flags */
	SASL_FEAT_WANT_CLIENT_FIRST
	| SASL_FEAT_ALLOWS_PROXY,	/* features */
	NULL,				/* required_prompts */
	NULL,				/* glob_context */
	&xoauth_client_mech_new,		/* mech_new */
	&xoauth_client_mech_step,	/* mech_step */
	&xoauth_client_mech_dispose,	/* mech_dispose */
	NULL,				/* mech_free */
	NULL,				/* idle */
	NULL,				/* spare */
	NULL				/* spare */
    }
};

int xoauth_client_plug_init(sasl_utils_t *utils,
			   int maxversion,
			   int *out_version,
			   sasl_client_plug_t **pluglist,
			   int *plugcount)
{
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
	SETERROR(utils, "XOAUTH version mismatch");
	return SASL_BADVERS;
    }
    
    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = xoauth_client_plugins;
    *plugcount = 1;

    debugfp = fopen("/tmp/sasl_oauth.log","w");
    
    fclose(debugfp);
    return SASL_OK;
}
