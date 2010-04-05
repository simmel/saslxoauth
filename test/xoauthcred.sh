#!/bin/sh
#export XOAUTHCRED=/tmp/xoauth.cred
python xoauth.py --generate_xoauth_string --user=somebody@gmail.com\
 --oauth_token=deed\
 --oauth_token_secret=deeddeed| sed -n '/^GET /p' >$XOAUTHCRED
