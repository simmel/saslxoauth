#include <stdio.h>
#include <sasl.h>

static int my_sasl_cb_log (void* context, int priority, const char* message)
{
  fprintf (stderr, "SASL: %s\n", message);

  return SASL_OK;
}


int my_sasl_start (void)
{
  static unsigned char sasl_init = 0;

  static sasl_callback_t callbacks[2];
  int rc;

  if (sasl_init)
    return SASL_OK;

  /* set up default logging callback */
  callbacks[0].id = SASL_CB_LOG;
  callbacks[0].proc = my_sasl_cb_log;
  callbacks[0].context = NULL;

  callbacks[1].id = SASL_CB_LIST_END;
  callbacks[1].proc = NULL;
  callbacks[1].context = NULL;

  rc = sasl_client_init (callbacks);

  if (rc != SASL_OK)
  {
    fprintf (stderr, "my_sasl_start: libsasl initialisation failed.\n");
    return SASL_FAIL;
  }

  sasl_init = 1;

  return SASL_OK;
}



int main(void) {
  char *method="xoauth";
  sasl_conn_t* saslconn;
  sasl_interact_t *interaction;
  char* pc;
  unsigned olen;
  char* mech;
  int rc;
  
  rc = my_sasl_start();
  if (rc != SASL_OK) {
    fprintf(stderr, "SASL: INIT FAIL\n");
    goto end;
  }
  
  printf("here 0\n");

  rc = sasl_client_new("IMAP", 
		       "imap.gmail.com", 
		       "1.1.1.1;993",
		       "2.2.2.2;12345",
		       NULL,
		       SASL_SUCCESS_DATA,
		       &saslconn);
  if (rc != SASL_OK) {
    fprintf(stderr, "SASL: NEW FAIL\n");
    goto end;
  }
  
  printf("here1\n");
  rc = sasl_client_start (saslconn, method, &interaction,
        &pc, &olen, &mech);
  if (rc != SASL_OK) {
    fprintf(stderr, "SASL: START FAIL\n");
    goto end;
  }

 end:
  printf("end\n");
}
