/*
** By Bob Jenkins, February 22, 1997, Public Domain
** This is an example of how to use the hash table.
**
** Given an input (stdin) with lines in any order
**   produce an output (stdout) with duplicate lines removed.
** Lines may not be longer than 4096 characters.
*/

#ifndef STANDARD
#include "standard.h"
#endif
#ifndef HASHTAB
#include "hashtab.h"
#endif
#define LINELEN 4096

int main()
{
  ub1   buf[LINELEN];
  ub1 *key, *val;
  ub4  keyl;
  htab *t;
  int cnt = 0 ;
  char str[256] ;

  t = hcreate(8);                      /* create hash table */

  /* read in all the lines */
  while (gets((char *)buf))            /* get line from stdin */
  {
    keyl = strlen((char *)buf);
    sprintf(str, "idx:%d", cnt++);
    if (hadd(t, buf, keyl, (void *)0)) /* if not a duplicate */
    {
      key = (ub1 *)malloc(keyl);       /* dumb use of malloc */
      memcpy(key, buf, keyl);          /* copy buf into key */
      hkey(t)=key;                     /* replace buf with key */
      val = (ub1 *)malloc(sizeof(str));       /* dumb use of malloc */
      memcpy(val, str, sizeof(str));          /* copy str to value */
      hstuff(t)=val;
    }
  }

  if (hfirst(t)) do                    /* go to first element */
  {
    printf("%.*s=%s\n",hkeyl(t),hkey(t), hstuff(t)); /* dump it to stdout */
  }
  while (hnext(t));                    /* go to next element */

  while (hcount(t))                    /* while the table is not empty */
  {
    free(hkey(t));                     /* free memory for the line */
    hdel(t);                           /* delete from hash table */
  }

  hdestroy(t);                         /* destroy hash table */

  return SUCCESS;
}
