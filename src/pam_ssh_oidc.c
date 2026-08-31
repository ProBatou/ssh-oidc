#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define CFG_PATH "/etc/security/pam-ssh-oidc.conf"
#define DEFAULT_SCOPE "openid profile email groups"
#define MAX_BODY (1024 * 1024)

typedef struct {
    char *issuer, *client_id, *client_secret, *scope;
    char *allowed_linux_users, *allow_users, *require_groups;
    char *ntfy_url, *ntfy_topic, *ntfy_token, *ntfy_user, *ntfy_password;
    int timeout;
} config_t;

typedef struct { char *device, *token, *userinfo; } discovery_t;
typedef struct { char *device_code, *user_code, *uri, *uri_complete; int expires, interval; } device_t;
typedef struct { char *p; size_t n; } buffer_t;

static char *dup_nonempty(const char *s) { return (s && *s) ? strdup(s) : NULL; }
static char *trim(char *s) { while (*s && isspace((unsigned char)*s)) s++; char *e=s+strlen(s); while(e>s && isspace((unsigned char)e[-1])) *--e=0; return s; }
static void setstr(char **dst,const char *src){ free(*dst); *dst=dup_nonempty(src); }
static void rstrip_slash(char *s){ if(!s)return; size_t n=strlen(s); while(n && s[n-1]=='/')s[--n]=0; }

static void free_config(config_t *c){
    free(c->issuer);free(c->client_id);free(c->client_secret);free(c->scope);
    free(c->allowed_linux_users);free(c->allow_users);free(c->require_groups);
    free(c->ntfy_url);free(c->ntfy_topic);free(c->ntfy_token);free(c->ntfy_user);free(c->ntfy_password);
    memset(c,0,sizeof(*c));
}

static int load_config(config_t *c){
    memset(c,0,sizeof(*c)); c->timeout=180; c->scope=strdup(DEFAULT_SCOPE); c->allowed_linux_users=strdup("root");
    FILE *f=fopen(CFG_PATH,"r"); if(!f)return -1;
    char *line=NULL; size_t cap=0; char section[64]="";
    while(getline(&line,&cap,f)>=0){
        char *p=trim(line); if(!*p||*p=='#'||*p==';')continue;
        if(*p=='['){ char *e=strchr(p,']'); if(!e)continue; *e=0; snprintf(section,sizeof(section),"%s",trim(p+1)); continue; }
        if(*section && strcasecmp(section,"ssh-oidc") && strcasecmp(section,"pocketid"))continue;
        char *eq=strchr(p,'='); if(!eq)continue; *eq=0; char *k=trim(p),*v=trim(eq+1);
        if(!strcasecmp(k,"issuer"))setstr(&c->issuer,v); else if(!strcasecmp(k,"client_id"))setstr(&c->client_id,v);
        else if(!strcasecmp(k,"client_secret"))setstr(&c->client_secret,v); else if(!strcasecmp(k,"scope"))setstr(&c->scope,v);
        else if(!strcasecmp(k,"allowed_linux_users"))setstr(&c->allowed_linux_users,v); else if(!strcasecmp(k,"allow_users"))setstr(&c->allow_users,v);
        else if(!strcasecmp(k,"require_groups"))setstr(&c->require_groups,v); else if(!strcasecmp(k,"ntfy_url"))setstr(&c->ntfy_url,v);
        else if(!strcasecmp(k,"ntfy_topic"))setstr(&c->ntfy_topic,v); else if(!strcasecmp(k,"ntfy_token"))setstr(&c->ntfy_token,v);
        else if(!strcasecmp(k,"ntfy_user"))setstr(&c->ntfy_user,v); else if(!strcasecmp(k,"ntfy_password"))setstr(&c->ntfy_password,v);
        else if(!strcasecmp(k,"timeout")){ long n=strtol(v,NULL,10); if(n>0&&n<=3600)c->timeout=(int)n; }
    }
    free(line); fclose(f); rstrip_slash(c->issuer); rstrip_slash(c->ntfy_url);
    return (c->issuer&&c->client_id)?0:-1;
}

static int csv_has(const char *csv,const char *needle){
    if(!csv||!*csv||!needle||!*needle)return 0; char *copy=strdup(csv),*save=NULL,*t; if(!copy)return 0; int ok=0;
    for(t=strtok_r(copy,",",&save);t;t=strtok_r(NULL,",",&save))if(!strcasecmp(trim(t),needle)){ok=1;break;} free(copy); return ok;
}

static int pam_info(pam_handle_t *pamh,const char *text){
    const void *service=NULL;
    if(pam_get_item(pamh,PAM_SERVICE,&service)==PAM_SUCCESS&&service&&!strcmp((const char*)service,"sshd"))return PAM_SUCCESS;
    const struct pam_conv *conv=NULL; if(pam_get_item(pamh,PAM_CONV,(const void**)&conv)!=PAM_SUCCESS||!conv||!conv->conv)return PAM_CONV_ERR;
    struct pam_message m={PAM_TEXT_INFO,text}; const struct pam_message *mp=&m; struct pam_response *r=NULL;
    int rc=conv->conv(1,&mp,&r,conv->appdata_ptr); if(r){ if(r->resp){memset(r->resp,0,strlen(r->resp));free(r->resp);} free(r);} return rc;
}

static size_t writer(char *ptr,size_t size,size_t nmemb,void *ud){
    buffer_t *b=ud; size_t add=size*nmemb; if(add>MAX_BODY||b->n>MAX_BODY-add)return 0; char *p=realloc(b->p,b->n+add+1); if(!p)return 0;
    b->p=p;memcpy(b->p+b->n,ptr,add);b->n+=add;b->p[b->n]=0;return add;
}

static int request(const char *url,int post,const char *body,struct curl_slist *headers,const char *userpwd,buffer_t *out,long *status){
    memset(out,0,sizeof(*out)); CURL *h=curl_easy_init(); if(!h)return -1;
    curl_easy_setopt(h,CURLOPT_URL,url);curl_easy_setopt(h,CURLOPT_FOLLOWLOCATION,0L);curl_easy_setopt(h,CURLOPT_CONNECTTIMEOUT,20L);curl_easy_setopt(h,CURLOPT_TIMEOUT,20L);
    curl_easy_setopt(h,CURLOPT_NOSIGNAL,1L);curl_easy_setopt(h,CURLOPT_USERAGENT,"pam-ssh-oidc/1");curl_easy_setopt(h,CURLOPT_WRITEFUNCTION,writer);curl_easy_setopt(h,CURLOPT_WRITEDATA,out);
    if(headers)curl_easy_setopt(h,CURLOPT_HTTPHEADER,headers); if(userpwd){curl_easy_setopt(h,CURLOPT_HTTPAUTH,CURLAUTH_BASIC);curl_easy_setopt(h,CURLOPT_USERPWD,userpwd);}
    if(post){curl_easy_setopt(h,CURLOPT_POST,1L);curl_easy_setopt(h,CURLOPT_POSTFIELDS,body?body:"");}
    CURLcode rc=curl_easy_perform(h); if(rc==CURLE_OK)curl_easy_getinfo(h,CURLINFO_RESPONSE_CODE,status); curl_easy_cleanup(h);
    if(rc!=CURLE_OK){free(out->p);memset(out,0,sizeof(*out));return -1;} return 0;
}

static char *join_url(const char *a,const char *b){size_t n=strlen(a)+strlen(b)+1;char *p=malloc(n);if(p)snprintf(p,n,"%s%s",a,b);return p;}
static char *jstr(json_object *o,const char *k){json_object *v=NULL;return (o&&json_object_object_get_ex(o,k,&v)&&json_object_is_type(v,json_type_string))?dup_nonempty(json_object_get_string(v)):NULL;}
static int jint(json_object *o,const char *k,int d){json_object *v=NULL;return (o&&json_object_object_get_ex(o,k,&v))?json_object_get_int(v):d;}

static int discover(const config_t *c,discovery_t *d){
    memset(d,0,sizeof(*d));char *u=join_url(c->issuer,"/.well-known/openid-configuration");buffer_t b;long s=0;
    if(!u||request(u,0,NULL,NULL,NULL,&b,&s)<0||s/100!=2){free(u);free(b.p);return -1;}free(u);
    json_object *j=json_tokener_parse(b.p?b.p:"");free(b.p);if(!j)return -1;
    d->device=jstr(j,"device_authorization_endpoint");d->token=jstr(j,"token_endpoint");d->userinfo=jstr(j,"userinfo_endpoint");json_object_put(j);
    if(!d->device)d->device=join_url(c->issuer,"/api/oidc/device/authorize");if(!d->token)d->token=join_url(c->issuer,"/api/oidc/token");if(!d->userinfo)d->userinfo=join_url(c->issuer,"/api/oidc/userinfo");
    return(d->device&&d->token&&d->userinfo)?0:-1;
}
static void free_discovery(discovery_t*d){free(d->device);free(d->token);free(d->userinfo);memset(d,0,sizeof(*d));}

static char *pair(CURL*h,const char*k,const char*v){char *e=curl_easy_escape(h,v?v:"",0);if(!e)return NULL;size_t n=strlen(k)+strlen(e)+2;char*p=malloc(n);if(p)snprintf(p,n,"%s=%s",k,e);curl_free(e);return p;}
static char *make_form(const config_t*c,const char*grant,const char*code){
    CURL*h=curl_easy_init();if(!h)return NULL;char *parts[5]={0};int count=0;
    parts[count++]=pair(h,"client_id",c->client_id);if(c->client_secret)parts[count++]=pair(h,"client_secret",c->client_secret);
    if(grant){parts[count++]=pair(h,"grant_type",grant);parts[count++]=pair(h,"device_code",code);}else parts[count++]=pair(h,"scope",c->scope?c->scope:DEFAULT_SCOPE);
    size_t n=1;for(int i=0;i<count;i++){if(!parts[i]){for(int q=0;q<count;q++)free(parts[q]);curl_easy_cleanup(h);return NULL;}n+=strlen(parts[i])+1;}
    char*out=calloc(1,n);if(out)for(int i=0;i<count;i++){if(i)strcat(out,"&");strcat(out,parts[i]);}for(int i=0;i<count;i++)free(parts[i]);curl_easy_cleanup(h);return out;
}

static int begin_device(const config_t*c,const discovery_t*d,device_t*v){
    memset(v,0,sizeof(*v));char*form=make_form(c,NULL,NULL);if(!form)return -1;struct curl_slist*h=NULL;h=curl_slist_append(h,"Content-Type: application/x-www-form-urlencoded");buffer_t b;long s=0;
    int rc=request(d->device,1,form,h,NULL,&b,&s);curl_slist_free_all(h);free(form);if(rc<0||s/100!=2){free(b.p);return -1;}
    json_object*j=json_tokener_parse(b.p?b.p:"");free(b.p);if(!j)return -1;v->device_code=jstr(j,"device_code");v->user_code=jstr(j,"user_code");v->uri=jstr(j,"verification_uri");v->uri_complete=jstr(j,"verification_uri_complete");v->expires=jint(j,"expires_in",c->timeout);v->interval=jint(j,"interval",5);json_object_put(j);return v->device_code?0:-1;
}
static void free_device(device_t*v){free(v->device_code);free(v->user_code);free(v->uri);free(v->uri_complete);memset(v,0,sizeof(*v));}

static void ntfy(const config_t*c,const device_t*v,const char*user,const char*rhost){
    if(!c->ntfy_url||!c->ntfy_topic)return;CURL*t=curl_easy_init();if(!t)return;char*topic=curl_easy_escape(t,c->ntfy_topic,0);if(!topic){curl_easy_cleanup(t);return;}
    char *url=NULL,*body=NULL,*click=NULL,*actions=NULL,*auth=NULL,*userpwd=NULL;asprintf(&url,"%s/%s",c->ntfy_url,topic);asprintf(&body,"SSH login for %s from %s\nCode: %s",user,rhost,v->user_code?v->user_code:"");
    struct curl_slist*h=NULL;h=curl_slist_append(h,"Title: SSH OIDC authentication");const char*link=v->uri_complete?v->uri_complete:v->uri;
    if(link){asprintf(&click,"Click: %s",link);asprintf(&actions,"Actions: view, Open Pocket ID, %s",link);if(click)h=curl_slist_append(h,click);if(actions)h=curl_slist_append(h,actions);}
    if(c->ntfy_token){asprintf(&auth,"Authorization: Bearer %s",c->ntfy_token);if(auth)h=curl_slist_append(h,auth);}else if(c->ntfy_user)asprintf(&userpwd,"%s:%s",c->ntfy_user,c->ntfy_password?c->ntfy_password:"");
    buffer_t b;long s=0;if(url&&body)request(url,1,body,h,userpwd,&b,&s);else memset(&b,0,sizeof(b));free(b.p);curl_slist_free_all(h);curl_free(topic);curl_easy_cleanup(t);free(url);free(body);free(click);free(actions);free(auth);free(userpwd);
}

static char *poll_token(const config_t*c,const discovery_t*d,const device_t*v){
    int interval=v->interval<2?2:v->interval,expires=v->expires>0?v->expires:c->timeout;if(expires>c->timeout)expires=c->timeout;time_t until=time(NULL)+expires;
    while(time(NULL)<until){char*form=make_form(c,"urn:ietf:params:oauth:grant-type:device_code",v->device_code);if(!form)return NULL;struct curl_slist*h=NULL;h=curl_slist_append(h,"Content-Type: application/x-www-form-urlencoded");buffer_t b;long s=0;
        int rc=request(d->token,1,form,h,NULL,&b,&s);(void)s;curl_slist_free_all(h);free(form);if(rc<0){free(b.p);return NULL;}json_object*j=json_tokener_parse(b.p?b.p:"");free(b.p);if(!j)return NULL;
        char*token=jstr(j,"access_token"),*err=jstr(j,"error");json_object_put(j);if(token){free(err);return token;}if(err&&!strcmp(err,"slow_down"))interval+=2;else if(err&&strcmp(err,"authorization_pending")){free(err);return NULL;}free(err);sleep((unsigned)interval);
    }return NULL;
}

static json_object *userinfo(const discovery_t*d,const char*token){
    char*auth=NULL;asprintf(&auth,"Authorization: Bearer %s",token);if(!auth)return NULL;struct curl_slist*h=NULL;h=curl_slist_append(h,auth);buffer_t b;long s=0;int rc=request(d->userinfo,0,NULL,h,NULL,&b,&s);curl_slist_free_all(h);free(auth);if(rc<0||s/100!=2){free(b.p);return NULL;}json_object*j=json_tokener_parse(b.p?b.p:"");free(b.p);return j;
}

static int claim_match(json_object*j,const char*k,const char*csv,int local){json_object*v=NULL;if(!csv||!*csv||!json_object_object_get_ex(j,k,&v)||!json_object_is_type(v,json_type_string))return 0;const char*s=json_object_get_string(v);if(csv_has(csv,s))return 1;if(local){const char*a=strchr(s,'@');if(a){char*p=strndup(s,(size_t)(a-s));int ok=p?csv_has(csv,p):0;free(p);if(ok)return 1;}}return 0;}
static int group_one(json_object*v,const char*csv){if(json_object_is_type(v,json_type_string))return csv_has(csv,json_object_get_string(v));if(json_object_is_type(v,json_type_object)){const char*k[]={"name","display_name","id",NULL};for(int i=0;k[i];i++){json_object*x=NULL;if(json_object_object_get_ex(v,k[i],&x)&&json_object_is_type(x,json_type_string)&&csv_has(csv,json_object_get_string(x)))return 1;}}return 0;}
static int group_match(json_object*j,const char*csv){json_object*g=NULL;if(!csv||!*csv||!json_object_object_get_ex(j,"groups",&g))return 0;if(json_object_is_type(g,json_type_array)){size_t n=json_object_array_length(g);for(size_t i=0;i<n;i++)if(group_one(json_object_array_get_idx(g,i),csv))return 1;return 0;}return group_one(g,csv);}
static int linux_match(json_object*j,const char*user){const char*k[]={"preferred_username","email","sub","name",NULL};for(int i=0;k[i];i++){json_object*v=NULL;if(!json_object_object_get_ex(j,k[i],&v)||!json_object_is_type(v,json_type_string))continue;const char*s=json_object_get_string(v);if(!strcasecmp(s,user))return 1;if(!strcmp(k[i],"email")){const char*a=strchr(s,'@');if(a&&strlen(user)==(size_t)(a-s)&&!strncasecmp(s,user,(size_t)(a-s)))return 1;}}return 0;}
static int authorized(json_object*j,const config_t*c,const char*user){if(claim_match(j,"preferred_username",c->allow_users,0)||claim_match(j,"email",c->allow_users,1)||claim_match(j,"sub",c->allow_users,0)||claim_match(j,"name",c->allow_users,0))return 1;if(group_match(j,c->require_groups))return 1;if(!c->require_groups||!*c->require_groups)return linux_match(j,user);return 0;}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t*pamh,int flags,int argc,const char**argv){
    (void)flags;(void)argc;(void)argv;const char*user=NULL;if(pam_get_user(pamh,&user,NULL)!=PAM_SUCCESS||!user)return PAM_AUTH_ERR;const void*ri=NULL;const char*rhost="unknown";if(pam_get_item(pamh,PAM_RHOST,&ri)==PAM_SUCCESS&&ri&&*(const char*)ri)rhost=(const char*)ri;
    config_t c;if(load_config(&c)<0){pam_info(pamh,"SSH OIDC configuration error.\n");return PAM_AUTHINFO_UNAVAIL;}int result=PAM_AUTH_ERR;if(!csv_has(c.allowed_linux_users,user)){result=PAM_USER_UNKNOWN;goto out_cfg;}
    if(curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK){result=PAM_AUTHINFO_UNAVAIL;goto out_cfg;}discovery_t d;if(discover(&c,&d)<0){pam_info(pamh,"OIDC provider unavailable.\n");result=PAM_AUTHINFO_UNAVAIL;goto out_curl;}device_t v;if(begin_device(&c,&d,&v)<0){pam_info(pamh,"Unable to start OIDC authentication.\n");goto out_disc;}
    ntfy(&c,&v,user,rhost);const char*link=v.uri_complete?v.uri_complete:v.uri;char*m=NULL;if(asprintf(&m,"\nOIDC authentication required.\nA notification was sent when ntfy is configured.\nOpen: %s\nCode: %s\nWaiting for approval...\n",link?link:"",v.user_code?v.user_code:"")>=0){pam_info(pamh,m);free(m);}
    char*token=poll_token(&c,&d,&v);if(!token){pam_info(pamh,"OIDC authentication failed or timed out.\n");goto out_dev;}json_object*j=userinfo(&d,token);free(token);if(!j)goto out_dev;if(!authorized(j,&c,user)){pam_info(pamh,"OIDC identity is not authorized for this SSH account.\n");json_object_put(j);goto out_dev;}json_object_put(j);pam_info(pamh,"OIDC authentication successful.\n");result=PAM_SUCCESS;
out_dev:free_device(&v);out_disc:free_discovery(&d);out_curl:curl_global_cleanup();out_cfg:free_config(&c);return result;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t*pamh,int flags,int argc,const char**argv){(void)pamh;(void)flags;(void)argc;(void)argv;return PAM_SUCCESS;}