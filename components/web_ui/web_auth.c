/* HTTP management for trusted local networks only. No TLS: interception by
 * a local active attacker remains possible. Never allow management via a
 * routed WAN or VPN source. Cookies are host-only, HttpOnly, SameSite=Strict.
 * All mutating routes require JSON and same-origin browser requests. */
#include "web_auth.h"
#include "device_security.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#define SESSION_SECONDS 1800LL
#define SESSION_SLOTS 4
#define LOGIN_BASE_US 2000000LL
typedef struct {
    char token[65];
    int64_t expires;
    uint32_t peer;
    uint32_t local;
} session_t;
/* HTTPD dispatches these handlers on one server task. */
static session_t sessions[SESSION_SLOTS];
static unsigned invalid_attempts;
static int64_t next_login;

static bool endpoints(httpd_req_t *r,uint32_t *peer,uint32_t *local) {
    struct sockaddr_storage p={0},l={0};
    socklen_t pn=sizeof(p),ln=sizeof(l);
    int fd=httpd_req_to_sockfd(r);
    if(fd<0 || getpeername(fd,(struct sockaddr*)&p,&pn)!=0 ||
       getsockname(fd,(struct sockaddr*)&l,&ln)!=0) return false;
    if(p.ss_family!=AF_INET || l.ss_family!=AF_INET) return false;
    *peer=((struct sockaddr_in*)&p)->sin_addr.s_addr;
    *local=((struct sockaddr_in*)&l)->sin_addr.s_addr;
    return true;
}
static bool private_ip(uint32_t ip) {
    uint32_t v=ntohl(ip);
    return (v>>24)==10 || (v>>20)==0xac1 || (v>>16)==0xc0a8;
}
static bool on_interface(const char *key,uint32_t peer,uint32_t local) {
    esp_netif_t *n=esp_netif_get_handle_from_ifkey(key);
    esp_netif_ip_info_t info={0};
    if(!n || !esp_netif_is_netif_up(n) || esp_netif_get_ip_info(n,&info)!=ESP_OK ||
       info.ip.addr!=local || !info.netmask.addr || !private_ip(peer) || !private_ip(local)) return false;
    return (peer & info.netmask.addr)==(local & info.netmask.addr) && peer!=info.gw.addr && peer!=local;
}
bool web_auth_local(httpd_req_t *r,bool ap_only) {
    uint32_t peer,local;
    if(!device_security_ready() || !endpoints(r,&peer,&local)) return false;
    if(on_interface("WIFI_AP_DEF",peer,local)) return true;
    return !ap_only && device_security_configured() && on_interface("WIFI_STA_DEF",peer,local);
}
void web_auth_headers(httpd_req_t *r) {
    httpd_resp_set_hdr(r,"Cache-Control","no-store");
    httpd_resp_set_hdr(r,"X-Content-Type-Options","nosniff");
    httpd_resp_set_hdr(r,"X-Frame-Options","DENY");
    httpd_resp_set_hdr(r,"Referrer-Policy","no-referrer");
    httpd_resp_set_hdr(r,"Content-Security-Policy","default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
}
static esp_err_t forbidden(httpd_req_t *r,const char *msg) {
    httpd_resp_set_status(r,"403 Forbidden");
    httpd_resp_set_type(r,"text/plain");
    return httpd_resp_sendstr(r,msg);
}
static bool request_host_valid(httpd_req_t *r) {
    uint32_t peer,local;
    char host[64],expected[INET_ADDRSTRLEN],with_port[64];
    if(!endpoints(r,&peer,&local) || !inet_ntop(AF_INET,&local,expected,sizeof(expected)) ||
       httpd_req_get_hdr_value_str(r,"Host",host,sizeof(host))!=ESP_OK) return false;
    snprintf(with_port,sizeof(with_port),"%s:80",expected);
    return !strcmp(host,expected)||!strcmp(host,with_port);
}
static bool same_origin(httpd_req_t *r) {
    char host[64],origin[96],expected[96],typ[64],site[24];
    if(!request_host_valid(r) ||
       httpd_req_get_hdr_value_str(r,"Host",host,sizeof(host))!=ESP_OK ||
       httpd_req_get_hdr_value_str(r,"Content-Type",typ,sizeof(typ))!=ESP_OK ||
       strcmp(typ,"application/json")!=0) return false;
    if(httpd_req_get_hdr_value_str(r,"Sec-Fetch-Site",site,sizeof(site))==ESP_OK &&
       strcmp(site,"same-origin") && strcmp(site,"none")) return false;
    esp_err_t e=httpd_req_get_hdr_value_str(r,"Origin",origin,sizeof(origin));
    if(e==ESP_ERR_NOT_FOUND) return true; /* non-browser JSON clients */
    if(e!=ESP_OK) return false;
    snprintf(expected,sizeof(expected),"http://%s",host);
    return strcmp(origin,expected)==0;
}
static session_t *find_session(httpd_req_t *r) {
    char cookies[512];
    if(httpd_req_get_hdr_value_str(r,"Cookie",cookies,sizeof(cookies))!=ESP_OK) return NULL;
    uint32_t peer,local;
    if(!endpoints(r,&peer,&local)) return NULL;
    char *p=cookies;
    while(p && *p) {
        while(*p==' ') p++;
        char *end=strchr(p,';');
        if(end) *end=0;
        if(!strncmp(p,"ads_session=",12) && strlen(p+12)==64) {
            int64_t now=esp_timer_get_time();
            for(unsigned i=0;i<SESSION_SLOTS;i++) {
                session_t *s=&sessions[i];
                uint8_t diff=0;
                for(unsigned j=0;j<64;j++) diff|=(uint8_t)(s->token[j]^p[12+j]);
                if(!diff && s->expires>now && s->peer==peer && s->local==local) return s;
            }
        }
        p=end?end+1:NULL;
    }
    return NULL;
}
bool web_auth_require(httpd_req_t *r) {
    web_auth_headers(r);
    if(!web_auth_local(r,false) || !request_host_valid(r)) {
        (void)forbidden(r,"Local management only"); return false;
    }
    if(r->method!=HTTP_GET && !same_origin(r)) {
        (void)forbidden(r,"Same-origin JSON requests only"); return false;
    }
    session_t *s=find_session(r);
    if(!device_security_configured() || !s) {
        httpd_resp_set_status(r,"401 Unauthorized");
        (void)httpd_resp_sendstr(r,"Login required"); return false;
    }
    s->expires=esp_timer_get_time()+SESSION_SECONDS*1000000LL;
    return true;
}
static bool public_route(httpd_req_t *r,bool ap_only,bool post) {
    web_auth_headers(r);
    if(!web_auth_local(r,ap_only) || !request_host_valid(r) || (post && !same_origin(r))) {
        (void)forbidden(r,"Local same-origin management only"); return false;
    }
    return true;
}
static cJSON *read_json(httpd_req_t *r) {
    char body[400]={0};
    if(r->content_len<2||r->content_len>=sizeof(body)) return NULL;
    int got=0;
    while(got<r->content_len) {
        int n=httpd_req_recv(r,body+got,r->content_len-got);
        if(n<=0) { memset(body,0,sizeof(body)); return NULL; }
        got+=n;
    }
    cJSON *root=cJSON_Parse(body);
    memset(body,0,sizeof(body));
    if(!cJSON_IsObject(root)) { cJSON_Delete(root); return NULL; }
    return root;
}
static const char *field(cJSON *root,const char *name) {
    cJSON *v=cJSON_GetObjectItemCaseSensitive(root,name);
    return cJSON_IsString(v)?v->valuestring:NULL;
}
static esp_err_t json(httpd_req_t *r,const char *msg) {
    httpd_resp_set_type(r,"application/json");
    return httpd_resp_sendstr(r,msg);
}
static esp_err_t bad(httpd_req_t *r,const char *msg) {
    return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,msg);
}
static esp_err_t state(httpd_req_t *r) {
    if(!public_route(r,false,false)) return ESP_OK;
    if(!device_security_configured()) return json(r,"{\"configured\":false,\"authenticated\":false}");
    return json(r,find_session(r)?"{\"configured\":true,\"authenticated\":true}":"{\"configured\":true,\"authenticated\":false}");
}
static esp_err_t setup(httpd_req_t *r) {
    if(!public_route(r,true,true)) return ESP_OK;
    if(device_security_configured()) return forbidden(r,"Already initialized");
    cJSON *root=read_json(r);
    const char *pass=root?field(root,"password"):NULL,*confirm=root?field(root,"confirm"):NULL;
    bool valid=device_security_valid_password(pass)&&confirm&&!strcmp(pass,confirm);
    esp_err_t e=valid?device_security_set_password(pass):ESP_ERR_INVALID_ARG;
    cJSON_Delete(root);
    if(!valid) return bad(r,"Passwords must match: 12-63 printable ASCII characters");
    if(e!=ESP_OK) return httpd_resp_send_err(r,HTTPD_500_INTERNAL_SERVER_ERROR,"Secure setup failed");
    memset(sessions,0,sizeof(sessions));
    esp_err_t result=json(r,"{\"saved\":true,\"restart\":true}");
    device_security_schedule_restart();
    return result;
}
static void fail_login(void) {
    invalid_attempts++;
    unsigned shift=invalid_attempts>5?5:invalid_attempts;
    next_login=esp_timer_get_time()+(LOGIN_BASE_US<<shift);
}
static esp_err_t login(httpd_req_t *r) {
    if(!public_route(r,false,true)) return ESP_OK;
    if(!device_security_configured()) return forbidden(r,"Initialize on AP first");
    int64_t now=esp_timer_get_time();
    if(now<next_login) {
        httpd_resp_set_status(r,"429 Too Many Requests");
        httpd_resp_set_hdr(r,"Retry-After","5");
        return httpd_resp_sendstr(r,"Login temporarily rate limited");
    }
    cJSON *root=read_json(r);
    const char *pass=root?field(root,"password"):NULL;
    bool ok=device_security_check_password(pass);
    cJSON_Delete(root);
    if(!ok) { fail_login(); httpd_resp_set_status(r,"401 Unauthorized"); return httpd_resp_sendstr(r,"Incorrect password"); }
    invalid_attempts=0; next_login=0;
    uint32_t peer,local;
    if(!endpoints(r,&peer,&local)) return forbidden(r,"Local management only");
    session_t *s=&sessions[0];
    for(unsigned i=0;i<SESSION_SLOTS;i++) {
        if(sessions[i].expires<=now) { s=&sessions[i]; break; }
        if(sessions[i].expires<s->expires) s=&sessions[i];
    }
    uint8_t random[32];
    esp_fill_random(random,sizeof(random));
    static const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<32;i++) {s->token[2*i]=hex[random[i]>>4]; s->token[2*i+1]=hex[random[i]&15];}
    s->token[64]=0; memset(random,0,sizeof(random));
    s->expires=esp_timer_get_time()+SESSION_SECONDS*1000000LL; s->peer=peer; s->local=local;
    char cookie[160];
    snprintf(cookie,sizeof(cookie),"ads_session=%s; Path=/; HttpOnly; SameSite=Strict",s->token);
    httpd_resp_set_hdr(r,"Set-Cookie",cookie);
    return json(r,"{\"authenticated\":true}");
}
static esp_err_t logout(httpd_req_t *r) {
    if(!web_auth_require(r)) return ESP_OK;
    session_t *s=find_session(r);
    if(s) memset(s,0,sizeof(*s));
    httpd_resp_set_hdr(r,"Set-Cookie","ads_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
    return json(r,"{\"authenticated\":false}");
}
static esp_err_t change(httpd_req_t *r) {
    if(!web_auth_require(r)) return ESP_OK;
    if(esp_timer_get_time()<next_login) {httpd_resp_set_status(r,"429 Too Many Requests");return httpd_resp_sendstr(r,"Try again later");}
    cJSON *root=read_json(r);
    const char *old=root?field(root,"current"):NULL,*pass=root?field(root,"password"):NULL,*confirm=root?field(root,"confirm"):NULL;
    bool correct=device_security_check_password(old);
    bool valid=device_security_valid_password(pass)&&confirm&&!strcmp(pass,confirm);
    esp_err_t e=correct&&valid?device_security_set_password(pass):ESP_ERR_INVALID_ARG;
    cJSON_Delete(root);
    if(!correct) {fail_login();return forbidden(r,"Incorrect current password");}
    if(!valid) return bad(r,"Passwords must match: 12-63 printable ASCII characters");
    if(e!=ESP_OK) return httpd_resp_send_err(r,HTTPD_500_INTERNAL_SERVER_ERROR,"Could not save password");
    invalid_attempts=0; next_login=0;
    memset(sessions,0,sizeof(sessions));
    httpd_resp_set_hdr(r,"Set-Cookie","ads_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
    esp_err_t result=json(r,"{\"saved\":true,\"restart\":true}");
    device_security_schedule_restart();
    return result;
}
esp_err_t web_auth_register(httpd_handle_t server) {
    const httpd_uri_t routes[]={
        {.uri="/api/auth/state",.method=HTTP_GET,.handler=state},
        {.uri="/api/auth/setup",.method=HTTP_POST,.handler=setup},
        {.uri="/api/auth/login",.method=HTTP_POST,.handler=login},
        {.uri="/api/auth/logout",.method=HTTP_POST,.handler=logout},
        {.uri="/api/auth/password",.method=HTTP_POST,.handler=change}
    };
    for(unsigned i=0;i<sizeof(routes)/sizeof(routes[0]);i++) {
        esp_err_t e=httpd_register_uri_handler(server,&routes[i]);
        if(e!=ESP_OK) return e;
    }
    return ESP_OK;
}
