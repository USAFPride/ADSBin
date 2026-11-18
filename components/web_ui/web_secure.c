/* Opt-in authenticated HTTPS configuration service.
 * Secrets require flash encryption before they can be persisted. Never put
 * credentials in logs, URLs, status JSON, or the open HTTP endpoint.
 */
#include "sdkconfig.h"
#ifdef CONFIG_ADSBIN_WEB_HTTPS_CONFIG
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_flash_encrypt.h"
#include "nvs.h"
#include "cJSON.h"
#include "web_ui.h"
static const char *TAG="web_secure";
static httpd_handle_t server;
static char admin_token[33];
extern const char index_html_start[] asm("_binary_index_html_start");
extern const char index_html_end[] asm("_binary_index_html_end");
extern const char servercert_pem_start[] asm("_binary_servercert_pem_start");
extern const char servercert_pem_end[] asm("_binary_servercert_pem_end");
extern const char serverkey_pem_start[] asm("_binary_serverkey_pem_start");
extern const char serverkey_pem_end[] asm("_binary_serverkey_pem_end");

static bool authorized(httpd_req_t *req) {
    char got[64] = {0};
    if(httpd_req_get_hdr_value_str(req,"X-ADSBin-Token",got,sizeof(got))!=ESP_OK) return false;
    /* Compare all bytes, not a prefix; constant time for correctly sized tokens. */
    if(strlen(got)!=sizeof(admin_token)-1) return false;
    unsigned diff=0;
    for(size_t i=0;i<sizeof(admin_token)-1;i++) diff |= (unsigned)(got[i]^admin_token[i]);
    return diff==0;
}
static esp_err_t unauthorized(httpd_req_t *r){
    return httpd_resp_send_err(r,HTTPD_401_UNAUTHORIZED,"Admin token required");
}
static esp_err_t page(httpd_req_t *r){
    httpd_resp_set_type(r,"text/html; charset=utf-8");
    httpd_resp_set_hdr(r,"Cache-Control","no-store");
    return httpd_resp_send(r,index_html_start,(int)(index_html_end-index_html_start));
}
static esp_err_t metadata(httpd_req_t *r){
    if(!authorized(r))return unauthorized(r);
    nvs_handle_t n;
    if(nvs_open("web_cfg",NVS_READONLY,&n)!=ESP_OK){
        httpd_resp_set_type(r,"application/json");
        return httpd_resp_sendstr(r,"{\"stored\":false,\"encrypted\":false}");
    }
    const char *keys[]={"wifi_ssid","beast_host","beast_port","wg_public",
                        "wg_endpoint","wg_ip","wg_port","wifi_pass","wg_private"};
    cJSON *root=cJSON_CreateObject();
    cJSON_AddBoolToObject(root,"stored",true);
    cJSON_AddBoolToObject(root,"encrypted",esp_flash_encryption_enabled());
    for(unsigned i=0;i<sizeof(keys)/sizeof(keys[0]);i++){
        size_t size=0;
        if(nvs_get_str(n,keys[i],NULL,&size)==ESP_OK && size>0){
            if(i>=7){cJSON_AddBoolToObject(root,keys[i],true);continue;}
            char *val=calloc(size,1);
            if(val){
                if(nvs_get_str(n,keys[i],val,&size)==ESP_OK)
                    cJSON_AddStringToObject(root,keys[i],val);
                free(val);
            }
        }
    }
    nvs_close(n);
    char *out=cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if(!out)return httpd_resp_send_err(r,HTTPD_500_INTERNAL_SERVER_ERROR,"Out of memory");
    httpd_resp_set_type(r,"application/json");
    httpd_resp_set_hdr(r,"Cache-Control","no-store");
    esp_err_t result=httpd_resp_sendstr(r,out);
    free(out);
    return result;
}
static bool is_ipv4(const char *s){
    unsigned a,b,c,d;char end;
    return sscanf(s,"%u.%u.%u.%u%c",&a,&b,&c,&d,&end)==4 &&
        a<=255 && b<=255 && c<=255 && d<=255;
}
static esp_err_t save(httpd_req_t *r){
    if(!authorized(r))return unauthorized(r);
    if(r->content_len<=0||r->content_len>1500)
        return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,"Invalid body length");
    char body[1501]={0};
    int got=0;
    while(got<r->content_len){
        int n=httpd_req_recv(r,body+got,r->content_len-got);
        if(n<=0)return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,"Incomplete request");
        got+=n;
    }
    cJSON *root=cJSON_Parse(body);
    memset(body,0,sizeof(body));
    if(!root||!cJSON_IsObject(root)){
        cJSON_Delete(root);
        return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,"Invalid JSON");
    }
    const char *keys[]={"wifi_ssid","wifi_pass","beast_host","beast_port",
                        "wg_private","wg_public","wg_endpoint","wg_ip","wg_port"};
    const size_t limits[]={32,63,45,5,44,44,128,15,5};
    bool secret_requested=false;
    for(const cJSON *item=root->child;item;item=item->next){
        int idx=-1;
        for(int i=0;i<9;i++)if(item->string&&strcmp(item->string,keys[i])==0){idx=i;break;}
        if(idx<0||!cJSON_IsString(item)||!item->valuestring||
           strlen(item->valuestring)>limits[idx]){
            cJSON_Delete(root);
            return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,"Invalid field");
        }
        if((idx==1||idx==4)&&item->valuestring[0])secret_requested=true;
        if((idx==3||idx==8)&&item->valuestring[0]){
            char *end=NULL;long port=strtol(item->valuestring,&end,10);
            if(!end||*end||port<1||port>65535){
                cJSON_Delete(root);return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,"Invalid port");
            }
        }
        if((idx==2||idx==7)&&item->valuestring[0]&&!is_ipv4(item->valuestring)){
            cJSON_Delete(root);return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,"Invalid IPv4 address");
        }
    }
    if(secret_requested){
        cJSON_Delete(root);
        return httpd_resp_send_err(r,HTTPD_403_FORBIDDEN,
            "Secret storage unavailable: encrypted NVS provisioning not yet implemented");
    }
    nvs_handle_t n;
    esp_err_t err=nvs_open("web_cfg",NVS_READWRITE,&n);
    if(err==ESP_OK){
        for(const cJSON *item=root->child;item;item=item->next){
            /* Blank password/key means leave existing secret untouched. */
            if((!strcmp(item->string,"wifi_pass")||!strcmp(item->string,"wg_private"))
                && !item->valuestring[0])continue;
            err=nvs_set_str(n,item->string,item->valuestring);
            if(err!=ESP_OK)break;
        }
        if(err==ESP_OK)err=nvs_commit(n);
        nvs_close(n);
    }
    cJSON_Delete(root);
    if(err!=ESP_OK)return httpd_resp_send_err(r,HTTPD_500_INTERNAL_SERVER_ERROR,"NVS commit failed");
    httpd_resp_set_type(r,"application/json");
    return httpd_resp_sendstr(r,"{\"saved\":true,\"apply\":\"reboot_required\"}");
}
esp_err_t web_ui_secure_start(void){
    if(server)return ESP_OK;
    uint8_t random[16];
    esp_fill_random(random,sizeof(random));
    for(unsigned i=0;i<16;i++)snprintf(admin_token+2*i,3,"%02x",random[i]);
    httpd_ssl_config_t cfg=HTTPD_SSL_CONFIG_DEFAULT();
    cfg.servercert=(const unsigned char*)servercert_pem_start;
    cfg.servercert_len=(size_t)(servercert_pem_end-servercert_pem_start);
    cfg.prvtkey_pem=(const unsigned char*)serverkey_pem_start;
    cfg.prvtkey_len=(size_t)(serverkey_pem_end-serverkey_pem_start);
    cfg.httpd.max_uri_handlers=5;
    cfg.httpd.stack_size=8192;
    esp_err_t err=httpd_ssl_start(&server,&cfg);
    if(err!=ESP_OK)return err;
    const httpd_uri_t routes[]={
        {.uri="/api/status",.method=HTTP_GET,.handler=web_ui_status_get},
        {.uri="/",.method=HTTP_GET,.handler=page},
        {.uri="/api/config",.method=HTTP_GET,.handler=metadata},
        {.uri="/api/config",.method=HTTP_POST,.handler=save}
    };
    for(unsigned i=0;i<sizeof(routes)/sizeof(routes[0]);i++){
        err=httpd_register_uri_handler(server,&routes[i]);
        if(err!=ESP_OK){httpd_ssl_stop(server);server=NULL;return err;}
    }
    ESP_LOGW(TAG,"HTTPS admin service enabled on port 443 (non-secret settings only)");
    ESP_LOGW(TAG,"ONE-BOOT ADMIN TOKEN: %s (UART ONLY; never share logs containing this line)",admin_token);
    return ESP_OK;
}
#endif
