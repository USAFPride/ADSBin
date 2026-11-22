/* Local HTTP bench configuration. Credentials only when explicit unsafe
 * Kconfig opt-in is enabled. Never echo passwords in GET or logs. */
#include "sdkconfig.h"
#ifdef CONFIG_ADSBIN_WEB_HTTP_CONFIG
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "esp_http_server.h"
#include "esp_log.h"
#include "nvs.h"
#include "cJSON.h"
#include "web_ui.h"
#include "web_auth.h"
#include "device_security.h"
#include "wifi_station.h"
static const char *TAG="web_secure";
static esp_err_t metadata(httpd_req_t *r){
    if(!web_auth_require(r)) return ESP_OK;
    nvs_handle_t n;
    if(nvs_open("web_cfg",NVS_READONLY,&n)!=ESP_OK){
        httpd_resp_set_type(r,"application/json");
        return httpd_resp_sendstr(r,"{\"stored\":false,\"wifi_password_entry_enabled\":true}");
    }
    const char *keys[]={"wifi_ssid","beast_host","beast_port","wg_public",
                        "wg_endpoint","wg_ip","wg_port","beast_enabled","mgmt_cidr"};
    cJSON *root=cJSON_CreateObject();
    cJSON_AddBoolToObject(root,"stored",true);
    cJSON_AddBoolToObject(root,"wifi_password_entry_enabled",true);
    cJSON_AddBoolToObject(root,"wifi_password_configured",device_security_has_secret("wifi_pass"));
    cJSON_AddBoolToObject(root,"wg_private_configured",device_security_has_secret("wg_private"));
    cJSON_AddBoolToObject(root,"wg_psk_configured",device_security_has_secret("wg_psk"));
    for(unsigned i=0;i<sizeof(keys)/sizeof(keys[0]);i++){
        size_t size=0;
        if(nvs_get_str(n,keys[i],NULL,&size)==ESP_OK && size>0){
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
    if(!web_auth_require(r)) return ESP_OK;
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
    const char *keys[]={"wifi_ssid","beast_host","beast_port",
                        "wg_public","wg_endpoint","wg_ip","wg_port",
                        "wifi_pass","beast_enabled","wg_private","wg_psk","mgmt_cidr"};
    const size_t limits[]={32,45,5,44,128,15,5,63,1,44,44,31};
    for(const cJSON *item=root->child;item;item=item->next){
        int idx=-1;
        for(unsigned i=0;i<sizeof(keys)/sizeof(keys[0]);i++)if(item->string&&strcmp(item->string,keys[i])==0){idx=(int)i;break;}
        if(idx<0||!cJSON_IsString(item)||!item->valuestring||
           strlen(item->valuestring)>limits[idx]){
            cJSON_Delete(root);
            return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,"Invalid field");
        }
        if(idx==11 && (!web_auth_local(r,true) || !web_auth_valid_management_cidr(item->valuestring))) {
            cJSON_Delete(root); return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,"Change management CIDR from AP only; use private network CIDR or blank");
        }
        if(idx==8 &&
           (strlen(item->valuestring)!=1 ||
            (item->valuestring[0]!='0' && item->valuestring[0]!='1'))) {
            cJSON_Delete(root);
            return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,"Invalid Beast enable value");
        }
        if(idx==9 || idx==10 || (idx==3 && item->valuestring[0])){
            const char *k=item->valuestring;
            if(strlen(k)!=44 || k[43]!='=' || strspn(k,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")!=43){
                cJSON_Delete(root); return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,"Invalid WireGuard base64 key");
            }
        }
        if(idx==7){
            size_t pwlen=strlen(item->valuestring);
            if(pwlen<8 || pwlen>63){
                cJSON_Delete(root);
                return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,"Test Wi-Fi password must be 8-63 characters");
            }
        }
        if((idx==2||idx==6)&&item->valuestring[0]){
            char *end=NULL;long port=strtol(item->valuestring,&end,10);
            if(!end||*end||port<1||port>65535){
                cJSON_Delete(root);return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,"Invalid port");
            }
        }
        if((idx==1||idx==5)&&item->valuestring[0]&&!is_ipv4(item->valuestring)){
            cJSON_Delete(root);return httpd_resp_send_err(r,HTTPD_400_BAD_REQUEST,"Invalid IPv4 address");
        }
    }
    nvs_handle_t n;
    esp_err_t err=nvs_open("web_cfg",NVS_READWRITE,&n);
    if(err==ESP_OK){
        for(const cJSON *item=root->child;item;item=item->next){
            if(!strcmp(item->string,"wifi_pass") || !strcmp(item->string,"wg_private") || !strcmp(item->string,"wg_psk"))
                err=device_security_set_secret(item->string,item->valuestring);
            else err=nvs_set_str(n,item->string,item->valuestring);
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
static esp_err_t wifi_test(httpd_req_t *req)
{
    if(!web_auth_require(req)) return ESP_OK;
    esp_err_t err = wifi_station_request_test();
    if (err != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                   "AP+STA not ready or test already running");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"started\":true}");
}
esp_err_t web_ui_http_config_register(httpd_handle_t server)
{
    const httpd_uri_t get={.uri="/api/config",.method=HTTP_GET,.handler=metadata};
    const httpd_uri_t post={.uri="/api/config",.method=HTTP_POST,.handler=save};
    esp_err_t err=httpd_register_uri_handler(server,&get);
    if(err==ESP_OK)err=httpd_register_uri_handler(server,&post);
    const httpd_uri_t test={.uri="/api/wifi/test",.method=HTTP_POST,.handler=wifi_test};
    if(err==ESP_OK)err=httpd_register_uri_handler(server,&test);
    if(err==ESP_OK)ESP_LOGW(TAG,"Local HTTP configuration; reversible development vault, trusted networks only");
    return err;
}
#endif
