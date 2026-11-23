/* Reversible test vault. AES-256-GCM key is stored in ordinary NVS on
 * this branch; protects against accidental plaintext exposure, NOT physical
 * flash extraction. Production requires hardware protected key storage.
 * No eFuse writes or boot security changes. */
#include "device_security.h"
#include <stdint.h>
#include <string.h>
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "psa/crypto.h"

#define VAULT_NS "ads_vault"
#define PBKDF_ROUNDS 200000u
#define RESET_GPIO GPIO_NUM_35
#define MAX_SECRET 128
static const char *TAG = "device_sec";
static SemaphoreHandle_t lock;
static uint8_t vault_key[32];
static bool ready;
static volatile bool resetting;
static bool configured;
typedef struct {
    uint8_t salt[16];
    uint8_t hash[32];
    /* Reserved for compatibility with the initial PR15 account layout. */
    uint8_t nonce[12];
    uint8_t ciphertext[64 + 16];
} account_t;

static void wipe(void *v, size_t n) {
    volatile uint8_t *p = v;
    while(n--) *p++ = 0;
}
static bool equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for(size_t i=0;i<n;i++) diff |= a[i]^b[i];
    return diff == 0;
}
static bool hash_password(const char *pass, const uint8_t salt[16], uint8_t hash[32]) {
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t r = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if(r==PSA_SUCCESS) r=psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, PBKDF_ROUNDS);
    if(r==PSA_SUCCESS) r=psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,salt,16);
    if(r==PSA_SUCCESS) r=psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,(const uint8_t*)pass,strlen(pass));
    if(r==PSA_SUCCESS) r=psa_key_derivation_output_bytes(&op,hash,32);
    (void)psa_key_derivation_abort(&op);
    return r==PSA_SUCCESS;
}
static esp_err_t crypt(bool encrypt,const char *name,const uint8_t nonce[12],
                       const uint8_t *in,size_t in_len,uint8_t *out,size_t cap,size_t *len) {
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr,256);
    psa_set_key_algorithm(&attr,PSA_ALG_GCM);
    psa_set_key_usage_flags(&attr,encrypt?PSA_KEY_USAGE_ENCRYPT:PSA_KEY_USAGE_DECRYPT);
    psa_status_t r=psa_import_key(&attr,vault_key,sizeof(vault_key),&key);
    if(r==PSA_SUCCESS) {
        if(encrypt) r=psa_aead_encrypt(key,PSA_ALG_GCM,nonce,12,(const uint8_t*)name,strlen(name),in,in_len,out,cap,len);
        else r=psa_aead_decrypt(key,PSA_ALG_GCM,nonce,12,(const uint8_t*)name,strlen(name),in,in_len,out,cap,len);
        (void)psa_destroy_key(key);
    }
    psa_reset_key_attributes(&attr);
    return r==PSA_SUCCESS?ESP_OK:ESP_FAIL;
}
static esp_err_t account_read(account_t *a) {
    nvs_handle_t n;
    esp_err_t e=nvs_open(VAULT_NS,NVS_READONLY,&n);
    if(e!=ESP_OK) return e;
    size_t size=sizeof(*a);
    e=nvs_get_blob(n,"account",a,&size);
    nvs_close(n);
    if(e==ESP_OK && size!=sizeof(*a)) e=ESP_ERR_INVALID_SIZE;
    return e;
}
esp_err_t device_security_init(void) {
    if(ready) return ESP_OK;
    if(psa_crypto_init()!=PSA_SUCCESS) return ESP_FAIL;
    lock=xSemaphoreCreateMutex();
    if(!lock) return ESP_ERR_NO_MEM;
    nvs_handle_t n;
    esp_err_t e=nvs_open(VAULT_NS,NVS_READWRITE,&n);
    if(e!=ESP_OK) return e;
    size_t len=sizeof(vault_key);
    e=nvs_get_blob(n,"test_key",vault_key,&len);
    if(e==ESP_ERR_NVS_NOT_FOUND) {
        esp_fill_random(vault_key,sizeof(vault_key));
        e=nvs_set_blob(n,"test_key",vault_key,sizeof(vault_key));
        if(e==ESP_OK) e=nvs_commit(n);
    } else if(e==ESP_OK && len!=sizeof(vault_key)) e=ESP_ERR_INVALID_SIZE;
    nvs_close(n);
    if(e!=ESP_OK) return e;
    account_t a={0};
    e=account_read(&a);
    wipe(&a,sizeof(a));
    if(e!=ESP_OK && e!=ESP_ERR_NVS_NOT_FOUND) return e;
    configured=e==ESP_OK;
    /* Explicitly discard legacy plaintext bench settings on first upgrade.
     * NVS logical deletion is not a physical erase; use test credentials. */
    if(!configured && nvs_open("web_cfg",NVS_READWRITE,&n)==ESP_OK) {
        e=nvs_erase_all(n);
        if(e==ESP_OK) e=nvs_commit(n);
        nvs_close(n);
        if(e!=ESP_OK) return e;
    }
    /* Verify the configured crypto backend on boot, not after claiming device. */
    uint8_t test_salt[16]={0}, hash[32], nonce[12]={0}, enc[32], dec[16];
    size_t enc_len=0,dec_len=0;
    bool good=hash_password("self-test",test_salt,hash) &&
        crypt(true,"selftest",nonce,(const uint8_t*)"test",4,enc,sizeof(enc),&enc_len)==ESP_OK &&
        crypt(false,"selftest",nonce,enc,enc_len,dec,sizeof(dec),&dec_len)==ESP_OK &&
        dec_len==4 && memcmp(dec,"test",4)==0;
    wipe(hash,sizeof(hash)); wipe(dec,sizeof(dec)); wipe(enc,sizeof(enc));
    if(!good) { ESP_LOGE(TAG,"Crypto backend unavailable; provisioning disabled"); return ESP_FAIL; }
    ready=true;
    return ESP_OK;
}
bool device_security_ready(void) { return ready && !resetting; }
bool device_security_configured(void) { return configured; }
bool device_security_reset_pending(void) { return resetting; }
bool device_security_valid_password(const char *p) {
    if(!p) return false;
    size_t n=strlen(p);
    if(n<12 || n>63) return false;
    for(size_t i=0;i<n;i++) if((unsigned char)p[i]<32 || (unsigned char)p[i]>126) return false;
    return true;
}
esp_err_t device_security_set_password(const char *pass) {
    if(!device_security_ready() || !device_security_valid_password(pass)) return ESP_ERR_INVALID_ARG;
    account_t a={0};
    esp_fill_random(a.salt,sizeof(a.salt));
    esp_err_t e=ESP_FAIL;
    xSemaphoreTake(lock,portMAX_DELAY);
    if(hash_password(pass,a.salt,a.hash)) {
        nvs_handle_t n;
        e=nvs_open(VAULT_NS,NVS_READWRITE,&n);
        if(e==ESP_OK) {
            e=nvs_set_blob(n,"account",&a,sizeof(a));
            if(e==ESP_OK) e=nvs_commit(n);
            nvs_close(n);
        }
        if(e==ESP_OK) configured=true;
    }
    xSemaphoreGive(lock);
    wipe(&a,sizeof(a));
    return e;
}
bool device_security_check_password(const char *pass) {
    if(!device_security_ready() || !configured || !device_security_valid_password(pass)) return false;
    account_t a={0}; uint8_t digest[32]={0};
    xSemaphoreTake(lock,portMAX_DELAY);
    bool correct=account_read(&a)==ESP_OK && hash_password(pass,a.salt,digest) && equal(digest,a.hash,sizeof(digest));
    xSemaphoreGive(lock);
    wipe(&a,sizeof(a)); wipe(digest,sizeof(digest));
    return correct;
}
static bool secret_name(const char *name) {
    return name && (!strcmp(name,"wifi_pass") || !strcmp(name,"wg_private") || !strcmp(name,"wg_psk"));
}
esp_err_t device_security_get_secret(const char *name,char *out,size_t size) {
    if(!out || !size || !name) return ESP_ERR_INVALID_ARG;
    memset(out,0,size);
    if(!device_security_ready() || !configured) return ESP_ERR_INVALID_STATE;
    xSemaphoreTake(lock,portMAX_DELAY);
    esp_err_t e=ESP_FAIL; size_t len=0;
    uint8_t clear[MAX_SECRET+1]={0};
    if(secret_name(name)) {
        uint8_t blob[12+MAX_SECRET+1+16]={0};
        nvs_handle_t n;
        e=nvs_open(VAULT_NS,NVS_READONLY,&n);
        if(e==ESP_OK) {
            size_t b=sizeof(blob);
            e=nvs_get_blob(n,name,blob,&b);
            nvs_close(n);
            if(e==ESP_OK && b>=29) e=crypt(false,name,blob,blob+12,b-12,clear,sizeof(clear),&len);
            else if(e==ESP_OK) e=ESP_ERR_INVALID_SIZE;
        }
        wipe(blob,sizeof(blob));
    } else e=ESP_ERR_INVALID_ARG;
    if(e==ESP_OK) {
        if(!len || len>sizeof(clear) || clear[len-1]!=0 || strlen((char*)clear)+1>size) e=ESP_ERR_INVALID_SIZE;
        else memcpy(out,clear,strlen((char*)clear)+1);
    }
    wipe(clear,sizeof(clear));
    xSemaphoreGive(lock);
    return e;
}
esp_err_t device_security_set_secret(const char *name,const char *value) {
    if(!device_security_ready() || !configured || !secret_name(name) || !value || strlen(value)>MAX_SECRET) return ESP_ERR_INVALID_ARG;
    uint8_t blob[12+MAX_SECRET+1+16]={0}; size_t len=0;
    esp_fill_random(blob,12);
    xSemaphoreTake(lock,portMAX_DELAY);
    esp_err_t e=crypt(true,name,blob,(const uint8_t*)value,strlen(value)+1,blob+12,sizeof(blob)-12,&len);
    if(e==ESP_OK) {
        nvs_handle_t n;
        e=nvs_open(VAULT_NS,NVS_READWRITE,&n);
        if(e==ESP_OK) {
            e=nvs_set_blob(n,name,blob,12+len);
            if(e==ESP_OK) e=nvs_commit(n);
            nvs_close(n);
        }
    }
    xSemaphoreGive(lock);
    wipe(blob,sizeof(blob));
    return e;
}
bool device_security_has_secret(const char *name) {
    char value[MAX_SECRET+1]={0};
    bool present=device_security_get_secret(name,value,sizeof(value))==ESP_OK && value[0];
    wipe(value,sizeof(value));
    return present;
}
/* Quiesce hosted Wi-Fi before P4 software reset. Normal password changes
 * do not use this path. The C6 restart still needs board verification. */
static void quiesce_wifi(void) {
    esp_err_t e=esp_wifi_disconnect();
    ESP_LOGI(TAG,"Wi-Fi disconnect before restart: %s",esp_err_to_name(e));
    e=esp_wifi_stop();
    ESP_LOGI(TAG,"Wi-Fi stop before restart: %s",esp_err_to_name(e));
    vTaskDelay(pdMS_TO_TICKS(500));
    e=esp_wifi_deinit();
    ESP_LOGI(TAG,"Wi-Fi deinit before restart: %s",esp_err_to_name(e));
    vTaskDelay(pdMS_TO_TICKS(500));
}
static void restart_task(void *arg) {
    (void)arg;
    resetting=true;
    vTaskDelay(pdMS_TO_TICKS(1200));
    quiesce_wifi();
    esp_restart();
}
void device_security_schedule_restart(void) {
    if(xTaskCreatePinnedToCore(restart_task,"sec_reboot",2048,NULL,4,NULL,1)!=pdPASS)
        esp_restart();
}
static void factory_reset(void) {
    resetting=true;
    ESP_LOGW(TAG,"Physical factory reset requested");
    /* Stop link before erasing configuration. Clear co-processor saved Wi-Fi
     * settings; RF calibration and firmware remain on that processor. */
    (void)esp_wifi_disconnect();
    esp_err_t wifi=esp_wifi_restore();
    if(wifi!=ESP_OK) ESP_LOGW(TAG,"C6 restore not confirmed: %s",esp_err_to_name(wifi));
    quiesce_wifi();
    if(lock) xSemaphoreTake(lock,portMAX_DELAY);
    wipe(vault_key,sizeof(vault_key));
    esp_err_t e=nvs_flash_erase();
    if(e!=ESP_OK) { ESP_LOGE(TAG,"NVS erase failed: %s",esp_err_to_name(e)); return; }
    esp_restart();
}
static void reset_task(void *arg) {
    (void)arg;
    bool stable=true, sample=true;
    unsigned debounce=0, presses=0;
    int64_t first=0;
    for(;;) {
        bool level=gpio_get_level(RESET_GPIO)!=0;
        if(level!=sample) { sample=level; debounce=0; }
        else if(debounce<3) debounce++;
        if(debounce==3 && stable!=sample) {
            stable=sample;
            if(!stable) {
                int64_t now=esp_timer_get_time();
                if(!first || now-first>10000000) { first=now; presses=0; }
                if(++presses>=5) { factory_reset(); vTaskDelete(NULL); }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}
void device_security_start_reset_button(void) {
    gpio_config_t cfg={.pin_bit_mask=1ULL<<RESET_GPIO,.mode=GPIO_MODE_INPUT,.pull_up_en=GPIO_PULLUP_ENABLE,.pull_down_en=GPIO_PULLDOWN_DISABLE,.intr_type=GPIO_INTR_DISABLE};
    if(gpio_config(&cfg)==ESP_OK)
        (void)xTaskCreatePinnedToCore(reset_task,"factory_reset",4096,NULL,3,NULL,1);
}
