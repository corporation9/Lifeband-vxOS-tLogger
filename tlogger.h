#ifndef _TLOGGER_H_
#define _TLOGGER_H_

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "dirent.h"
#include "sys/stat.h"

#include "esp_err.h"
#include "esp_log.h"

#include "global_cfg.h"
#include "sniffer.h"

// the size of the tlogger record head (type)
#define TLOGGER_DEVICE_HEAD_SIZE (1)

typedef enum {
    TLOGGER_TYPE_AP,
    TLOGGER_TYPE_TFI,
    TLOGGER_TYPE_BLE,
    TLOGGER_TYPE_MAX
} tlogger_device_type_t;

// Tlogger Access Point (AP) entry template
typedef struct {
    uint8_t bssid[6];
    uint8_t ssid_len;
    char ssid[32];
} tlogger_device_ap_t;

// Tlogger Tracer Device (TFI) entry template
typedef struct {
    uint8_t mac[6];
} tlogger_device_tfi_t;

// Tlogger Bluetoth Low Energy Device (BLE) entry template
typedef struct {
    uint8_t mac[6];
    uint8_t is_mac_random : 1;
    uint8_t adv_payload_len : 5;
    uint8_t resv : 2;
    uint8_t adv_payload[31];
} tlogger_device_ble_t;

typedef struct {
    uint8_t type;
    union {
        tlogger_device_ap_t as_ap;
        tlogger_device_tfi_t as_tfi;
        tlogger_device_ble_t as_ble;
    };
} tlogger_device_t;

typedef struct {
    int8_t rssi;
    uint8_t channel : 4;
    uint8_t type : 4;
    uint16_t id;
} tlogger_record_t;

typedef struct {
    int8_t rssi;
    uint8_t channel;
    tlogger_device_t * dev;
} tlogger_scanres_t;

// Tlogger log template
typedef struct {
    const char * path;
    uint32_t epoch;
    size_t size;
} tlogger_log_info_t;

// Tlogger Database 
typedef struct {
    FILE * dev_files[TLOGGER_TYPE_MAX];
} tlogger_db_t;


// ==== utilities ====

// checks if a type is a valid tlogger type
#define TLOGGER_IS_TYPE(type) ((type) >= 0 && (type) < TLOGGER_TYPE_MAX)

bool tlogger_log_path_parse(const char * fpath, uint32_t * epoch);

void tlogger_esplog_device(tlogger_device_t * dev);
void tlogger_esplog_pair(tlogger_device_t * dev, tlogger_record_t * record);

uint32_t tlogger_record_hash(tlogger_record_t * record);

// ==== logfiles ====
FILE * tlogger_log_openw(uint32_t epoch);
FILE * tlogger_log_openr(tlogger_log_info_t * finfo);
void tlogger_log_close(FILE * logfile);
void tlogger_log_write(FILE * logfile, tlogger_record_t * record);
bool tlogger_log_read(FILE * logfile, tlogger_record_t * record);

// ==== databases ====
void tlogger_db_load(tlogger_db_t * db);
void tlogger_db_close(tlogger_db_t * db);

void tlogger_db_put(tlogger_db_t * db, tlogger_device_t * dev, uint16_t * id);

// ==== devices ====
tlogger_device_t * tlogger_device_create(tlogger_device_type_t type);
void tlogger_device_free(tlogger_device_t * dev);

void tlogger_device_init_ap(tlogger_device_t * dev, 
    uint8_t * bssid, 
    uint8_t ssid_len, char * ssid);
void tlogger_device_init_tfi(tlogger_device_t * dev, uint8_t * mac);
void tlogger_device_init_ble(tlogger_device_t * dev, 
    uint8_t * mac, bool is_mac_random, 
    uint8_t adv_payload_len, uint8_t * adv_payload);

// ==== Directory Iterators====
bool tlogger_dir_next(DIR * dir, tlogger_log_info_t * finfo);

#endif
