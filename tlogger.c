#include "tlogger.h"

static const char * TAG = "tlogger";

// ==== utilities ====
static const size_t tlogger_type2size[] = {
    sizeof(tlogger_device_ap_t),
    sizeof(tlogger_device_tfi_t),
    sizeof(tlogger_device_ble_t)
};

static const char * tlogger_type2dbpath[] = {
    SPIFFS_ROOT "/ap.db",
    SPIFFS_ROOT "/tfi.db",
    SPIFFS_ROOT "/ble.db"
};

// attempts to parse a file path. returns true on success or false on failure.
bool tlogger_log_path_parse(const char * fpath, uint32_t * epoch) {
    size_t fpath_len = strlen(fpath);

    if (strncmp(fpath + fpath_len - strlen(".log"), ".log", 4) == 0) { // if it ends in .log,

        const char * fpath_hex = fpath + fpath_len - strlen("xxxxxxxx.log");
        char * fpath_hex_end;

        //ESP_LOGI(TAG, "found hex logfile with name %s", fpath_hex);

        *epoch = strtoul(fpath_hex, &fpath_hex_end, 16);

        return fpath_hex_end != fpath_hex;
    }

    return false;
}

// prints a device info out to serial
void tlogger_esplog_device(tlogger_device_t * dev) {
    switch (dev->type) {
        case TLOGGER_TYPE_AP:
            ESP_LOGI(TAG, "AP \"%.*s\" (%hhu bytes)", dev->as_ap.ssid_len, 
                dev->as_ap.ssid, dev->as_ap.ssid_len);
            ESP_LOGI(TAG, "\tbssid: " SNIFFER_FMT_MAC_STR, 
                SNIFFER_FMT_MAC_DECOMP(dev->as_ap.bssid));
            break;
        case TLOGGER_TYPE_TFI:
            ESP_LOGI(TAG, "TRACERFI");
            ESP_LOGI(TAG, "\tmac: " SNIFFER_FMT_MAC_STR, 
                SNIFFER_FMT_MAC_DECOMP(dev->as_tfi.mac));
            break;
        case TLOGGER_TYPE_BLE:
            ESP_LOGI(TAG, "BLE");
            ESP_LOGI(TAG, "\tmac: " SNIFFER_FMT_MAC_STR, 
                SNIFFER_FMT_MAC_DECOMP(dev->as_ble.mac));
            ESP_LOGI(TAG, "\tis_mac_random: %hhu", dev->as_ble.is_mac_random);
            ESP_LOGI(TAG, "\tadv_payload_len: %hhu", dev->as_ble.adv_payload_len);
            break;
        default:
            ESP_LOGW(TAG, "UNKNOWN");
            break;
    }
}

// prints out a device and its recorded info
void tlogger_esplog_pair(tlogger_device_t * dev, tlogger_record_t * record) {
    tlogger_esplog_device(dev);
    ESP_LOGI(TAG, "\trssi: %hhi", record->rssi);
    ESP_LOGI(TAG, "\tchannel: %hhu", record->channel);
    ESP_LOGI(TAG, "\tid: %hu", record->id);
}

// returns a unique identifier for a given record, using its id, channel, and type fields
uint32_t tlogger_record_hash(tlogger_record_t * record) {
    uint32_t ret = 0;
    ret |= record->id;
    ret |= record->type << 16;
    ret |= record->channel << 20;
    return ret;
}

// ==== logfiles ====

// opens a tlogger file for writing at given epoch. do not use this for reading! it will delete the file.
FILE * tlogger_log_openw(uint32_t epoch) {

    char fpath[] = SPIFFS_ROOT"/xxxxxxxx.log";

    utoa(epoch, fpath + sizeof(SPIFFS_ROOT), 16); // parse filename as hex string

    fpath[strlen(SPIFFS_ROOT"/xxxxxxxx")] = '.'; // get the dot back

    ESP_LOGI(TAG, "opening file for writing at path %s", fpath);

    return fopen(fpath, "wb");
}

// opens a logfile for reading
FILE * tlogger_log_openr(tlogger_log_info_t * finfo) {
    ESP_LOGI(TAG, "opening file for reading at path %s", finfo->path);

    return fopen(finfo->path, "rb");
}

// closes a logfile.
void tlogger_log_close(FILE * logfile) {
    fclose(logfile);
}

// writes a record to a logfile.
void tlogger_log_write(FILE * logfile, tlogger_record_t * record) {
    if (!TLOGGER_IS_TYPE(record->type)) {
        ESP_LOGW(TAG, "cannot log invalid type!");
        return;
    }
    size_t bytes_wrote = fwrite(
        record, 
        1, sizeof(*record),
        logfile
    );

    ESP_LOGD(TAG, "wrote %u/%u bytes", bytes_wrote, 
        sizeof(*record));
}

// tries to get the next record and returns true. otherwise, returns false.
bool tlogger_log_read(FILE * logfile, tlogger_record_t * record) {
    size_t bytes_read;

    bytes_read = fread((void *)record, 1, sizeof(*record), logfile); // read the header contents to the record

    if (bytes_read != sizeof(*record)) {
        ESP_LOGI(TAG, "incomplete record (expected size %u, read %u)!",
            sizeof(*record), bytes_read);
        return false;
    }

    return true;
}

// ==== databases ====

// loads databases into a db object
void tlogger_db_load(tlogger_db_t * db) {
    for (size_t type = 0; type < TLOGGER_TYPE_MAX; type++) {
        if ((db->dev_files[type] = fopen(tlogger_type2dbpath[type], "ab+")) == NULL) {
            ESP_LOGE(TAG, "unable to open database at path %s", 
                tlogger_type2dbpath[type]);
        }
    }
}

// closes databases
void tlogger_db_close(tlogger_db_t * db) {
    for (size_t type = 0; type < TLOGGER_TYPE_MAX; type++) {
        fclose(db->dev_files[type]);
    }
}

// puts a device in a database, and stores the index in id. if it already exists, sets id to the device's index
void tlogger_db_put(tlogger_db_t * db, tlogger_device_t * dev, uint16_t * id) {
    __label__ exit_safe;

    if (!TLOGGER_IS_TYPE(dev->type)) {
        ESP_LOGE(TAG, "tried to search for invalid type!");
        return;
    }

    // qdev = query device
    void * qdev = (void *)dev + TLOGGER_DEVICE_HEAD_SIZE;
    size_t qdev_size = tlogger_type2size[dev->type];

    FILE * qdev_db = db->dev_files[dev->type];

    // cdev = candidate device
    void * cdev = malloc(qdev_size);

    rewind(qdev_db);
    *id = 0;

    while (fread(cdev, 1, qdev_size, qdev_db) == qdev_size) {
        if (memcmp(qdev, cdev, qdev_size) == 0) {
            ESP_LOGD(TAG, "found device at id %hu", *id);
            goto exit_safe;
        }
        (*id)++;
    }
    
    fseek(qdev_db, 0, SEEK_END);
    ESP_LOGD(TAG, "writing new device at id %hu", *id);
    if (fwrite(qdev, 1, qdev_size, qdev_db) != qdev_size) {
        ESP_LOGE(TAG, "could not write new device!");
        *id = 0;
    }

    exit_safe:

    free(cdev);
}

// ==== devices ====

// allocates a device given a type
tlogger_device_t * tlogger_device_create(tlogger_device_type_t type) {
    
    if (!TLOGGER_IS_TYPE(type)) {
        ESP_LOGE(TAG, "tried to create invalid type!");
        return NULL;
    }

    tlogger_device_t * dev = malloc(
        TLOGGER_DEVICE_HEAD_SIZE + tlogger_type2size[type]
    );
    
    dev->type = type;

    return dev;
}

void tlogger_device_free(tlogger_device_t * dev) {
    free((void *)dev);
}

// populates an ap device. bssid must be at least 6 bytes.
void tlogger_device_init_ap(tlogger_device_t * dev, uint8_t * bssid, uint8_t ssid_len, char * ssid) {
    
    if (dev->type != TLOGGER_TYPE_AP) {
        ESP_LOGE(TAG, "tried to populate invalid type with ap data!");
        return;
    }

    memcpy(dev->as_ap.bssid, bssid, 6);

    dev->as_ap.ssid_len = ssid_len;
    for (uint8_t i = 0; i < sizeof(dev->as_ap.ssid); i++) {
        dev->as_ap.ssid[i] = i < ssid_len ? (uint8_t)ssid[i] : 0;
    }
}

// populates a tracerfi device. mac must be 6 bytes.
void tlogger_device_init_tfi(tlogger_device_t * dev, uint8_t * mac) {
    
    if (dev->type != TLOGGER_TYPE_TFI) {
        ESP_LOGE(TAG, "tried to populate invalid type with ap data!");
        return;
    }

    memcpy(dev->as_tfi.mac, mac, 6);
}

// populates a ble device. mac must be 6 bytes, and the advertising payload will be 
// truncated to 31 bytes.
void tlogger_device_init_ble(tlogger_device_t * dev, 
    uint8_t * mac, bool is_mac_random, 
    uint8_t adv_payload_len, uint8_t * adv_payload) {
    
    if (dev->type != TLOGGER_TYPE_BLE) {
        ESP_LOGE(TAG, "tried to populate invalid type with ble data!");
        return;
    }
    ESP_LOGD(TAG, "copying mac...");

    if (is_mac_random) memset(dev->as_ble.mac, 0, 6);
    else memcpy(dev->as_ble.mac, mac, 6);

    ESP_LOGD(TAG, "copying mac random flag...");

    dev->as_ble.is_mac_random = is_mac_random;

    if (adv_payload_len > sizeof(dev->as_ble.adv_payload)) {
        ESP_LOGW(TAG, "truncated ble payload! (%hhu to %hhu bytes, mac="SNIFFER_FMT_MAC_STR")", 
            adv_payload_len, sizeof(dev->as_ble.adv_payload),
            SNIFFER_FMT_MAC_DECOMP(mac)
        );
        adv_payload_len = sizeof(dev->as_ble.adv_payload);
    }

    dev->as_ble.adv_payload_len = adv_payload_len;

    ESP_LOGD(TAG, "copying payload...");

    for (uint8_t i = 0; i < sizeof(dev->as_ble.adv_payload); i++) {
        dev->as_ble.adv_payload[i] = i < adv_payload_len ? adv_payload[i] : 0;
    }
}

// ==== directory iterators ====

// tries to get the next valid logfile path in the directory. returns true on success.
bool tlogger_dir_next(DIR * dir, tlogger_log_info_t * finfo) {
    
    static struct dirent * entry;
    static char fpath[] = SPIFFS_ROOT"/xxxxxxxx.log";
    struct stat fstat;
    
    while ((entry = readdir(dir)) != NULL) {
        if (tlogger_log_path_parse(entry->d_name, &finfo->epoch)) {
            // copy logfile name into string
            strncpy(&fpath[strlen(SPIFFS_ROOT"/")], 
                entry->d_name, strlen("xxxxxxxx.log"));

            stat(fpath, &fstat);

            finfo->path = fpath;
            finfo->size = fstat.st_size;

            return true;
        }
    }

    return false;
}
