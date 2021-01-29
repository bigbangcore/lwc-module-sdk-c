#ifndef LWC_MODULE_H
#define LWC_MODULE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define MAX_PINCODE_LEN 128
#define MIN_PINCODE_LEN 6
#define MAX_SECRET_LEN 1024

typedef int (*WriteFunction)(const void *ctx, const unsigned char *data, size_t length);
typedef int (*ReadFunction)(const void *ctx, unsigned char *data, size_t *length);

typedef struct _LWCModule LWCModule;

typedef enum {
    LWCMError_Success = 0,
} LWCMError;

typedef struct {
    char json[256];
} GetAbout;

typedef struct {
    int pincode_status;
    int retry_times;
    int solt0_status;
    int solt1_status;
    int solt2_status;
    int solt3_status;
    int solt4_status;
    int solt5_status;
    int solt6_status;
    int secret0_status;
    int secret1_status;
    int secret2_status;
    int secret3_status;
    int secret4_status;
    int secret5_status;
    int secret6_status;
} DeviceStatus;

typedef struct {
    uint32_t crc32;
    size_t length;
    unsigned char secret[MAX_SECRET_LEN];
} ReadSecret;

typedef struct {
    unsigned char head[2];
    unsigned char datetime[8];
    unsigned char hash[20];
    unsigned char foot[2];
} GetID;

typedef struct {
    unsigned char ed25519_public_key[32];
} GetED25519PK;

typedef struct {
    unsigned char curve25519_public_key[32];
} GetCurve25519PK;

typedef struct {
    unsigned char curve25519_secret_key[32];
} GetCurve25519SK;

typedef struct {
    char address[58];
} GetAddress;

typedef struct {
    unsigned char signature[64];
} DataSignature;

typedef struct {
    unsigned char signature[64];
} TransactionSignature;

typedef struct {
    unsigned char shared_key[32];
} BoxBeforenm;

typedef struct {
    unsigned char shared_key[32];
} Curve25519Scalarmult;

LWCMError module_new(void *context, const WriteFunction write_func, const ReadFunction read_func, LWCModule **module);
LWCMError module_delete(LWCModule *module);

LWCMError management_get_about(LWCModule *module, GetAbout *output);
LWCMError management_device_status(LWCModule *module, DeviceStatus *output);
LWCMError management_set_pincode(LWCModule *module, const uint8_t old_pincode_length, const unsigned char *old_pincode,
                                 const uint8_t pincode_length, const unsigned char *pincode);
LWCMError management_access_by_pincode(LWCModule *module, const uint8_t pincode_length, const unsigned char *pincode);
LWCMError management_write_keypair(LWCModule *module, const uint8_t solt, const unsigned char *public_key,
                                   const unsigned char *private_key);
LWCMError management_erase_keypair(LWCModule *module, const uint8_t solt, const uint8_t pincode_length,
                                   const unsigned char *pincode);
LWCMError management_write_secret(LWCModule *module, const uint8_t section, const uint32_t crc32, const size_t length,
                                  const unsigned char *secret);
LWCMError management_erase_secret(LWCModule *module, const uint8_t section, const uint8_t pincode_length,
                                  const unsigned char *pincode);
LWCMError management_read_secret(LWCModule *module, const uint8_t section, ReadSecret *output);
LWCMError management_get_id(LWCModule *module, GetID *output);
LWCMError management_reset_device(LWCModule *module, const uint8_t pincode_length, unsigned char *pincode);

LWCMError wallet_get_ed25519_pk(LWCModule *module, const uint8_t solt, GetED25519PK *output);
LWCMError wallet_get_curve25519_pk(LWCModule *module, const uint8_t solt, GetCurve25519PK *output);
LWCMError wallet_get_curve25519_sk(LWCModule *module, const uint8_t solt, GetCurve25519SK *output);
LWCMError wallet_get_address(LWCModule *module, const uint8_t solt, GetAddress *output);

LWCMError oraclize_data_signature(LWCModule *module, const uint8_t solt, const size_t length, const unsigned char *data,
                                  DataSignature *output);
LWCMError oraclize_data_verify(LWCModule *module, const uint8_t solt);
LWCMError oraclize_transaction_signature(LWCModule *module, const uint8_t solt, const size_t length,
                                         const unsigned char *data, TransactionSignature *output);

LWCMError crypto_box_beforenm(LWCModule *module, const uint8_t solt, const unsigned char public_key,
                              BoxBeforenm *output);
LWCMError crypto_curve25519_scalarmult(LWCModule *module, const uint8_t solt, Curve25519Scalarmult *output);

#ifdef __cplusplus
}
#endif
#endif