#ifndef LWC_MODULE_H
#define LWC_MODULE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define MAX_PINCODE_LEN 128
#define MIN_PINCODE_LEN 6

typedef int (*WriteCommand)(const void *ctx, const unsigned char *data, size_t length);
typedef int (*ReadReply)(const void *ctx, unsigned char *data, size_t *length);

typedef struct _LWCModule LWCModule;

typedef enum {
    LWCMError_Success = 0,
} LWCMError;

typedef struct {
    char json[256];
} GetAboutOutput;

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
} DeviceStatusOutput;

typedef struct {
    uint8_t old_pincode_length;
    unsigned char old_pincode[MAX_PINCODE_LEN];
    uint8_t pincode_length;
    unsigned char pincode[MAX_PINCODE_LEN];
} SetPincodeInput;

LWCMError management_get_about(LWCModule *module, GetAboutOutput *output);
LWCMError management_device_status(LWCModule *module, DeviceStatusOutput *output);
LWCMError management_set_pincode(LWCModule *module, SetPincodeInput *input);
LWCMError management_access_by_pincode(LWCModule *module, unsigned char *output);
LWCMError management_write_keypair(LWCModule *module, unsigned char *output);
LWCMError management_erase_keypair(LWCModule *module, unsigned char *output);
LWCMError management_write_secret(LWCModule *module, unsigned char *output);
LWCMError management_erase_secret(LWCModule *module, unsigned char *output);
LWCMError management_read_secret(LWCModule *module, unsigned char *output);
LWCMError management_get_id(LWCModule *module, unsigned char *output);
LWCMError management_reset_device(LWCModule *module, unsigned char *output);

LWCMError wallet_get_ed25519_pk(LWCModule *module, unsigned char *output);
LWCMError wallet_get_curve25519_pk(LWCModule *module, unsigned char *output);
LWCMError wallet_get_curve25519_sk(LWCModule *module, unsigned char *output);
LWCMError wallet_get_address(LWCModule *module, unsigned char *output);

LWCMError oraclize_data_signature(LWCModule *module, unsigned char *output);
LWCMError oraclize_data_verify(LWCModule *module, unsigned char *output);
LWCMError oraclize_transaction_signature(LWCModule *module, unsigned char *output);

LWCMError crypto_box_beforenm(LWCModule *module, unsigned char *output);
LWCMError crypto_curve25519_scalarmult(LWCModule *module, unsigned char *output);

#ifdef __cplusplus
}
#endif
#endif