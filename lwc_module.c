#include <stdlib.h>
#include <stdio.h>
#include "lwc_module.h"

struct _LWCModule {
    uint32_t index;
    void *context;
    WriteFunction write;
    ReadFunction read;
};

LWCMError module_new(void *context, const WriteFunction write_func, const ReadFunction read_func, LWCModule **module)
{
    return LWCMError_Success;
}

LWCMError module_delete(LWCModule *module) { return LWCMError_Success; }

LWCMError management_get_about(LWCModule *module, GetAbout *output) { return LWCMError_Success; }

LWCMError management_device_status(LWCModule *module, DeviceStatus *output) { return LWCMError_Success; }

LWCMError management_set_pincode(LWCModule *module, const uint8_t old_pincode_length, const unsigned char *old_pincode,
                                 const uint8_t pincode_length, const unsigned char *pincode)
{
    return LWCMError_Success;
}

LWCMError management_access_by_pincode(LWCModule *module, const uint8_t pincode_length, const unsigned char *pincode)
{
    return LWCMError_Success;
}

LWCMError management_write_keypair(LWCModule *module, const uint8_t solt, const unsigned char *public_key,
                                   const unsigned char *private_key)
{
    return LWCMError_Success;
}

LWCMError management_erase_keypair(LWCModule *module, const uint8_t solt, const uint8_t pincode_length,
                                   const unsigned char *pincode)
{
    return LWCMError_Success;
}

LWCMError management_write_secret(LWCModule *module, const uint8_t section, const uint32_t crc32, const size_t length,
                                  const unsigned char *secret)
{
    return LWCMError_Success;
}

LWCMError management_erase_secret(LWCModule *module, const uint8_t section, const uint8_t pincode_length,
                                  const unsigned char *pincode)
{
    return LWCMError_Success;
}

LWCMError management_read_secret(LWCModule *module, const uint8_t section, ReadSecret *output)
{
    return LWCMError_Success;
}

LWCMError management_get_id(LWCModule *module, GetID *output) { return LWCMError_Success; }

LWCMError management_reset_device(LWCModule *module, const uint8_t pincode_length, unsigned char *pincode)
{
    return LWCMError_Success;
}

LWCMError wallet_get_ed25519_pk(LWCModule *module, const uint8_t solt, GetED25519PK *output)
{
    return LWCMError_Success;
}

LWCMError wallet_get_curve25519_pk(LWCModule *module, const uint8_t solt, GetCurve25519PK *output)
{
    return LWCMError_Success;
}

LWCMError wallet_get_curve25519_sk(LWCModule *module, const uint8_t solt, GetCurve25519SK *output)
{
    return LWCMError_Success;
}

LWCMError wallet_get_address(LWCModule *module, const uint8_t solt, GetAddress *output) { return LWCMError_Success; }

LWCMError oraclize_data_signature(LWCModule *module, const uint8_t solt, const size_t length, const unsigned char *data,
                                  DataSignature *output)
{
    return LWCMError_Success;
}

LWCMError oraclize_data_verify(LWCModule *module, const uint8_t solt) { return LWCMError_Success; }

LWCMError oraclize_transaction_signature(LWCModule *module, const uint8_t solt, const size_t length,
                                         const unsigned char *data, TransactionSignature *output)
{
    return LWCMError_Success;
}

LWCMError crypto_box_beforenm(LWCModule *module, const uint8_t solt, const unsigned char public_key,
                              BoxBeforenm *output)
{
    return LWCMError_Success;
}

LWCMError crypto_curve25519_scalarmult(LWCModule *module, const uint8_t solt, Curve25519Scalarmult *output)
{
    return LWCMError_Success;
}