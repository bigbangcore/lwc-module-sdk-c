#include <stdlib.h>
#include <stdio.h>
#include <libserialport.h>
#include "lwc_module.h"

struct sp_port *port;

int check(enum sp_return result)
{
    /* For this example we'll just exit on any error by calling abort(). */
    char *error_message;

    switch (result) {
        case SP_ERR_ARG:
            printf("Error: Invalid argument.\n");
            abort();
        case SP_ERR_FAIL:
            error_message = sp_last_error_message();
            printf("Error: Failed: %s\n", error_message);
            sp_free_error_message(error_message);
            abort();
        case SP_ERR_SUPP:
            printf("Error: Not supported.\n");
            abort();
        case SP_ERR_MEM:
            printf("Error: Couldn't allocate memory.\n");
            abort();
        case SP_OK:
        default:
            return result;
    }
}

int serial_open(const char *path)
{
    enum sp_return ret = sp_get_port_by_name(path, &port);
    if (SP_OK != ret) {
        return -1;
    }

    ret = sp_open(port, SP_MODE_READ_WRITE);
    if (SP_OK != ret) {
        return -2;
    }

    ret = sp_set_baudrate(port, 1200);
    if (SP_OK != ret) {
        return -3;
    }

    ret = sp_set_bits(port, 8);
    if (SP_OK != ret) {
        return -4;
    }

    ret = sp_set_parity(port, SP_PARITY_EVEN);
    if (SP_OK != ret) {
        return -5;
    }

    ret = sp_set_stopbits(port, 1);
    if (SP_OK != ret) {
        return -6;
    }

    ret = sp_set_flowcontrol(port, SP_FLOWCONTROL_NONE);
    if (SP_OK != ret) {
        return -7;
    }

    return 0;
}

static int serial_close() { return 0; }

static int write_func(const void *ctx, const unsigned char *data, size_t length) { return 0; }

static int read_func(const void *ctx, unsigned char *data, size_t *length) { return 0; }

int main(int argc, char **argv) { return EXIT_SUCCESS; }