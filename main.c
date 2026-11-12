#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#define PRIVATE_KEY "keys/private.pem"
#define PUBLIC_KEY  "keys/public.pem"
#define VERSION_FILE "state/min_version.txt"

#define MAX_FIRMWARE (1024 * 1024)

typedef enum
{
    BOOT_IDLE,
    BOOT_VERIFY,
    BOOT_VERSION_CHECK,
    BOOT_AUTHORIZED,
    BOOT_DENIED
} BootState;

typedef struct
{
    uint32_t version;
    uint32_t size;
} FirmwareInfo;


/* Convert a 32-bit integer to bytes */

void write_u32(unsigned char *p, uint32_t value)
{
    p[0] = (value >> 24) & 0xFF;
    p[1] = (value >> 16) & 0xFF;
    p[2] = (value >> 8) & 0xFF;
    p[3] = value & 0xFF;
}


/* Convert bytes to a 32-bit integer */

uint32_t read_u32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}


/* Read a file */

int read_file(
    const char *filename,
    unsigned char **data,
    size_t *size
)
{
    FILE *file = fopen(filename, "rb");

    if (!file)
        return 0;

    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        return 0;
    }

    long length = ftell(file);

    if (length < 0 ||
        length > MAX_FIRMWARE + 1024)
    {
        fclose(file);
        return 0;
    }

    rewind(file);

    unsigned char *buffer = malloc(
        length > 0 ? (size_t)length : 1
    );

    if (!buffer)
    {
        fclose(file);
        return 0;
    }

    if (fread(buffer, 1, length, file) !=
        (size_t)length)
    {
        free(buffer);
        fclose(file);
        return 0;
    }

    fclose(file);

    *data = buffer;
    *size = length;

    return 1;
}


/* Write a file */

int write_file(
    const char *filename,
    const unsigned char *data,
    size_t size
)
{
    FILE *file = fopen(filename, "wb");

    if (!file)
        return 0;

    int success =
        fwrite(data, 1, size, file) == size;

    if (fclose(file) != 0)
        success = 0;

    return success;
}


/* Generate RSA-2048 key pair */

int generate_keys(void)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    FILE *file = NULL;

    int success = 0;

    ctx = EVP_PKEY_CTX_new_id(
        EVP_PKEY_RSA, NULL
    );

    if (!ctx)
        goto cleanup;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(
            ctx, 2048) <= 0)
        goto cleanup;

    if (EVP_PKEY_keygen(ctx, &key) <= 0)
        goto cleanup;

    file = fopen(PRIVATE_KEY, "wb");

    if (!file)
        goto cleanup;

    if (PEM_write_PrivateKey(
            file, key,
            NULL, NULL, 0, NULL, NULL
        ) != 1)
        goto cleanup;

    if (fclose(file) != 0)
    {
        file = NULL;
        goto cleanup;
    }

    file = NULL;

    file = fopen(PUBLIC_KEY, "wb");

    if (!file)
        goto cleanup;

    if (PEM_write_PUBKEY(file, key) != 1)
        goto cleanup;

    if (fclose(file) != 0)
    {
        file = NULL;
        goto cleanup;
    }

    file = NULL;

    success = 1;

cleanup:

    if (file)
        fclose(file);

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return success;
}


/* Create a digitally signed firmware package */

int sign_firmware(
    const char *input,
    uint32_t version,
    const char *output
)
{
    unsigned char *firmware = NULL;
    unsigned char *package = NULL;

    size_t firmware_size = 0;
    size_t signature_size = 0;

    FILE *file = NULL;

    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *key_ctx = NULL;

    int success = 0;

    if (!read_file(
            input,
            &firmware,
            &firmware_size
        ))
        goto cleanup;

    if (firmware_size > MAX_FIRMWARE)
        goto cleanup;

    file = fopen(PRIVATE_KEY, "rb");

    if (!file)
        goto cleanup;

    key = PEM_read_PrivateKey(
        file, NULL, NULL, NULL
    );

    fclose(file);
    file = NULL;

    if (!key)
        goto cleanup;

    size_t header_size = 16;

    package = malloc(
        header_size + firmware_size + 512
    );

    if (!package)
        goto cleanup;

    memcpy(package, "ECUDEMO1", 8);

    write_u32(package + 8, version);

    write_u32(
        package + 12,
        (uint32_t)firmware_size
    );

    memcpy(
        package + header_size,
        firmware,
        firmware_size
    );

    ctx = EVP_MD_CTX_new();

    if (!ctx)
        goto cleanup;

    if (EVP_DigestSignInit(
            ctx,
            &key_ctx,
            EVP_sha256(),
            NULL,
            key
        ) != 1)
        goto cleanup;

    if (EVP_PKEY_CTX_set_rsa_padding(
            key_ctx,
            RSA_PKCS1_PSS_PADDING
        ) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(
            key_ctx,
            RSA_PSS_SALTLEN_DIGEST
        ) <= 0)
        goto cleanup;

    if (EVP_DigestSignUpdate(
            ctx,
            package,
            header_size + firmware_size
        ) != 1)
        goto cleanup;

    if (EVP_DigestSignFinal(
            ctx, NULL, &signature_size
        ) != 1)
        goto cleanup;

    if (signature_size > 512)
        goto cleanup;

    if (EVP_DigestSignFinal(
            ctx,
            package + header_size + firmware_size,
            &signature_size
        ) != 1)
        goto cleanup;

    success = write_file(
        output,
        package,
        header_size + firmware_size + signature_size
    );

cleanup:

    free(firmware);
    free(package);

    if (file)
        fclose(file);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);

    return success;
}


/* Verify firmware digital signature */

int verify_firmware(
    const char *filename,
    FirmwareInfo *info
)
{
    unsigned char *package = NULL;

    size_t package_size = 0;

    FILE *file = NULL;

    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *key_ctx = NULL;

    int success = 0;

    if (!read_file(
            filename,
            &package,
            &package_size
        ))
        goto cleanup;

    if (package_size < 16 + 256)
        goto cleanup;

    if (memcmp(package, "ECUDEMO1", 8) != 0)
        goto cleanup;

    uint32_t version = read_u32(package + 8);
    uint32_t size = read_u32(package + 12);

    if (size > MAX_FIRMWARE ||
        size > package_size - 16)
        goto cleanup;

    size_t signature_size =
        package_size - 16 - size;

    file = fopen(PUBLIC_KEY, "rb");

    if (!file)
        goto cleanup;

    key = PEM_read_PUBKEY(
        file, NULL, NULL, NULL
    );

    fclose(file);
    file = NULL;

    if (!key)
        goto cleanup;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA ||
        EVP_PKEY_get_size(key) != 256 ||
        signature_size != 256)
        goto cleanup;

    ctx = EVP_MD_CTX_new();

    if (!ctx)
        goto cleanup;

    if (EVP_DigestVerifyInit(
            ctx,
            &key_ctx,
            EVP_sha256(),
            NULL,
            key
        ) != 1)
        goto cleanup;

    if (EVP_PKEY_CTX_set_rsa_padding(
            key_ctx,
            RSA_PKCS1_PSS_PADDING
        ) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(
            key_ctx,
            RSA_PSS_SALTLEN_DIGEST
        ) <= 0)
        goto cleanup;

    if (EVP_DigestVerifyUpdate(
            ctx,
            package,
            16 + size
        ) != 1)
        goto cleanup;

    if (EVP_DigestVerifyFinal(
            ctx,
            package + 16 + size,
            signature_size
        ) != 1)
        goto cleanup;

    if (info)
    {
        info->version = version;
        info->size = size;
    }

    success = 1;

cleanup:

    free(package);

    if (file)
        fclose(file);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);

    return success;
}


/* Read minimum permitted firmware version */

int read_min_version(uint32_t *version)
{
    FILE *file = fopen(VERSION_FILE, "r");

    if (!file)
        return 0;

    unsigned int value;

    int success = fscanf(file, "%u", &value) == 1;

    fclose(file);

    if (success)
        *version = value;

    return success;
}


/* Save minimum permitted firmware version */

int save_min_version(uint32_t version)
{
    FILE *file = fopen(
        "state/version.tmp", "w"
    );

    if (!file)
        return 0;

    int success = fprintf(
        file, "%u\n", version
    ) > 0;

    if (fclose(file) != 0)
        success = 0;

    if (!success)
        return 0;

    return rename(
        "state/version.tmp",
        VERSION_FILE
    ) == 0;
}


/* Secure boot state machine */

int secure_boot(const char *filename)
{
    BootState state = BOOT_IDLE;

    FirmwareInfo firmware = {0};

    uint32_t minimum_version = 0;

    printf("\n=================================\n");
    printf(" AUTOMOTIVE ECU SECURE BOOT\n");
    printf("=================================\n");

    state = BOOT_VERIFY;

    printf("\n[STATE] VERIFY FIRMWARE\n");

    if (!verify_firmware(
            filename, &firmware
        ))
    {
        printf("SECURITY ALERT: INVALID SIGNATURE\n");

        state = BOOT_DENIED;
    }

    else
    {
        printf("Firmware Authentication: PASSED\n");

        state = BOOT_VERSION_CHECK;
    }

    if (state == BOOT_VERSION_CHECK)
    {
        printf("\n[STATE] VERSION CHECK\n");

        if (!read_min_version(&minimum_version))
        {
            printf("ERROR: Security state unavailable\n");

            state = BOOT_DENIED;
        }

        else
        {
            printf(
                "Firmware Version: %u\n",
                firmware.version
            );

            printf(
                "Minimum Version: %u\n",
                minimum_version
            );

            if (firmware.version < minimum_version)
            {
                printf(
                    "SECURITY ALERT: ROLLBACK DETECTED\n"
                );

                state = BOOT_DENIED;
            }

            else
            {
                if (firmware.version > minimum_version)
                {
                    if (!save_min_version(
                            firmware.version
                        ))
                    {
                        printf("ERROR: State update failed\n");

                        state = BOOT_DENIED;
                    }

                    else
                    {
                        state = BOOT_AUTHORIZED;
                    }
                }

                else
                {
                    state = BOOT_AUTHORIZED;
                }
            }
        }
    }

    if (state == BOOT_AUTHORIZED)
    {
        printf("\n[STATE] BOOT AUTHORIZED\n");

        printf("Firmware accepted successfully!\n");

        return 1;
    }

    printf("\n[STATE] BOOT DENIED\n");

    printf("Firmware execution blocked!\n");

    return 0;
}


/* Main program */

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Commands:\n");
        printf("  init\n");
        printf("  sign <firmware> <version> <package>\n");
        printf("  verify <package>\n");
        printf("  boot <package>\n");

        return 1;
    }

    if (strcmp(argv[1], "init") == 0)
    {
        FILE *check = fopen(PUBLIC_KEY, "rb");

        if (check)
        {
            fclose(check);
            printf("Keys already exist. Initialization refused.\n");
            return 1;
        }

        check = fopen(VERSION_FILE, "rb");

        if (check)
        {
            fclose(check);
            printf("Security state already exists.\n");
            return 1;
        }

        if (!generate_keys())
        {
            printf("Key generation failed!\n");
            return 1;
        }

        if (!save_min_version(1))
        {
            printf("Initialization failed!\n");
            return 1;
        }

        printf("ECU initialized successfully!\n");

        return 0;
    }

    else if (strcmp(argv[1], "sign") == 0 &&
             argc == 5)
    {
        char *end = NULL;

        unsigned long version = strtoul(
            argv[3], &end, 10
        );

        if (!end || end == argv[3] || *end ||
            version > UINT32_MAX)
        {
            printf("Invalid firmware version.\n");
            return 1;
        }

        if (sign_firmware(
                argv[2],
                (uint32_t)version,
                argv[4]
            ))
        {
            printf("Firmware signed successfully!\n");
            return 0;
        }

        printf("Firmware signing failed!\n");
        return 1;
    }

    else if (strcmp(argv[1], "verify") == 0 &&
             argc == 3)
    {
        FirmwareInfo info = {0};

        if (verify_firmware(argv[2], &info))
        {
            printf("Signature Verification: PASSED\n");
            printf("Firmware Version: %u\n", info.version);
            return 0;
        }

        printf("Signature Verification: FAILED\n");
        return 1;
    }

    else if (strcmp(argv[1], "boot") == 0 &&
             argc == 3)
    {
        return secure_boot(argv[2]) ? 0 : 1;
    }

    printf("Invalid command.\n");

    return 1;
}