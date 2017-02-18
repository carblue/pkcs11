/* Copyright (c) OASIS Open 2016. All Rights Reserved./
 * Copyright (C) 2017  for the binding: Carsten Blüggel <carblue@geekmail.de>
 * /Distributed under the terms of the OASIS IPR Policy,
 * [http://www.oasis-open.org/policies-guidelines/ipr], AS-IS, WITHOUT ANY
 * IMPLIED OR EXPRESS WARRANTY; there is no warranty of MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE or NONINFRINGEMENT of the rights of others.
 */

/* Latest version of the specification:
 * http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html
 */

/* See top of pkcs11.h for information about the macros that
 * must be defined and the structure-packing conventions that
 * must be set before including this file.
 */

/*
Written in the D programming language.
For git maintenance (ensure at least one congruent line with originating C header):
#define _PKCS11T_H_ 1
*/

module pkcs11.pkcs11t;

import core.stdc.config; // : c_ulong, c_long;
import pkcs11.pkcs11f;

extern(C) nothrow @nogc @system :


enum CRYPTOKI_VERSION_MAJOR          = 2;
enum CRYPTOKI_VERSION_MINOR          = 40;
enum CRYPTOKI_VERSION_AMENDMENT      = 0;

enum ubyte CK_TRUE         = 1;
enum ubyte CK_FALSE        = 0;
enum void* NULL_PTR        = null;

/* an unsigned 8-bit value */
alias ubyte             CK_BYTE;

/* an unsigned 8-bit character */
alias CK_BYTE           CK_CHAR;

/* an 8-bit UTF-8 character */
alias CK_BYTE           CK_UTF8CHAR;

/* a BYTE-sized Boolean flag */
alias CK_BYTE           CK_BBOOL;

/* an unsigned value, at least 32 bits long */
alias c_ulong           CK_ULONG;

/* a signed value, the same size as a CK_ULONG */
alias c_long            CK_LONG;

/* at least 32 bits; each bit is a Boolean flag */
alias CK_ULONG          CK_FLAGS;


/* some special values for certain CK_ULONG variables */
enum CK_UNAVAILABLE_INFORMATION      = (~0UL);
enum CK_EFFECTIVELY_INFINITE         = 0UL;


alias CK_BYTE     *   CK_BYTE_PTR;
alias CK_CHAR     *   CK_CHAR_PTR;
alias CK_UTF8CHAR *   CK_UTF8CHAR_PTR;
alias CK_ULONG    *   CK_ULONG_PTR;
alias void        *   CK_VOID_PTR;

/* Pointer to a CK_VOID_PTR-- i.e., pointer to pointer to void */
alias CK_VOID_PTR *   CK_VOID_PTR_PTR;


/* The following value is always invalid if used as a session
 * handle or object handle
 */
enum CK_INVALID_HANDLE       = 0UL;


struct CK_VERSION {
  CK_BYTE       major;  /* integer portion of version number */
  CK_BYTE       minor;  /* 1/100ths portion of version number */
}

alias CK_VERSION * CK_VERSION_PTR;


struct CK_INFO {
  CK_VERSION       cryptokiVersion;     /* Cryptoki interface ver */
  CK_UTF8CHAR[32]  manufacturerID;      /* blank padded */
  CK_FLAGS         flags;               /* must be zero */
  CK_UTF8CHAR[32]  libraryDescription;  /* blank padded */
  CK_VERSION       libraryVersion;      /* version of library */
}

alias CK_INFO *    CK_INFO_PTR;


/* CK_NOTIFICATION enumerates the types of notifications that
 * Cryptoki provides to an application
 */
alias CK_ULONG CK_NOTIFICATION;
enum CKN_SURRENDER           = 0UL;
enum CKN_OTP_CHANGED         = 1UL;

alias CK_ULONG          CK_SLOT_ID;

alias CK_SLOT_ID * CK_SLOT_ID_PTR;


/* CK_SLOT_INFO provides information about a slot */
struct CK_SLOT_INFO {
  CK_UTF8CHAR[64]   slotDescription;  /* blank padded */
  CK_UTF8CHAR[32]   manufacturerID;   /* blank padded */
  CK_FLAGS          flags;

  CK_VERSION        hardwareVersion;  /* version of hardware */
  CK_VERSION        firmwareVersion;  /* version of firmware */
}

/* flags: bit flags that provide capabilities of the slot
 *      Bit Flag              Mask        Meaning
 */
enum CKF_TOKEN_PRESENT     = 0x00000001UL;  /* a token is there */
enum CKF_REMOVABLE_DEVICE  = 0x00000002UL;  /* removable devices*/
enum CKF_HW_SLOT           = 0x00000004UL;  /* hardware slot */

alias CK_SLOT_INFO * CK_SLOT_INFO_PTR;


/* CK_TOKEN_INFO provides information about a token */
struct CK_TOKEN_INFO {
  CK_UTF8CHAR[32]  label;              /* blank padded */
  CK_UTF8CHAR[32]  manufacturerID;     /* blank padded */
  CK_UTF8CHAR[16]  model;              /* blank padded */
  CK_CHAR[16]      serialNumber;       /* blank padded */
  CK_FLAGS         flags;              /* see below */

  CK_ULONG      ulMaxSessionCount;     /* max open sessions */
  CK_ULONG      ulSessionCount;        /* sess. now open */
  CK_ULONG      ulMaxRwSessionCount;   /* max R/W sessions */
  CK_ULONG      ulRwSessionCount;      /* R/W sess. now open */
  CK_ULONG      ulMaxPinLen;           /* in bytes */
  CK_ULONG      ulMinPinLen;           /* in bytes */
  CK_ULONG      ulTotalPublicMemory;   /* in bytes */
  CK_ULONG      ulFreePublicMemory;    /* in bytes */
  CK_ULONG      ulTotalPrivateMemory;  /* in bytes */
  CK_ULONG      ulFreePrivateMemory;   /* in bytes */
  CK_VERSION    hardwareVersion;       /* version of hardware */
  CK_VERSION    firmwareVersion;       /* version of firmware */
  CK_CHAR[16]   utcTime;           /* time */
}

/* The flags parameter is defined as follows:
 *      Bit Flag                    Mask        Meaning
 */
enum CKF_RNG                     = 0x00000001UL;  /* has random # generator */
enum CKF_WRITE_PROTECTED         = 0x00000002UL;  /* token is write-protected */
enum CKF_LOGIN_REQUIRED          = 0x00000004UL;  /* user must login */
enum CKF_USER_PIN_INITIALIZED    = 0x00000008UL;  /* normal user's PIN is set */

/* CKF_RESTORE_KEY_NOT_NEEDED.  If it is set,
 * that means that *every* time the state of cryptographic
 * operations of a session is successfully saved, all keys
 * needed to continue those operations are stored in the state
 */
enum CKF_RESTORE_KEY_NOT_NEEDED  = 0x00000020UL;

/* CKF_CLOCK_ON_TOKEN.  If it is set, that means
 * that the token has some sort of clock.  The time on that
 * clock is returned in the token info structure
 */
enum CKF_CLOCK_ON_TOKEN          = 0x00000040UL;

/* CKF_PROTECTED_AUTHENTICATION_PATH.  If it is
 * set, that means that there is some way for the user to login
 * without sending a PIN through the Cryptoki library itself
 */
enum CKF_PROTECTED_AUTHENTICATION_PATH = 0x00000100UL;

/* CKF_DUAL_CRYPTO_OPERATIONS.  If it is true,
 * that means that a single session with the token can perform
 * dual simultaneous cryptographic operations (digest and
 * encrypt; decrypt and digest; sign and encrypt; and decrypt
 * and sign)
 */
enum CKF_DUAL_CRYPTO_OPERATIONS  = 0x00000200UL;

/* CKF_TOKEN_INITIALIZED. If it is true, the
 * token has been initialized using C_InitializeToken or an
 * equivalent mechanism outside the scope of PKCS #11.
 * Calling C_InitializeToken when this flag is set will cause
 * the token to be reinitialized.
 */
enum CKF_TOKEN_INITIALIZED       = 0x00000400UL;

/* CKF_SECONDARY_AUTHENTICATION. If it is
 * true, the token supports secondary authentication for
 * private key objects.
 */
enum CKF_SECONDARY_AUTHENTICATION  = 0x00000800UL;

/* CKF_USER_PIN_COUNT_LOW. If it is true, an
 * incorrect user login PIN has been entered at least once
 * since the last successful authentication.
 */
enum CKF_USER_PIN_COUNT_LOW       = 0x00010000UL;

/* CKF_USER_PIN_FINAL_TRY. If it is true,
 * supplying an incorrect user PIN will it to become locked.
 */
enum CKF_USER_PIN_FINAL_TRY       = 0x00020000UL;

/* CKF_USER_PIN_LOCKED. If it is true, the
 * user PIN has been locked. User login to the token is not
 * possible.
 */
enum CKF_USER_PIN_LOCKED          = 0x00040000UL;

/* CKF_USER_PIN_TO_BE_CHANGED. If it is true,
 * the user PIN value is the default value set by token
 * initialization or manufacturing, or the PIN has been
 * expired by the card.
 */
enum CKF_USER_PIN_TO_BE_CHANGED   = 0x00080000UL;

/* CKF_SO_PIN_COUNT_LOW. If it is true, an
 * incorrect SO login PIN has been entered at least once since
 * the last successful authentication.
 */
enum CKF_SO_PIN_COUNT_LOW         = 0x00100000UL;

/* CKF_SO_PIN_FINAL_TRY. If it is true,
 * supplying an incorrect SO PIN will it to become locked.
 */
enum CKF_SO_PIN_FINAL_TRY         = 0x00200000UL;

/* CKF_SO_PIN_LOCKED. If it is true, the SO
 * PIN has been locked. SO login to the token is not possible.
 */
enum CKF_SO_PIN_LOCKED            = 0x00400000UL;

/* CKF_SO_PIN_TO_BE_CHANGED. If it is true,
 * the SO PIN value is the default value set by token
 * initialization or manufacturing, or the PIN has been
 * expired by the card.
 */
enum CKF_SO_PIN_TO_BE_CHANGED     = 0x00800000UL;

enum CKF_ERROR_STATE              = 0x01000000UL;

alias CK_TOKEN_INFO * CK_TOKEN_INFO_PTR;


/* CK_SESSION_HANDLE is a Cryptoki-assigned value that
 * identifies a session
 */
alias CK_ULONG          CK_SESSION_HANDLE;

alias CK_SESSION_HANDLE * CK_SESSION_HANDLE_PTR;


/* CK_USER_TYPE enumerates the types of Cryptoki users */
alias CK_ULONG          CK_USER_TYPE;
/* Security Officer */
enum CKU_SO                  = 0UL;
/* Normal user */
enum CKU_USER                = 1UL;
/* Context specific */
enum CKU_CONTEXT_SPECIFIC    = 2UL;

/* CK_STATE enumerates the session states */
alias CK_ULONG          CK_STATE;
enum CKS_RO_PUBLIC_SESSION   = 0UL;
enum CKS_RO_USER_FUNCTIONS   = 1UL;
enum CKS_RW_PUBLIC_SESSION   = 2UL;
enum CKS_RW_USER_FUNCTIONS   = 3UL;
enum CKS_RW_SO_FUNCTIONS     = 4UL;

/* CK_SESSION_INFO provides information about a session */
struct CK_SESSION_INFO {
  CK_SLOT_ID    slotID;
  CK_STATE      state;
  CK_FLAGS      flags;          /* see below */
  CK_ULONG      ulDeviceError;  /* device-dependent error code */
}

/* The flags are defined in the following table:
 *      Bit Flag                Mask        Meaning
 */
enum CKF_RW_SESSION          = 0x00000002UL; /* session is r/w */
enum CKF_SERIAL_SESSION      = 0x00000004UL; /* no parallel    */

alias CK_SESSION_INFO * CK_SESSION_INFO_PTR;


/* CK_OBJECT_HANDLE is a token-specific identifier for an
 * object
 */
alias CK_ULONG          CK_OBJECT_HANDLE;

alias CK_OBJECT_HANDLE * CK_OBJECT_HANDLE_PTR;


/* CK_OBJECT_CLASS is a value that identifies the classes (or
 * types) of objects that Cryptoki recognizes.  It is defined
 * as follows:
 */
alias CK_ULONG          CK_OBJECT_CLASS;

/* The following classes of objects are defined: */
enum CKO_DATA              = 0x00000000UL;
enum CKO_CERTIFICATE       = 0x00000001UL;
enum CKO_PUBLIC_KEY        = 0x00000002UL;
enum CKO_PRIVATE_KEY       = 0x00000003UL;
enum CKO_SECRET_KEY        = 0x00000004UL;
enum CKO_HW_FEATURE        = 0x00000005UL;
enum CKO_DOMAIN_PARAMETERS = 0x00000006UL;
enum CKO_MECHANISM         = 0x00000007UL;
enum CKO_OTP_KEY           = 0x00000008UL;

enum CKO_VENDOR_DEFINED    = 0x80000000UL;

alias CK_OBJECT_CLASS * CK_OBJECT_CLASS_PTR;

/* CK_HW_FEATURE_TYPE is a value that identifies the hardware feature type
 * of an object with CK_OBJECT_CLASS equal to CKO_HW_FEATURE.
 */
alias CK_ULONG          CK_HW_FEATURE_TYPE;

/* The following hardware feature types are defined */
enum CKH_MONOTONIC_COUNTER  = 0x00000001UL;
enum CKH_CLOCK              = 0x00000002UL;
enum CKH_USER_INTERFACE     = 0x00000003UL;
enum CKH_VENDOR_DEFINED     = 0x80000000UL;

/* CK_KEY_TYPE is a value that identifies a key type */
alias CK_ULONG          CK_KEY_TYPE;

/* the following key types are defined: */
enum CKK_RSA                 = 0x00000000UL;
enum CKK_DSA                 = 0x00000001UL;
enum CKK_DH                  = 0x00000002UL;
enum CKK_ECDSA               = 0x00000003UL; /* Deprecated */
enum CKK_EC                  = 0x00000003UL;
enum CKK_X9_42_DH            = 0x00000004UL;
enum CKK_KEA                 = 0x00000005UL;
enum CKK_GENERIC_SECRET      = 0x00000010UL;
enum CKK_RC2                 = 0x00000011UL;
enum CKK_RC4                 = 0x00000012UL;
enum CKK_DES                 = 0x00000013UL;
enum CKK_DES2                = 0x00000014UL;
enum CKK_DES3                = 0x00000015UL;
enum CKK_CAST                = 0x00000016UL;
enum CKK_CAST3               = 0x00000017UL;
enum CKK_CAST5               = 0x00000018UL; /* Deprecated */
enum CKK_CAST128             = 0x00000018UL;
enum CKK_RC5                 = 0x00000019UL;
enum CKK_IDEA                = 0x0000001AUL;
enum CKK_SKIPJACK            = 0x0000001BUL;
enum CKK_BATON               = 0x0000001CUL;
enum CKK_JUNIPER             = 0x0000001DUL;
enum CKK_CDMF                = 0x0000001EUL;
enum CKK_AES                 = 0x0000001FUL;
enum CKK_BLOWFISH            = 0x00000020UL;
enum CKK_TWOFISH             = 0x00000021UL;
enum CKK_SECURID             = 0x00000022UL;
enum CKK_HOTP                = 0x00000023UL;
enum CKK_ACTI                = 0x00000024UL;
enum CKK_CAMELLIA            = 0x00000025UL;
enum CKK_ARIA                = 0x00000026UL;

enum CKK_MD5_HMAC            = 0x00000027UL;
enum CKK_SHA_1_HMAC          = 0x00000028UL;
enum CKK_RIPEMD128_HMAC      = 0x00000029UL;
enum CKK_RIPEMD160_HMAC      = 0x0000002AUL;
enum CKK_SHA256_HMAC         = 0x0000002BUL;
enum CKK_SHA384_HMAC         = 0x0000002CUL;
enum CKK_SHA512_HMAC         = 0x0000002DUL;
enum CKK_SHA224_HMAC         = 0x0000002EUL;

enum CKK_SEED                = 0x0000002FUL;
enum CKK_GOSTR3410           = 0x00000030UL;
enum CKK_GOSTR3411           = 0x00000031UL;
enum CKK_GOST28147           = 0x00000032UL;



enum CKK_VENDOR_DEFINED      = 0x80000000UL;


/* CK_CERTIFICATE_TYPE is a value that identifies a certificate
 * type
 */
alias CK_ULONG          CK_CERTIFICATE_TYPE;

enum CK_CERTIFICATE_CATEGORY_UNSPECIFIED     = 0UL;
enum CK_CERTIFICATE_CATEGORY_TOKEN_USER      = 1UL;
enum CK_CERTIFICATE_CATEGORY_AUTHORITY       = 2UL;
enum CK_CERTIFICATE_CATEGORY_OTHER_ENTITY    = 3UL;

enum CK_SECURITY_DOMAIN_UNSPECIFIED     = 0UL;
enum CK_SECURITY_DOMAIN_MANUFACTURER    = 1UL;
enum CK_SECURITY_DOMAIN_OPERATOR        = 2UL;
enum CK_SECURITY_DOMAIN_THIRD_PARTY     = 3UL;


/* The following certificate types are defined: */
enum CKC_X_509               = 0x00000000UL;
enum CKC_X_509_ATTR_CERT     = 0x00000001UL;
enum CKC_WTLS                = 0x00000002UL;
enum CKC_VENDOR_DEFINED      = 0x80000000UL;


/* CK_ATTRIBUTE_TYPE is a value that identifies an attribute
 * type
 */
alias CK_ULONG          CK_ATTRIBUTE_TYPE;

/* The CKF_ARRAY_ATTRIBUTE flag identifies an attribute which
 * consists of an array of values.
 */
enum CKF_ARRAY_ATTRIBUTE     = 0x40000000UL;

/* The following OTP-related defines relate to the CKA_OTP_FORMAT attribute */
enum CK_OTP_FORMAT_DECIMAL           = 0UL;
enum CK_OTP_FORMAT_HEXADECIMAL       = 1UL;
enum CK_OTP_FORMAT_ALPHANUMERIC      = 2UL;
enum CK_OTP_FORMAT_BINARY            = 3UL;

/* The following OTP-related defines relate to the CKA_OTP_..._REQUIREMENT
 * attributes
 */
enum CK_OTP_PARAM_IGNORED            = 0UL;
enum CK_OTP_PARAM_OPTIONAL           = 1UL;
enum CK_OTP_PARAM_MANDATORY          = 2UL;

/* The following attribute types are defined: */
enum CKA_CLASS              = 0x00000000UL;
enum CKA_TOKEN              = 0x00000001UL;
enum CKA_PRIVATE            = 0x00000002UL;
enum CKA_LABEL              = 0x00000003UL;
enum CKA_APPLICATION        = 0x00000010UL;
enum CKA_VALUE              = 0x00000011UL;
enum CKA_OBJECT_ID          = 0x00000012UL;
enum CKA_CERTIFICATE_TYPE   = 0x00000080UL;
enum CKA_ISSUER             = 0x00000081UL;
enum CKA_SERIAL_NUMBER      = 0x00000082UL;
enum CKA_AC_ISSUER          = 0x00000083UL;
enum CKA_OWNER              = 0x00000084UL;
enum CKA_ATTR_TYPES         = 0x00000085UL;
enum CKA_TRUSTED            = 0x00000086UL;
enum CKA_CERTIFICATE_CATEGORY        = 0x00000087UL;
enum CKA_JAVA_MIDP_SECURITY_DOMAIN   = 0x00000088UL;
enum CKA_URL                         = 0x00000089UL;
enum CKA_HASH_OF_SUBJECT_PUBLIC_KEY  = 0x0000008AUL;
enum CKA_HASH_OF_ISSUER_PUBLIC_KEY   = 0x0000008BUL;
enum CKA_NAME_HASH_ALGORITHM         = 0x0000008CUL;
enum CKA_CHECK_VALUE                 = 0x00000090UL;

enum CKA_KEY_TYPE           = 0x00000100UL;
enum CKA_SUBJECT            = 0x00000101UL;
enum CKA_ID                 = 0x00000102UL;
enum CKA_SENSITIVE          = 0x00000103UL;
enum CKA_ENCRYPT            = 0x00000104UL;
enum CKA_DECRYPT            = 0x00000105UL;
enum CKA_WRAP               = 0x00000106UL;
enum CKA_UNWRAP             = 0x00000107UL;
enum CKA_SIGN               = 0x00000108UL;
enum CKA_SIGN_RECOVER       = 0x00000109UL;
enum CKA_VERIFY             = 0x0000010AUL;
enum CKA_VERIFY_RECOVER     = 0x0000010BUL;
enum CKA_DERIVE             = 0x0000010CUL;
enum CKA_START_DATE         = 0x00000110UL;
enum CKA_END_DATE           = 0x00000111UL;
enum CKA_MODULUS            = 0x00000120UL;
enum CKA_MODULUS_BITS       = 0x00000121UL;
enum CKA_PUBLIC_EXPONENT    = 0x00000122UL;
enum CKA_PRIVATE_EXPONENT   = 0x00000123UL;
enum CKA_PRIME_1            = 0x00000124UL;
enum CKA_PRIME_2            = 0x00000125UL;
enum CKA_EXPONENT_1         = 0x00000126UL;
enum CKA_EXPONENT_2         = 0x00000127UL;
enum CKA_COEFFICIENT        = 0x00000128UL;
enum CKA_PUBLIC_KEY_INFO    = 0x00000129UL;
enum CKA_PRIME              = 0x00000130UL;
enum CKA_SUBPRIME           = 0x00000131UL;
enum CKA_BASE               = 0x00000132UL;

enum CKA_PRIME_BITS         = 0x00000133UL;
enum CKA_SUBPRIME_BITS      = 0x00000134UL;
enum CKA_SUB_PRIME_BITS     = CKA_SUBPRIME_BITS;

enum CKA_VALUE_BITS         = 0x00000160UL;
enum CKA_VALUE_LEN          = 0x00000161UL;
enum CKA_EXTRACTABLE        = 0x00000162UL;
enum CKA_LOCAL              = 0x00000163UL;
enum CKA_NEVER_EXTRACTABLE  = 0x00000164UL;
enum CKA_ALWAYS_SENSITIVE   = 0x00000165UL;
enum CKA_KEY_GEN_MECHANISM  = 0x00000166UL;

enum CKA_MODIFIABLE         = 0x00000170UL;
enum CKA_COPYABLE           = 0x00000171UL;

enum CKA_DESTROYABLE        = 0x00000172UL;

enum CKA_ECDSA_PARAMS       = 0x00000180UL; /* Deprecated */
enum CKA_EC_PARAMS          = 0x00000180UL;

enum CKA_EC_POINT           = 0x00000181UL;

enum CKA_SECONDARY_AUTH     = 0x00000200UL; /* Deprecated */
enum CKA_AUTH_PIN_FLAGS     = 0x00000201UL; /* Deprecated */

enum CKA_ALWAYS_AUTHENTICATE  = 0x00000202UL;

enum CKA_WRAP_WITH_TRUSTED    = 0x00000210UL;
enum CKA_WRAP_TEMPLATE        = (CKF_ARRAY_ATTRIBUTE|0x00000211UL);
enum CKA_UNWRAP_TEMPLATE      = (CKF_ARRAY_ATTRIBUTE|0x00000212UL);
enum CKA_DERIVE_TEMPLATE      = (CKF_ARRAY_ATTRIBUTE|0x00000213UL);

enum CKA_OTP_FORMAT                = 0x00000220UL;
enum CKA_OTP_LENGTH                = 0x00000221UL;
enum CKA_OTP_TIME_INTERVAL         = 0x00000222UL;
enum CKA_OTP_USER_FRIENDLY_MODE    = 0x00000223UL;
enum CKA_OTP_CHALLENGE_REQUIREMENT = 0x00000224UL;
enum CKA_OTP_TIME_REQUIREMENT      = 0x00000225UL;
enum CKA_OTP_COUNTER_REQUIREMENT   = 0x00000226UL;
enum CKA_OTP_PIN_REQUIREMENT       = 0x00000227UL;
enum CKA_OTP_COUNTER               = 0x0000022EUL;
enum CKA_OTP_TIME                  = 0x0000022FUL;
enum CKA_OTP_USER_IDENTIFIER       = 0x0000022AUL;
enum CKA_OTP_SERVICE_IDENTIFIER    = 0x0000022BUL;
enum CKA_OTP_SERVICE_LOGO          = 0x0000022CUL;
enum CKA_OTP_SERVICE_LOGO_TYPE     = 0x0000022DUL;

enum CKA_GOSTR3410_PARAMS            = 0x00000250UL;
enum CKA_GOSTR3411_PARAMS            = 0x00000251UL;
enum CKA_GOST28147_PARAMS            = 0x00000252UL;

enum CKA_HW_FEATURE_TYPE             = 0x00000300UL;
enum CKA_RESET_ON_INIT               = 0x00000301UL;
enum CKA_HAS_RESET                   = 0x00000302UL;

enum CKA_PIXEL_X                     = 0x00000400UL;
enum CKA_PIXEL_Y                     = 0x00000401UL;
enum CKA_RESOLUTION                  = 0x00000402UL;
enum CKA_CHAR_ROWS                   = 0x00000403UL;
enum CKA_CHAR_COLUMNS                = 0x00000404UL;
enum CKA_COLOR                       = 0x00000405UL;
enum CKA_BITS_PER_PIXEL              = 0x00000406UL;
enum CKA_CHAR_SETS                   = 0x00000480UL;
enum CKA_ENCODING_METHODS            = 0x00000481UL;
enum CKA_MIME_TYPES                  = 0x00000482UL;
enum CKA_MECHANISM_TYPE              = 0x00000500UL;
enum CKA_REQUIRED_CMS_ATTRIBUTES     = 0x00000501UL;
enum CKA_DEFAULT_CMS_ATTRIBUTES      = 0x00000502UL;
enum CKA_SUPPORTED_CMS_ATTRIBUTES    = 0x00000503UL;
enum CKA_ALLOWED_MECHANISMS          = (CKF_ARRAY_ATTRIBUTE|0x00000600UL);

enum CKA_VENDOR_DEFINED              = 0x80000000UL;

/* CK_ATTRIBUTE is a structure that includes the type, length
 * and value of an attribute
 */
struct CK_ATTRIBUTE {
  CK_ATTRIBUTE_TYPE type;
  CK_VOID_PTR       pValue;
  CK_ULONG          ulValueLen;  /* in bytes */
}

alias CK_ATTRIBUTE * CK_ATTRIBUTE_PTR;

/* CK_DATE is a structure that defines a date */
struct CK_DATE{
  CK_CHAR[4]       year;   /* the year ("1900" - "9999") */
  CK_CHAR[2]       month;  /* the month ("01" - "12") */
  CK_CHAR[2]       day;    /* the day   ("01" - "31") */
}


/* CK_MECHANISM_TYPE is a value that identifies a mechanism
 * type
 */
alias CK_ULONG          CK_MECHANISM_TYPE;

/* the following mechanism types are defined: */
enum CKM_RSA_PKCS_KEY_PAIR_GEN      = 0x00000000UL;
enum CKM_RSA_PKCS                   = 0x00000001UL;
enum CKM_RSA_9796                   = 0x00000002UL;
enum CKM_RSA_X_509                  = 0x00000003UL;

enum CKM_MD2_RSA_PKCS               = 0x00000004UL;
enum CKM_MD5_RSA_PKCS               = 0x00000005UL;
enum CKM_SHA1_RSA_PKCS              = 0x00000006UL;

enum CKM_RIPEMD128_RSA_PKCS         = 0x00000007UL;
enum CKM_RIPEMD160_RSA_PKCS         = 0x00000008UL;
enum CKM_RSA_PKCS_OAEP              = 0x00000009UL;

enum CKM_RSA_X9_31_KEY_PAIR_GEN     = 0x0000000AUL;
enum CKM_RSA_X9_31                  = 0x0000000BUL;
enum CKM_SHA1_RSA_X9_31             = 0x0000000CUL;
enum CKM_RSA_PKCS_PSS               = 0x0000000DUL;
enum CKM_SHA1_RSA_PKCS_PSS          = 0x0000000EUL;

enum CKM_DSA_KEY_PAIR_GEN           = 0x00000010UL;
enum CKM_DSA                        = 0x00000011UL;
enum CKM_DSA_SHA1                   = 0x00000012UL;
enum CKM_DSA_SHA224                 = 0x00000013UL;
enum CKM_DSA_SHA256                 = 0x00000014UL;
enum CKM_DSA_SHA384                 = 0x00000015UL;
enum CKM_DSA_SHA512                 = 0x00000016UL;

enum CKM_DH_PKCS_KEY_PAIR_GEN       = 0x00000020UL;
enum CKM_DH_PKCS_DERIVE             = 0x00000021UL;

enum CKM_X9_42_DH_KEY_PAIR_GEN      = 0x00000030UL;
enum CKM_X9_42_DH_DERIVE            = 0x00000031UL;
enum CKM_X9_42_DH_HYBRID_DERIVE     = 0x00000032UL;
enum CKM_X9_42_MQV_DERIVE           = 0x00000033UL;

enum CKM_SHA256_RSA_PKCS            = 0x00000040UL;
enum CKM_SHA384_RSA_PKCS            = 0x00000041UL;
enum CKM_SHA512_RSA_PKCS            = 0x00000042UL;
enum CKM_SHA256_RSA_PKCS_PSS        = 0x00000043UL;
enum CKM_SHA384_RSA_PKCS_PSS        = 0x00000044UL;
enum CKM_SHA512_RSA_PKCS_PSS        = 0x00000045UL;

enum CKM_SHA224_RSA_PKCS            = 0x00000046UL;
enum CKM_SHA224_RSA_PKCS_PSS        = 0x00000047UL;

enum CKM_SHA512_224                 = 0x00000048UL;
enum CKM_SHA512_224_HMAC            = 0x00000049UL;
enum CKM_SHA512_224_HMAC_GENERAL    = 0x0000004AUL;
enum CKM_SHA512_224_KEY_DERIVATION  = 0x0000004BUL;
enum CKM_SHA512_256                 = 0x0000004CUL;
enum CKM_SHA512_256_HMAC            = 0x0000004DUL;
enum CKM_SHA512_256_HMAC_GENERAL    = 0x0000004EUL;
enum CKM_SHA512_256_KEY_DERIVATION  = 0x0000004FUL;

enum CKM_SHA512_T                   = 0x00000050UL;
enum CKM_SHA512_T_HMAC              = 0x00000051UL;
enum CKM_SHA512_T_HMAC_GENERAL      = 0x00000052UL;
enum CKM_SHA512_T_KEY_DERIVATION    = 0x00000053UL;

enum CKM_RC2_KEY_GEN                = 0x00000100UL;
enum CKM_RC2_ECB                    = 0x00000101UL;
enum CKM_RC2_CBC                    = 0x00000102UL;
enum CKM_RC2_MAC                    = 0x00000103UL;

enum CKM_RC2_MAC_GENERAL            = 0x00000104UL;
enum CKM_RC2_CBC_PAD                = 0x00000105UL;

enum CKM_RC4_KEY_GEN                = 0x00000110UL;
enum CKM_RC4                        = 0x00000111UL;
enum CKM_DES_KEY_GEN                = 0x00000120UL;
enum CKM_DES_ECB                    = 0x00000121UL;
enum CKM_DES_CBC                    = 0x00000122UL;
enum CKM_DES_MAC                    = 0x00000123UL;

enum CKM_DES_MAC_GENERAL            = 0x00000124UL;
enum CKM_DES_CBC_PAD                = 0x00000125UL;

enum CKM_DES2_KEY_GEN               = 0x00000130UL;
enum CKM_DES3_KEY_GEN               = 0x00000131UL;
enum CKM_DES3_ECB                   = 0x00000132UL;
enum CKM_DES3_CBC                   = 0x00000133UL;
enum CKM_DES3_MAC                   = 0x00000134UL;

enum CKM_DES3_MAC_GENERAL           = 0x00000135UL;
enum CKM_DES3_CBC_PAD               = 0x00000136UL;
enum CKM_DES3_CMAC_GENERAL          = 0x00000137UL;
enum CKM_DES3_CMAC                  = 0x00000138UL;
enum CKM_CDMF_KEY_GEN               = 0x00000140UL;
enum CKM_CDMF_ECB                   = 0x00000141UL;
enum CKM_CDMF_CBC                   = 0x00000142UL;
enum CKM_CDMF_MAC                   = 0x00000143UL;
enum CKM_CDMF_MAC_GENERAL           = 0x00000144UL;
enum CKM_CDMF_CBC_PAD               = 0x00000145UL;

enum CKM_DES_OFB64                  = 0x00000150UL;
enum CKM_DES_OFB8                   = 0x00000151UL;
enum CKM_DES_CFB64                  = 0x00000152UL;
enum CKM_DES_CFB8                   = 0x00000153UL;

enum CKM_MD2                        = 0x00000200UL;

enum CKM_MD2_HMAC                   = 0x00000201UL;
enum CKM_MD2_HMAC_GENERAL           = 0x00000202UL;

enum CKM_MD5                        = 0x00000210UL;

enum CKM_MD5_HMAC                   = 0x00000211UL;
enum CKM_MD5_HMAC_GENERAL           = 0x00000212UL;

enum CKM_SHA_1                      = 0x00000220UL;

enum CKM_SHA_1_HMAC                 = 0x00000221UL;
enum CKM_SHA_1_HMAC_GENERAL         = 0x00000222UL;

enum CKM_RIPEMD128                  = 0x00000230UL;
enum CKM_RIPEMD128_HMAC             = 0x00000231UL;
enum CKM_RIPEMD128_HMAC_GENERAL     = 0x00000232UL;
enum CKM_RIPEMD160                  = 0x00000240UL;
enum CKM_RIPEMD160_HMAC             = 0x00000241UL;
enum CKM_RIPEMD160_HMAC_GENERAL     = 0x00000242UL;

enum CKM_SHA256                     = 0x00000250UL;
enum CKM_SHA256_HMAC                = 0x00000251UL;
enum CKM_SHA256_HMAC_GENERAL        = 0x00000252UL;
enum CKM_SHA224                     = 0x00000255UL;
enum CKM_SHA224_HMAC                = 0x00000256UL;
enum CKM_SHA224_HMAC_GENERAL        = 0x00000257UL;
enum CKM_SHA384                     = 0x00000260UL;
enum CKM_SHA384_HMAC                = 0x00000261UL;
enum CKM_SHA384_HMAC_GENERAL        = 0x00000262UL;
enum CKM_SHA512                     = 0x00000270UL;
enum CKM_SHA512_HMAC                = 0x00000271UL;
enum CKM_SHA512_HMAC_GENERAL        = 0x00000272UL;
enum CKM_SECURID_KEY_GEN            = 0x00000280UL;
enum CKM_SECURID                    = 0x00000282UL;
enum CKM_HOTP_KEY_GEN               = 0x00000290UL;
enum CKM_HOTP                       = 0x00000291UL;
enum CKM_ACTI                       = 0x000002A0UL;
enum CKM_ACTI_KEY_GEN               = 0x000002A1UL;

enum CKM_CAST_KEY_GEN               = 0x00000300UL;
enum CKM_CAST_ECB                   = 0x00000301UL;
enum CKM_CAST_CBC                   = 0x00000302UL;
enum CKM_CAST_MAC                   = 0x00000303UL;
enum CKM_CAST_MAC_GENERAL           = 0x00000304UL;
enum CKM_CAST_CBC_PAD               = 0x00000305UL;
enum CKM_CAST3_KEY_GEN              = 0x00000310UL;
enum CKM_CAST3_ECB                  = 0x00000311UL;
enum CKM_CAST3_CBC                  = 0x00000312UL;
enum CKM_CAST3_MAC                  = 0x00000313UL;
enum CKM_CAST3_MAC_GENERAL          = 0x00000314UL;
enum CKM_CAST3_CBC_PAD              = 0x00000315UL;
/* Note that CAST128 and CAST5 are the same algorithm */
enum CKM_CAST5_KEY_GEN              = 0x00000320UL;
enum CKM_CAST128_KEY_GEN            = 0x00000320UL;
enum CKM_CAST5_ECB                  = 0x00000321UL;
enum CKM_CAST128_ECB                = 0x00000321UL;
enum CKM_CAST5_CBC                  = 0x00000322UL; /* Deprecated */
enum CKM_CAST128_CBC                = 0x00000322UL;
enum CKM_CAST5_MAC                  = 0x00000323UL; /* Deprecated */
enum CKM_CAST128_MAC                = 0x00000323UL;
enum CKM_CAST5_MAC_GENERAL          = 0x00000324UL; /* Deprecated */
enum CKM_CAST128_MAC_GENERAL        = 0x00000324UL;
enum CKM_CAST5_CBC_PAD              = 0x00000325UL; /* Deprecated */
enum CKM_CAST128_CBC_PAD            = 0x00000325UL;
enum CKM_RC5_KEY_GEN                = 0x00000330UL;
enum CKM_RC5_ECB                    = 0x00000331UL;
enum CKM_RC5_CBC                    = 0x00000332UL;
enum CKM_RC5_MAC                    = 0x00000333UL;
enum CKM_RC5_MAC_GENERAL            = 0x00000334UL;
enum CKM_RC5_CBC_PAD                = 0x00000335UL;
enum CKM_IDEA_KEY_GEN               = 0x00000340UL;
enum CKM_IDEA_ECB                   = 0x00000341UL;
enum CKM_IDEA_CBC                   = 0x00000342UL;
enum CKM_IDEA_MAC                   = 0x00000343UL;
enum CKM_IDEA_MAC_GENERAL           = 0x00000344UL;
enum CKM_IDEA_CBC_PAD               = 0x00000345UL;
enum CKM_GENERIC_SECRET_KEY_GEN     = 0x00000350UL;
enum CKM_CONCATENATE_BASE_AND_KEY   = 0x00000360UL;
enum CKM_CONCATENATE_BASE_AND_DATA  = 0x00000362UL;
enum CKM_CONCATENATE_DATA_AND_BASE  = 0x00000363UL;
enum CKM_XOR_BASE_AND_DATA          = 0x00000364UL;
enum CKM_EXTRACT_KEY_FROM_KEY       = 0x00000365UL;
enum CKM_SSL3_PRE_MASTER_KEY_GEN    = 0x00000370UL;
enum CKM_SSL3_MASTER_KEY_DERIVE     = 0x00000371UL;
enum CKM_SSL3_KEY_AND_MAC_DERIVE    = 0x00000372UL;

enum CKM_SSL3_MASTER_KEY_DERIVE_DH  = 0x00000373UL;
enum CKM_TLS_PRE_MASTER_KEY_GEN     = 0x00000374UL;
enum CKM_TLS_MASTER_KEY_DERIVE      = 0x00000375UL;
enum CKM_TLS_KEY_AND_MAC_DERIVE     = 0x00000376UL;
enum CKM_TLS_MASTER_KEY_DERIVE_DH   = 0x00000377UL;

enum CKM_TLS_PRF                    = 0x00000378UL;

enum CKM_SSL3_MD5_MAC               = 0x00000380UL;
enum CKM_SSL3_SHA1_MAC              = 0x00000381UL;
enum CKM_MD5_KEY_DERIVATION         = 0x00000390UL;
enum CKM_MD2_KEY_DERIVATION         = 0x00000391UL;
enum CKM_SHA1_KEY_DERIVATION        = 0x00000392UL;

enum CKM_SHA256_KEY_DERIVATION      = 0x00000393UL;
enum CKM_SHA384_KEY_DERIVATION      = 0x00000394UL;
enum CKM_SHA512_KEY_DERIVATION      = 0x00000395UL;
enum CKM_SHA224_KEY_DERIVATION      = 0x00000396UL;

enum CKM_PBE_MD2_DES_CBC            = 0x000003A0UL;
enum CKM_PBE_MD5_DES_CBC            = 0x000003A1UL;
enum CKM_PBE_MD5_CAST_CBC           = 0x000003A2UL;
enum CKM_PBE_MD5_CAST3_CBC          = 0x000003A3UL;
enum CKM_PBE_MD5_CAST5_CBC          = 0x000003A4UL; /* Deprecated */
enum CKM_PBE_MD5_CAST128_CBC        = 0x000003A4UL;
enum CKM_PBE_SHA1_CAST5_CBC         = 0x000003A5UL; /* Deprecated */
enum CKM_PBE_SHA1_CAST128_CBC       = 0x000003A5UL;
enum CKM_PBE_SHA1_RC4_128           = 0x000003A6UL;
enum CKM_PBE_SHA1_RC4_40            = 0x000003A7UL;
enum CKM_PBE_SHA1_DES3_EDE_CBC      = 0x000003A8UL;
enum CKM_PBE_SHA1_DES2_EDE_CBC      = 0x000003A9UL;
enum CKM_PBE_SHA1_RC2_128_CBC       = 0x000003AAUL;
enum CKM_PBE_SHA1_RC2_40_CBC        = 0x000003ABUL;

enum CKM_PKCS5_PBKD2                = 0x000003B0UL;

enum CKM_PBA_SHA1_WITH_SHA1_HMAC    = 0x000003C0UL;

enum CKM_WTLS_PRE_MASTER_KEY_GEN         = 0x000003D0UL;
enum CKM_WTLS_MASTER_KEY_DERIVE          = 0x000003D1UL;
enum CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC   = 0x000003D2UL;
enum CKM_WTLS_PRF                        = 0x000003D3UL;
enum CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE  = 0x000003D4UL;
enum CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE  = 0x000003D5UL;

enum CKM_TLS10_MAC_SERVER                = 0x000003D6UL;
enum CKM_TLS10_MAC_CLIENT                = 0x000003D7UL;
enum CKM_TLS12_MAC                       = 0x000003D8UL;
enum CKM_TLS12_KDF                       = 0x000003D9UL;
enum CKM_TLS12_MASTER_KEY_DERIVE         = 0x000003E0UL;
enum CKM_TLS12_KEY_AND_MAC_DERIVE        = 0x000003E1UL;
enum CKM_TLS12_MASTER_KEY_DERIVE_DH      = 0x000003E2UL;
enum CKM_TLS12_KEY_SAFE_DERIVE           = 0x000003E3UL;
enum CKM_TLS_MAC                         = 0x000003E4UL;
enum CKM_TLS_KDF                         = 0x000003E5UL;

enum CKM_KEY_WRAP_LYNKS             = 0x00000400UL;
enum CKM_KEY_WRAP_SET_OAEP          = 0x00000401UL;

enum CKM_CMS_SIG                    = 0x00000500UL;
enum CKM_KIP_DERIVE                 = 0x00000510UL;
enum CKM_KIP_WRAP                   = 0x00000511UL;
enum CKM_KIP_MAC                    = 0x00000512UL;

enum CKM_CAMELLIA_KEY_GEN           = 0x00000550UL;
enum CKM_CAMELLIA_ECB               = 0x00000551UL;
enum CKM_CAMELLIA_CBC               = 0x00000552UL;
enum CKM_CAMELLIA_MAC               = 0x00000553UL;
enum CKM_CAMELLIA_MAC_GENERAL       = 0x00000554UL;
enum CKM_CAMELLIA_CBC_PAD           = 0x00000555UL;
enum CKM_CAMELLIA_ECB_ENCRYPT_DATA  = 0x00000556UL;
enum CKM_CAMELLIA_CBC_ENCRYPT_DATA  = 0x00000557UL;
enum CKM_CAMELLIA_CTR               = 0x00000558UL;

enum CKM_ARIA_KEY_GEN               = 0x00000560UL;
enum CKM_ARIA_ECB                   = 0x00000561UL;
enum CKM_ARIA_CBC                   = 0x00000562UL;
enum CKM_ARIA_MAC                   = 0x00000563UL;
enum CKM_ARIA_MAC_GENERAL           = 0x00000564UL;
enum CKM_ARIA_CBC_PAD               = 0x00000565UL;
enum CKM_ARIA_ECB_ENCRYPT_DATA      = 0x00000566UL;
enum CKM_ARIA_CBC_ENCRYPT_DATA      = 0x00000567UL;

enum CKM_SEED_KEY_GEN               = 0x00000650UL;
enum CKM_SEED_ECB                   = 0x00000651UL;
enum CKM_SEED_CBC                   = 0x00000652UL;
enum CKM_SEED_MAC                   = 0x00000653UL;
enum CKM_SEED_MAC_GENERAL           = 0x00000654UL;
enum CKM_SEED_CBC_PAD               = 0x00000655UL;
enum CKM_SEED_ECB_ENCRYPT_DATA      = 0x00000656UL;
enum CKM_SEED_CBC_ENCRYPT_DATA      = 0x00000657UL;

enum CKM_SKIPJACK_KEY_GEN           = 0x00001000UL;
enum CKM_SKIPJACK_ECB64             = 0x00001001UL;
enum CKM_SKIPJACK_CBC64             = 0x00001002UL;
enum CKM_SKIPJACK_OFB64             = 0x00001003UL;
enum CKM_SKIPJACK_CFB64             = 0x00001004UL;
enum CKM_SKIPJACK_CFB32             = 0x00001005UL;
enum CKM_SKIPJACK_CFB16             = 0x00001006UL;
enum CKM_SKIPJACK_CFB8              = 0x00001007UL;
enum CKM_SKIPJACK_WRAP              = 0x00001008UL;
enum CKM_SKIPJACK_PRIVATE_WRAP      = 0x00001009UL;
enum CKM_SKIPJACK_RELAYX            = 0x0000100aUL;
enum CKM_KEA_KEY_PAIR_GEN           = 0x00001010UL;
enum CKM_KEA_KEY_DERIVE             = 0x00001011UL;
enum CKM_KEA_DERIVE                 = 0x00001012UL;
enum CKM_FORTEZZA_TIMESTAMP         = 0x00001020UL;
enum CKM_BATON_KEY_GEN              = 0x00001030UL;
enum CKM_BATON_ECB128               = 0x00001031UL;
enum CKM_BATON_ECB96                = 0x00001032UL;
enum CKM_BATON_CBC128               = 0x00001033UL;
enum CKM_BATON_COUNTER              = 0x00001034UL;
enum CKM_BATON_SHUFFLE              = 0x00001035UL;
enum CKM_BATON_WRAP                 = 0x00001036UL;

enum CKM_ECDSA_KEY_PAIR_GEN         = 0x00001040UL; /* Deprecated */
enum CKM_EC_KEY_PAIR_GEN            = 0x00001040UL;

enum CKM_ECDSA                      = 0x00001041UL;
enum CKM_ECDSA_SHA1                 = 0x00001042UL;
enum CKM_ECDSA_SHA224               = 0x00001043UL;
enum CKM_ECDSA_SHA256               = 0x00001044UL;
enum CKM_ECDSA_SHA384               = 0x00001045UL;
enum CKM_ECDSA_SHA512               = 0x00001046UL;

enum CKM_ECDH1_DERIVE               = 0x00001050UL;
enum CKM_ECDH1_COFACTOR_DERIVE      = 0x00001051UL;
enum CKM_ECMQV_DERIVE               = 0x00001052UL;

enum CKM_ECDH_AES_KEY_WRAP          = 0x00001053UL;
enum CKM_RSA_AES_KEY_WRAP           = 0x00001054UL;

enum CKM_JUNIPER_KEY_GEN            = 0x00001060UL;
enum CKM_JUNIPER_ECB128             = 0x00001061UL;
enum CKM_JUNIPER_CBC128             = 0x00001062UL;
enum CKM_JUNIPER_COUNTER            = 0x00001063UL;
enum CKM_JUNIPER_SHUFFLE            = 0x00001064UL;
enum CKM_JUNIPER_WRAP               = 0x00001065UL;
enum CKM_FASTHASH                   = 0x00001070UL;

enum CKM_AES_KEY_GEN                = 0x00001080UL;
enum CKM_AES_ECB                    = 0x00001081UL;
enum CKM_AES_CBC                    = 0x00001082UL;
enum CKM_AES_MAC                    = 0x00001083UL;
enum CKM_AES_MAC_GENERAL            = 0x00001084UL;
enum CKM_AES_CBC_PAD                = 0x00001085UL;
enum CKM_AES_CTR                    = 0x00001086UL;
enum CKM_AES_GCM                    = 0x00001087UL;
enum CKM_AES_CCM                    = 0x00001088UL;
enum CKM_AES_CTS                    = 0x00001089UL;
enum CKM_AES_CMAC                   = 0x0000108AUL;
enum CKM_AES_CMAC_GENERAL           = 0x0000108BUL;

enum CKM_AES_XCBC_MAC               = 0x0000108CUL;
enum CKM_AES_XCBC_MAC_96            = 0x0000108DUL;
enum CKM_AES_GMAC                   = 0x0000108EUL;

enum CKM_BLOWFISH_KEY_GEN           = 0x00001090UL;
enum CKM_BLOWFISH_CBC               = 0x00001091UL;
enum CKM_TWOFISH_KEY_GEN            = 0x00001092UL;
enum CKM_TWOFISH_CBC                = 0x00001093UL;
enum CKM_BLOWFISH_CBC_PAD           = 0x00001094UL;
enum CKM_TWOFISH_CBC_PAD            = 0x00001095UL;

enum CKM_DES_ECB_ENCRYPT_DATA       = 0x00001100UL;
enum CKM_DES_CBC_ENCRYPT_DATA       = 0x00001101UL;
enum CKM_DES3_ECB_ENCRYPT_DATA      = 0x00001102UL;
enum CKM_DES3_CBC_ENCRYPT_DATA      = 0x00001103UL;
enum CKM_AES_ECB_ENCRYPT_DATA       = 0x00001104UL;
enum CKM_AES_CBC_ENCRYPT_DATA       = 0x00001105UL;

enum CKM_GOSTR3410_KEY_PAIR_GEN     = 0x00001200UL;
enum CKM_GOSTR3410                  = 0x00001201UL;
enum CKM_GOSTR3410_WITH_GOSTR3411   = 0x00001202UL;
enum CKM_GOSTR3410_KEY_WRAP         = 0x00001203UL;
enum CKM_GOSTR3410_DERIVE           = 0x00001204UL;
enum CKM_GOSTR3411                  = 0x00001210UL;
enum CKM_GOSTR3411_HMAC             = 0x00001211UL;
enum CKM_GOST28147_KEY_GEN          = 0x00001220UL;
enum CKM_GOST28147_ECB              = 0x00001221UL;
enum CKM_GOST28147                  = 0x00001222UL;
enum CKM_GOST28147_MAC              = 0x00001223UL;
enum CKM_GOST28147_KEY_WRAP         = 0x00001224UL;

enum CKM_DSA_PARAMETER_GEN          = 0x00002000UL;
enum CKM_DH_PKCS_PARAMETER_GEN      = 0x00002001UL;
enum CKM_X9_42_DH_PARAMETER_GEN     = 0x00002002UL;
enum CKM_DSA_PROBABLISTIC_PARAMETER_GEN    = 0x00002003UL;
enum CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN    = 0x00002004UL;

enum CKM_AES_OFB                    = 0x00002104UL;
enum CKM_AES_CFB64                  = 0x00002105UL;
enum CKM_AES_CFB8                   = 0x00002106UL;
enum CKM_AES_CFB128                 = 0x00002107UL;

enum CKM_AES_CFB1                   = 0x00002108UL;
enum CKM_AES_KEY_WRAP               = 0x00002109UL;     /* WAS: 0x00001090 */
enum CKM_AES_KEY_WRAP_PAD           = 0x0000210AUL;     /* WAS: 0x00001091 */

enum CKM_RSA_PKCS_TPM_1_1           = 0x00004001UL;
enum CKM_RSA_PKCS_OAEP_TPM_1_1      = 0x00004002UL;

enum CKM_VENDOR_DEFINED             = 0x80000000UL;

alias CK_MECHANISM_TYPE * CK_MECHANISM_TYPE_PTR;


/* CK_MECHANISM is a structure that specifies a particular
 * mechanism
 */
struct CK_MECHANISM {
  CK_MECHANISM_TYPE mechanism;
  CK_VOID_PTR       pParameter;
  CK_ULONG          ulParameterLen;  /* in bytes */
}

alias CK_MECHANISM * CK_MECHANISM_PTR;


/* CK_MECHANISM_INFO provides information about a particular
 * mechanism
 */
struct CK_MECHANISM_INFO {
    CK_ULONG    ulMinKeySize;
    CK_ULONG    ulMaxKeySize;
    CK_FLAGS    flags;
}

/* The flags are defined as follows:
 *      Bit Flag               Mask          Meaning */
enum CKF_HW                 = 0x00000001UL;  /* performed by HW */

/* Specify whether or not a mechanism can be used for a particular task */
enum CKF_ENCRYPT            = 0x00000100UL;
enum CKF_DECRYPT            = 0x00000200UL;
enum CKF_DIGEST             = 0x00000400UL;
enum CKF_SIGN               = 0x00000800UL;
enum CKF_SIGN_RECOVER       = 0x00001000UL;
enum CKF_VERIFY             = 0x00002000UL;
enum CKF_VERIFY_RECOVER     = 0x00004000UL;
enum CKF_GENERATE           = 0x00008000UL;
enum CKF_GENERATE_KEY_PAIR  = 0x00010000UL;
enum CKF_WRAP               = 0x00020000UL;
enum CKF_UNWRAP             = 0x00040000UL;
enum CKF_DERIVE             = 0x00080000UL;

/* Describe a token's EC capabilities not available in mechanism
 * information.
 */
enum CKF_EC_F_P             = 0x00100000UL;
enum CKF_EC_F_2M            = 0x00200000UL;
enum CKF_EC_ECPARAMETERS    = 0x00400000UL;
enum CKF_EC_NAMEDCURVE      = 0x00800000UL;
enum CKF_EC_UNCOMPRESS      = 0x01000000UL;
enum CKF_EC_COMPRESS        = 0x02000000UL;

enum CKF_EXTENSION          = 0x80000000UL;

alias CK_MECHANISM_INFO * CK_MECHANISM_INFO_PTR;

/* CK_RV is a value that identifies the return value of a
 * Cryptoki function
 */
alias CK_ULONG          CK_RV;

enum CKR_OK                                = 0x00000000UL;
enum CKR_CANCEL                            = 0x00000001UL;
enum CKR_HOST_MEMORY                       = 0x00000002UL;
enum CKR_SLOT_ID_INVALID                   = 0x00000003UL;

enum CKR_GENERAL_ERROR                     = 0x00000005UL;
enum CKR_FUNCTION_FAILED                   = 0x00000006UL;

enum CKR_ARGUMENTS_BAD                     = 0x00000007UL;
enum CKR_NO_EVENT                          = 0x00000008UL;
enum CKR_NEED_TO_CREATE_THREADS            = 0x00000009UL;
enum CKR_CANT_LOCK                         = 0x0000000AUL;

enum CKR_ATTRIBUTE_READ_ONLY               = 0x00000010UL;
enum CKR_ATTRIBUTE_SENSITIVE               = 0x00000011UL;
enum CKR_ATTRIBUTE_TYPE_INVALID            = 0x00000012UL;
enum CKR_ATTRIBUTE_VALUE_INVALID           = 0x00000013UL;

enum CKR_ACTION_PROHIBITED                 = 0x0000001BUL;

enum CKR_DATA_INVALID                      = 0x00000020UL;
enum CKR_DATA_LEN_RANGE                    = 0x00000021UL;
enum CKR_DEVICE_ERROR                      = 0x00000030UL;
enum CKR_DEVICE_MEMORY                     = 0x00000031UL;
enum CKR_DEVICE_REMOVED                    = 0x00000032UL;
enum CKR_ENCRYPTED_DATA_INVALID            = 0x00000040UL;
enum CKR_ENCRYPTED_DATA_LEN_RANGE          = 0x00000041UL;
enum CKR_FUNCTION_CANCELED                 = 0x00000050UL;
enum CKR_FUNCTION_NOT_PARALLEL             = 0x00000051UL;

enum CKR_FUNCTION_NOT_SUPPORTED            = 0x00000054UL;

enum CKR_KEY_HANDLE_INVALID                = 0x00000060UL;

enum CKR_KEY_SIZE_RANGE                    = 0x00000062UL;
enum CKR_KEY_TYPE_INCONSISTENT             = 0x00000063UL;

enum CKR_KEY_NOT_NEEDED                    = 0x00000064UL;
enum CKR_KEY_CHANGED                       = 0x00000065UL;
enum CKR_KEY_NEEDED                        = 0x00000066UL;
enum CKR_KEY_INDIGESTIBLE                  = 0x00000067UL;
enum CKR_KEY_FUNCTION_NOT_PERMITTED        = 0x00000068UL;
enum CKR_KEY_NOT_WRAPPABLE                 = 0x00000069UL;
enum CKR_KEY_UNEXTRACTABLE                 = 0x0000006AUL;

enum CKR_MECHANISM_INVALID                 = 0x00000070UL;
enum CKR_MECHANISM_PARAM_INVALID           = 0x00000071UL;

enum CKR_OBJECT_HANDLE_INVALID             = 0x00000082UL;
enum CKR_OPERATION_ACTIVE                  = 0x00000090UL;
enum CKR_OPERATION_NOT_INITIALIZED         = 0x00000091UL;
enum CKR_PIN_INCORRECT                     = 0x000000A0UL;
enum CKR_PIN_INVALID                       = 0x000000A1UL;
enum CKR_PIN_LEN_RANGE                     = 0x000000A2UL;

enum CKR_PIN_EXPIRED                       = 0x000000A3UL;
enum CKR_PIN_LOCKED                        = 0x000000A4UL;

enum CKR_SESSION_CLOSED                    = 0x000000B0UL;
enum CKR_SESSION_COUNT                     = 0x000000B1UL;
enum CKR_SESSION_HANDLE_INVALID            = 0x000000B3UL;
enum CKR_SESSION_PARALLEL_NOT_SUPPORTED    = 0x000000B4UL;
enum CKR_SESSION_READ_ONLY                 = 0x000000B5UL;
enum CKR_SESSION_EXISTS                    = 0x000000B6UL;

enum CKR_SESSION_READ_ONLY_EXISTS          = 0x000000B7UL;
enum CKR_SESSION_READ_WRITE_SO_EXISTS      = 0x000000B8UL;

enum CKR_SIGNATURE_INVALID                 = 0x000000C0UL;
enum CKR_SIGNATURE_LEN_RANGE               = 0x000000C1UL;
enum CKR_TEMPLATE_INCOMPLETE               = 0x000000D0UL;
enum CKR_TEMPLATE_INCONSISTENT             = 0x000000D1UL;
enum CKR_TOKEN_NOT_PRESENT                 = 0x000000E0UL;
enum CKR_TOKEN_NOT_RECOGNIZED              = 0x000000E1UL;
enum CKR_TOKEN_WRITE_PROTECTED             = 0x000000E2UL;
enum CKR_UNWRAPPING_KEY_HANDLE_INVALID     = 0x000000F0UL;
enum CKR_UNWRAPPING_KEY_SIZE_RANGE         = 0x000000F1UL;
enum CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  = 0x000000F2UL;
enum CKR_USER_ALREADY_LOGGED_IN            = 0x00000100UL;
enum CKR_USER_NOT_LOGGED_IN                = 0x00000101UL;
enum CKR_USER_PIN_NOT_INITIALIZED          = 0x00000102UL;
enum CKR_USER_TYPE_INVALID                 = 0x00000103UL;

enum CKR_USER_ANOTHER_ALREADY_LOGGED_IN    = 0x00000104UL;
enum CKR_USER_TOO_MANY_TYPES               = 0x00000105UL;

enum CKR_WRAPPED_KEY_INVALID               = 0x00000110UL;
enum CKR_WRAPPED_KEY_LEN_RANGE             = 0x00000112UL;
enum CKR_WRAPPING_KEY_HANDLE_INVALID       = 0x00000113UL;
enum CKR_WRAPPING_KEY_SIZE_RANGE           = 0x00000114UL;
enum CKR_WRAPPING_KEY_TYPE_INCONSISTENT    = 0x00000115UL;
enum CKR_RANDOM_SEED_NOT_SUPPORTED         = 0x00000120UL;

enum CKR_RANDOM_NO_RNG                     = 0x00000121UL;

enum CKR_DOMAIN_PARAMS_INVALID             = 0x00000130UL;

enum CKR_CURVE_NOT_SUPPORTED               = 0x00000140UL;

enum CKR_BUFFER_TOO_SMALL                  = 0x00000150UL;
enum CKR_SAVED_STATE_INVALID               = 0x00000160UL;
enum CKR_INFORMATION_SENSITIVE             = 0x00000170UL;
enum CKR_STATE_UNSAVEABLE                  = 0x00000180UL;

enum CKR_CRYPTOKI_NOT_INITIALIZED          = 0x00000190UL;
enum CKR_CRYPTOKI_ALREADY_INITIALIZED      = 0x00000191UL;
enum CKR_MUTEX_BAD                         = 0x000001A0UL;
enum CKR_MUTEX_NOT_LOCKED                  = 0x000001A1UL;

enum CKR_NEW_PIN_MODE                      = 0x000001B0UL;
enum CKR_NEXT_OTP                          = 0x000001B1UL;

enum CKR_EXCEEDED_MAX_ITERATIONS           = 0x000001B5UL;
enum CKR_FIPS_SELF_TEST_FAILED             = 0x000001B6UL;
enum CKR_LIBRARY_LOAD_FAILED               = 0x000001B7UL;
enum CKR_PIN_TOO_WEAK                      = 0x000001B8UL;
enum CKR_PUBLIC_KEY_INVALID                = 0x000001B9UL;

enum CKR_FUNCTION_REJECTED                 = 0x00000200UL;

enum CKR_VENDOR_DEFINED                    = 0x80000000UL;


/* CK_NOTIFY is an application callback that processes events */
alias  CK_NOTIFY = CK_RV function(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_NOTIFICATION   event,
  CK_VOID_PTR       pApplication  /* passed to C_OpenSession */
);


/* CK_FUNCTION_LIST is a structure holding a Cryptoki spec
 * version and pointers of appropriate types to all the
 * Cryptoki functions
 */
//typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;

alias CK_FUNCTION_LIST * CK_FUNCTION_LIST_PTR;

alias CK_FUNCTION_LIST_PTR * CK_FUNCTION_LIST_PTR_PTR;


/* CK_CREATEMUTEX is an application callback for creating a
 * mutex object
 */
alias  CK_CREATEMUTEX = CK_RV function(
  CK_VOID_PTR_PTR ppMutex  /* location to receive ptr to mutex */
);


/* CK_DESTROYMUTEX is an application callback for destroying a
 * mutex object
 */
alias  CK_DESTROYMUTEX = CK_RV function(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);


/* CK_LOCKMUTEX is an application callback for locking a mutex */
alias  CK_LOCKMUTEX = CK_RV function(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);


/* CK_UNLOCKMUTEX is an application callback for unlocking a
 * mutex
 */
alias  CK_UNLOCKMUTEX = CK_RV function(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);


/* CK_C_INITIALIZE_ARGS provides the optional arguments to
 * C_Initialize
 */
struct CK_C_INITIALIZE_ARGS {
  CK_CREATEMUTEX CreateMutex;
  CK_DESTROYMUTEX DestroyMutex;
  CK_LOCKMUTEX LockMutex;
  CK_UNLOCKMUTEX UnlockMutex;
  CK_FLAGS flags;
  CK_VOID_PTR pReserved;
}

/* flags: bit flags that provide capabilities of the slot
 *      Bit Flag                           Mask       Meaning
 */
enum CKF_LIBRARY_CANT_CREATE_OS_THREADS = 0x00000001UL;
enum CKF_OS_LOCKING_OK                  = 0x00000002UL;

alias CK_C_INITIALIZE_ARGS * CK_C_INITIALIZE_ARGS_PTR;


/* additional flags for parameters to functions */

/* CKF_DONT_BLOCK is for the function C_WaitForSlotEvent */
enum CKF_DONT_BLOCK     = 1;

/* CK_RSA_PKCS_MGF_TYPE  is used to indicate the Message
 * Generation Function (MGF) applied to a message block when
 * formatting a message block for the PKCS #1 OAEP encryption
 * scheme.
 */
alias CK_ULONG  CK_RSA_PKCS_MGF_TYPE;

alias CK_RSA_PKCS_MGF_TYPE *  CK_RSA_PKCS_MGF_TYPE_PTR;

/* The following MGFs are defined */
enum CKG_MGF1_SHA1         = 0x00000001UL;
enum CKG_MGF1_SHA256       = 0x00000002UL;
enum CKG_MGF1_SHA384       = 0x00000003UL;
enum CKG_MGF1_SHA512       = 0x00000004UL;
enum CKG_MGF1_SHA224       = 0x00000005UL;

/* CK_RSA_PKCS_OAEP_SOURCE_TYPE  is used to indicate the source
 * of the encoding parameter when formatting a message block
 * for the PKCS #1 OAEP encryption scheme.
 */
alias CK_ULONG  CK_RSA_PKCS_OAEP_SOURCE_TYPE;

alias CK_RSA_PKCS_OAEP_SOURCE_TYPE *  CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR;

/* The following encoding parameter sources are defined */
enum CKZ_DATA_SPECIFIED    = 0x00000001UL;

/* CK_RSA_PKCS_OAEP_PARAMS provides the parameters to the
 * CKM_RSA_PKCS_OAEP mechanism.
 */
struct CK_RSA_PKCS_OAEP_PARAMS {
        CK_MECHANISM_TYPE hashAlg;
        CK_RSA_PKCS_MGF_TYPE mgf;
        CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
        CK_VOID_PTR pSourceData;
        CK_ULONG ulSourceDataLen;
}

alias CK_RSA_PKCS_OAEP_PARAMS * CK_RSA_PKCS_OAEP_PARAMS_PTR;

/* CK_RSA_PKCS_PSS_PARAMS provides the parameters to the
 * CKM_RSA_PKCS_PSS mechanism(s).
 */
struct CK_RSA_PKCS_PSS_PARAMS {
        CK_MECHANISM_TYPE    hashAlg;
        CK_RSA_PKCS_MGF_TYPE mgf;
        CK_ULONG             sLen;
}

alias CK_RSA_PKCS_PSS_PARAMS * CK_RSA_PKCS_PSS_PARAMS_PTR;

alias CK_ULONG CK_EC_KDF_TYPE;

/* The following EC Key Derivation Functions are defined */
enum CKD_NULL                 = 0x00000001UL;
enum CKD_SHA1_KDF             = 0x00000002UL;

/* The following X9.42 DH key derivation functions are defined */
enum CKD_SHA1_KDF_ASN1        = 0x00000003UL;
enum CKD_SHA1_KDF_CONCATENATE = 0x00000004UL;
enum CKD_SHA224_KDF           = 0x00000005UL;
enum CKD_SHA256_KDF           = 0x00000006UL;
enum CKD_SHA384_KDF           = 0x00000007UL;
enum CKD_SHA512_KDF           = 0x00000008UL;
enum CKD_CPDIVERSIFY_KDF      = 0x00000009UL;


/* CK_ECDH1_DERIVE_PARAMS provides the parameters to the
 * CKM_ECDH1_DERIVE and CKM_ECDH1_COFACTOR_DERIVE mechanisms,
 * where each party contributes one key pair.
 */
struct CK_ECDH1_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
}

alias CK_ECDH1_DERIVE_PARAMS * CK_ECDH1_DERIVE_PARAMS_PTR;

/*
 * CK_ECDH2_DERIVE_PARAMS provides the parameters to the
 * CKM_ECMQV_DERIVE mechanism, where each party contributes two key pairs.
 */
struct CK_ECDH2_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
}

alias CK_ECDH2_DERIVE_PARAMS * CK_ECDH2_DERIVE_PARAMS_PTR;

struct CK_ECMQV_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
  CK_OBJECT_HANDLE publicKey;
}

alias CK_ECMQV_DERIVE_PARAMS * CK_ECMQV_DERIVE_PARAMS_PTR;

/* Typedefs and defines for the CKM_X9_42_DH_KEY_PAIR_GEN and the
 * CKM_X9_42_DH_PARAMETER_GEN mechanisms
 */
alias CK_ULONG CK_X9_42_DH_KDF_TYPE;
alias CK_X9_42_DH_KDF_TYPE * CK_X9_42_DH_KDF_TYPE_PTR;

/* CK_X9_42_DH1_DERIVE_PARAMS provides the parameters to the
 * CKM_X9_42_DH_DERIVE key derivation mechanism, where each party
 * contributes one key pair
 */
struct CK_X9_42_DH1_DERIVE_PARAMS {
  CK_X9_42_DH_KDF_TYPE kdf;
  CK_ULONG ulOtherInfoLen;
  CK_BYTE_PTR pOtherInfo;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
}

alias CK_X9_42_DH1_DERIVE_PARAMS * CK_X9_42_DH1_DERIVE_PARAMS_PTR;

/* CK_X9_42_DH2_DERIVE_PARAMS provides the parameters to the
 * CKM_X9_42_DH_HYBRID_DERIVE and CKM_X9_42_MQV_DERIVE key derivation
 * mechanisms, where each party contributes two key pairs
 */
struct CK_X9_42_DH2_DERIVE_PARAMS {
  CK_X9_42_DH_KDF_TYPE kdf;
  CK_ULONG ulOtherInfoLen;
  CK_BYTE_PTR pOtherInfo;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
}

alias CK_X9_42_DH2_DERIVE_PARAMS * CK_X9_42_DH2_DERIVE_PARAMS_PTR;

struct CK_X9_42_MQV_DERIVE_PARAMS {
  CK_X9_42_DH_KDF_TYPE kdf;
  CK_ULONG ulOtherInfoLen;
  CK_BYTE_PTR pOtherInfo;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
  CK_OBJECT_HANDLE publicKey;
}

alias CK_X9_42_MQV_DERIVE_PARAMS * CK_X9_42_MQV_DERIVE_PARAMS_PTR;

/* CK_KEA_DERIVE_PARAMS provides the parameters to the
 * CKM_KEA_DERIVE mechanism
 */
struct CK_KEA_DERIVE_PARAMS {
  CK_BBOOL      isSender;
  CK_ULONG      ulRandomLen;
  CK_BYTE_PTR   pRandomA;
  CK_BYTE_PTR   pRandomB;
  CK_ULONG      ulPublicDataLen;
  CK_BYTE_PTR   pPublicData;
}

alias CK_KEA_DERIVE_PARAMS * CK_KEA_DERIVE_PARAMS_PTR;


/* CK_RC2_PARAMS provides the parameters to the CKM_RC2_ECB and
 * CKM_RC2_MAC mechanisms.  An instance of CK_RC2_PARAMS just
 * holds the effective keysize
 */
alias CK_ULONG          CK_RC2_PARAMS;

alias CK_RC2_PARAMS * CK_RC2_PARAMS_PTR;


/* CK_RC2_CBC_PARAMS provides the parameters to the CKM_RC2_CBC
 * mechanism
 */
struct CK_RC2_CBC_PARAMS {
  CK_ULONG         ulEffectiveBits;  /* effective bits (1-1024) */
  CK_BYTE[8]       iv;               /* IV for CBC mode */
}

alias CK_RC2_CBC_PARAMS * CK_RC2_CBC_PARAMS_PTR;


/* CK_RC2_MAC_GENERAL_PARAMS provides the parameters for the
 * CKM_RC2_MAC_GENERAL mechanism
 */
struct CK_RC2_MAC_GENERAL_PARAMS {
  CK_ULONG      ulEffectiveBits;  /* effective bits (1-1024) */
  CK_ULONG      ulMacLength;      /* Length of MAC in bytes */
}

alias CK_RC2_MAC_GENERAL_PARAMS *  CK_RC2_MAC_GENERAL_PARAMS_PTR;


/* CK_RC5_PARAMS provides the parameters to the CKM_RC5_ECB and
 * CKM_RC5_MAC mechanisms
 */
struct CK_RC5_PARAMS {
  CK_ULONG      ulWordsize;  /* wordsize in bits */
  CK_ULONG      ulRounds;    /* number of rounds */
}

alias CK_RC5_PARAMS * CK_RC5_PARAMS_PTR;


/* CK_RC5_CBC_PARAMS provides the parameters to the CKM_RC5_CBC
 * mechanism
 */
struct CK_RC5_CBC_PARAMS {
  CK_ULONG      ulWordsize;  /* wordsize in bits */
  CK_ULONG      ulRounds;    /* number of rounds */
  CK_BYTE_PTR   pIv;         /* pointer to IV */
  CK_ULONG      ulIvLen;     /* length of IV in bytes */
}

alias CK_RC5_CBC_PARAMS * CK_RC5_CBC_PARAMS_PTR;


/* CK_RC5_MAC_GENERAL_PARAMS provides the parameters for the
 * CKM_RC5_MAC_GENERAL mechanism
 */
struct CK_RC5_MAC_GENERAL_PARAMS {
  CK_ULONG      ulWordsize;   /* wordsize in bits */
  CK_ULONG      ulRounds;     /* number of rounds */
  CK_ULONG      ulMacLength;  /* Length of MAC in bytes */
}

alias CK_RC5_MAC_GENERAL_PARAMS *  CK_RC5_MAC_GENERAL_PARAMS_PTR;

/* CK_MAC_GENERAL_PARAMS provides the parameters to most block
 * ciphers' MAC_GENERAL mechanisms.  Its value is the length of
 * the MAC
 */
alias CK_ULONG          CK_MAC_GENERAL_PARAMS;

alias CK_MAC_GENERAL_PARAMS * CK_MAC_GENERAL_PARAMS_PTR;

struct CK_DES_CBC_ENCRYPT_DATA_PARAMS {
  CK_BYTE[8]   iv;
  CK_BYTE_PTR  pData;
  CK_ULONG     length;
}

alias CK_DES_CBC_ENCRYPT_DATA_PARAMS * CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR;

struct CK_AES_CBC_ENCRYPT_DATA_PARAMS {
  CK_BYTE[16]  iv;
  CK_BYTE_PTR  pData;
  CK_ULONG     length;
}

alias CK_AES_CBC_ENCRYPT_DATA_PARAMS * CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR;

/* CK_SKIPJACK_PRIVATE_WRAP_PARAMS provides the parameters to the
 * CKM_SKIPJACK_PRIVATE_WRAP mechanism
 */
struct CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
  CK_ULONG      ulPasswordLen;
  CK_BYTE_PTR   pPassword;
  CK_ULONG      ulPublicDataLen;
  CK_BYTE_PTR   pPublicData;
  CK_ULONG      ulPAndGLen;
  CK_ULONG      ulQLen;
  CK_ULONG      ulRandomLen;
  CK_BYTE_PTR   pRandomA;
  CK_BYTE_PTR   pPrimeP;
  CK_BYTE_PTR   pBaseG;
  CK_BYTE_PTR   pSubprimeQ;
}

alias CK_SKIPJACK_PRIVATE_WRAP_PARAMS *  CK_SKIPJACK_PRIVATE_WRAP_PARAMS_PTR;


/* CK_SKIPJACK_RELAYX_PARAMS provides the parameters to the
 * CKM_SKIPJACK_RELAYX mechanism
 */
struct CK_SKIPJACK_RELAYX_PARAMS {
  CK_ULONG      ulOldWrappedXLen;
  CK_BYTE_PTR   pOldWrappedX;
  CK_ULONG      ulOldPasswordLen;
  CK_BYTE_PTR   pOldPassword;
  CK_ULONG      ulOldPublicDataLen;
  CK_BYTE_PTR   pOldPublicData;
  CK_ULONG      ulOldRandomLen;
  CK_BYTE_PTR   pOldRandomA;
  CK_ULONG      ulNewPasswordLen;
  CK_BYTE_PTR   pNewPassword;
  CK_ULONG      ulNewPublicDataLen;
  CK_BYTE_PTR   pNewPublicData;
  CK_ULONG      ulNewRandomLen;
  CK_BYTE_PTR   pNewRandomA;
}

alias CK_SKIPJACK_RELAYX_PARAMS *  CK_SKIPJACK_RELAYX_PARAMS_PTR;


struct CK_PBE_PARAMS {
  CK_BYTE_PTR      pInitVector;
  CK_UTF8CHAR_PTR  pPassword;
  CK_ULONG         ulPasswordLen;
  CK_BYTE_PTR      pSalt;
  CK_ULONG         ulSaltLen;
  CK_ULONG         ulIteration;
}

alias CK_PBE_PARAMS * CK_PBE_PARAMS_PTR;


/* CK_KEY_WRAP_SET_OAEP_PARAMS provides the parameters to the
 * CKM_KEY_WRAP_SET_OAEP mechanism
 */
struct CK_KEY_WRAP_SET_OAEP_PARAMS {
  CK_BYTE       bBC;     /* block contents byte */
  CK_BYTE_PTR   pX;      /* extra data */
  CK_ULONG      ulXLen;  /* length of extra data in bytes */
}

alias CK_KEY_WRAP_SET_OAEP_PARAMS * CK_KEY_WRAP_SET_OAEP_PARAMS_PTR;

struct CK_SSL3_RANDOM_DATA {
  CK_BYTE_PTR  pClientRandom;
  CK_ULONG     ulClientRandomLen;
  CK_BYTE_PTR  pServerRandom;
  CK_ULONG     ulServerRandomLen;
}


struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
  CK_SSL3_RANDOM_DATA RandomInfo;
  CK_VERSION_PTR pVersion;
}

alias CK_SSL3_MASTER_KEY_DERIVE_PARAMS *  CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR;

struct CK_SSL3_KEY_MAT_OUT {
  CK_OBJECT_HANDLE hClientMacSecret;
  CK_OBJECT_HANDLE hServerMacSecret;
  CK_OBJECT_HANDLE hClientKey;
  CK_OBJECT_HANDLE hServerKey;
  CK_BYTE_PTR      pIVClient;
  CK_BYTE_PTR      pIVServer;
}

alias CK_SSL3_KEY_MAT_OUT * CK_SSL3_KEY_MAT_OUT_PTR;


struct CK_SSL3_KEY_MAT_PARAMS {
  CK_ULONG                ulMacSizeInBits;
  CK_ULONG                ulKeySizeInBits;
  CK_ULONG                ulIVSizeInBits;
  CK_BBOOL                bIsExport;
  CK_SSL3_RANDOM_DATA     RandomInfo;
  CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
}

alias CK_SSL3_KEY_MAT_PARAMS * CK_SSL3_KEY_MAT_PARAMS_PTR;

struct CK_TLS_PRF_PARAMS {
  CK_BYTE_PTR  pSeed;
  CK_ULONG     ulSeedLen;
  CK_BYTE_PTR  pLabel;
  CK_ULONG     ulLabelLen;
  CK_BYTE_PTR  pOutput;
  CK_ULONG_PTR pulOutputLen;
}

alias CK_TLS_PRF_PARAMS * CK_TLS_PRF_PARAMS_PTR;

struct CK_WTLS_RANDOM_DATA {
  CK_BYTE_PTR pClientRandom;
  CK_ULONG    ulClientRandomLen;
  CK_BYTE_PTR pServerRandom;
  CK_ULONG    ulServerRandomLen;
}

alias CK_WTLS_RANDOM_DATA * CK_WTLS_RANDOM_DATA_PTR;

struct CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
  CK_MECHANISM_TYPE   DigestMechanism;
  CK_WTLS_RANDOM_DATA RandomInfo;
  CK_BYTE_PTR         pVersion;
}

alias CK_WTLS_MASTER_KEY_DERIVE_PARAMS *  CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR;

struct CK_WTLS_PRF_PARAMS {
  CK_MECHANISM_TYPE DigestMechanism;
  CK_BYTE_PTR       pSeed;
  CK_ULONG          ulSeedLen;
  CK_BYTE_PTR       pLabel;
  CK_ULONG          ulLabelLen;
  CK_BYTE_PTR       pOutput;
  CK_ULONG_PTR      pulOutputLen;
}

alias CK_WTLS_PRF_PARAMS * CK_WTLS_PRF_PARAMS_PTR;

struct CK_WTLS_KEY_MAT_OUT {
  CK_OBJECT_HANDLE hMacSecret;
  CK_OBJECT_HANDLE hKey;
  CK_BYTE_PTR      pIV;
}

alias CK_WTLS_KEY_MAT_OUT * CK_WTLS_KEY_MAT_OUT_PTR;

struct CK_WTLS_KEY_MAT_PARAMS {
  CK_MECHANISM_TYPE       DigestMechanism;
  CK_ULONG                ulMacSizeInBits;
  CK_ULONG                ulKeySizeInBits;
  CK_ULONG                ulIVSizeInBits;
  CK_ULONG                ulSequenceNumber;
  CK_BBOOL                bIsExport;
  CK_WTLS_RANDOM_DATA     RandomInfo;
  CK_WTLS_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
}

alias CK_WTLS_KEY_MAT_PARAMS * CK_WTLS_KEY_MAT_PARAMS_PTR;

struct CK_CMS_SIG_PARAMS {
  CK_OBJECT_HANDLE      certificateHandle;
  CK_MECHANISM_PTR      pSigningMechanism;
  CK_MECHANISM_PTR      pDigestMechanism;
  CK_UTF8CHAR_PTR       pContentType;
  CK_BYTE_PTR           pRequestedAttributes;
  CK_ULONG              ulRequestedAttributesLen;
  CK_BYTE_PTR           pRequiredAttributes;
  CK_ULONG              ulRequiredAttributesLen;
}

alias CK_CMS_SIG_PARAMS * CK_CMS_SIG_PARAMS_PTR;

struct CK_KEY_DERIVATION_STRING_DATA {
  CK_BYTE_PTR pData;
  CK_ULONG    ulLen;
}

alias CK_KEY_DERIVATION_STRING_DATA *  CK_KEY_DERIVATION_STRING_DATA_PTR;


/* The CK_EXTRACT_PARAMS is used for the
 * CKM_EXTRACT_KEY_FROM_KEY mechanism.  It specifies which bit
 * of the base key should be used as the first bit of the
 * derived key
 */
alias CK_ULONG CK_EXTRACT_PARAMS;

alias CK_EXTRACT_PARAMS * CK_EXTRACT_PARAMS_PTR;

/* CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE is used to
 * indicate the Pseudo-Random Function (PRF) used to generate
 * key bits using PKCS #5 PBKDF2.
 */
alias CK_ULONG CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE;

alias CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE *  CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR;

enum CKP_PKCS5_PBKD2_HMAC_SHA1          = 0x00000001UL;
enum CKP_PKCS5_PBKD2_HMAC_GOSTR3411     = 0x00000002UL;
enum CKP_PKCS5_PBKD2_HMAC_SHA224        = 0x00000003UL;
enum CKP_PKCS5_PBKD2_HMAC_SHA256        = 0x00000004UL;
enum CKP_PKCS5_PBKD2_HMAC_SHA384        = 0x00000005UL;
enum CKP_PKCS5_PBKD2_HMAC_SHA512        = 0x00000006UL;
enum CKP_PKCS5_PBKD2_HMAC_SHA512_224    = 0x00000007UL;
enum CKP_PKCS5_PBKD2_HMAC_SHA512_256    = 0x00000008UL;

/* CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE is used to indicate the
 * source of the salt value when deriving a key using PKCS #5
 * PBKDF2.
 */
alias CK_ULONG CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE;

alias CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE *  CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR;

/* The following salt value sources are defined in PKCS #5 v2.0. */
enum CKZ_SALT_SPECIFIED        = 0x00000001UL;

/* CK_PKCS5_PBKD2_PARAMS is a structure that provides the
 * parameters to the CKM_PKCS5_PBKD2 mechanism.
 */
struct CK_PKCS5_PBKD2_PARAMS {
        CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE           saltSource;
        CK_VOID_PTR                                pSaltSourceData;
        CK_ULONG                                   ulSaltSourceDataLen;
        CK_ULONG                                   iterations;
        CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE prf;
        CK_VOID_PTR                                pPrfData;
        CK_ULONG                                   ulPrfDataLen;
        CK_UTF8CHAR_PTR                            pPassword;
        CK_ULONG_PTR                               ulPasswordLen;
}

alias CK_PKCS5_PBKD2_PARAMS * CK_PKCS5_PBKD2_PARAMS_PTR;

/* CK_PKCS5_PBKD2_PARAMS2 is a corrected version of the CK_PKCS5_PBKD2_PARAMS
 * structure that provides the parameters to the CKM_PKCS5_PBKD2 mechanism
 * noting that the ulPasswordLen field is a CK_ULONG and not a CK_ULONG_PTR.
 */
struct CK_PKCS5_PBKD2_PARAMS2 {
        CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE saltSource;
        CK_VOID_PTR pSaltSourceData;
        CK_ULONG ulSaltSourceDataLen;
        CK_ULONG iterations;
        CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE prf;
        CK_VOID_PTR pPrfData;
        CK_ULONG ulPrfDataLen;
        CK_UTF8CHAR_PTR pPassword;
        CK_ULONG ulPasswordLen;
}

alias CK_PKCS5_PBKD2_PARAMS2 * CK_PKCS5_PBKD2_PARAMS2_PTR;

alias CK_ULONG CK_OTP_PARAM_TYPE;
alias CK_OTP_PARAM_TYPE CK_PARAM_TYPE; /* backward compatibility */

struct CK_OTP_PARAM {
    CK_OTP_PARAM_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
}

alias CK_OTP_PARAM * CK_OTP_PARAM_PTR;

struct CK_OTP_PARAMS {
    CK_OTP_PARAM_PTR pParams;
    CK_ULONG ulCount;
}

alias CK_OTP_PARAMS * CK_OTP_PARAMS_PTR;

struct CK_OTP_SIGNATURE_INFO {
    CK_OTP_PARAM_PTR pParams;
    CK_ULONG ulCount;
}

alias CK_OTP_SIGNATURE_INFO * CK_OTP_SIGNATURE_INFO_PTR;

enum CK_OTP_VALUE          = 0UL;
enum CK_OTP_PIN            = 1UL;
enum CK_OTP_CHALLENGE      = 2UL;
enum CK_OTP_TIME           = 3UL;
enum CK_OTP_COUNTER        = 4UL;
enum CK_OTP_FLAGS          = 5UL;
enum CK_OTP_OUTPUT_LENGTH  = 6UL;
enum CK_OTP_OUTPUT_FORMAT  = 7UL;

enum CKF_NEXT_OTP          = 0x00000001UL;
enum CKF_EXCLUDE_TIME      = 0x00000002UL;
enum CKF_EXCLUDE_COUNTER   = 0x00000004UL;
enum CKF_EXCLUDE_CHALLENGE = 0x00000008UL;
enum CKF_EXCLUDE_PIN       = 0x00000010UL;
enum CKF_USER_FRIENDLY_OTP = 0x00000020UL;

struct CK_KIP_PARAMS {
    CK_MECHANISM_PTR  pMechanism;
    CK_OBJECT_HANDLE  hKey;
    CK_BYTE_PTR       pSeed;
    CK_ULONG          ulSeedLen;
}

alias CK_KIP_PARAMS * CK_KIP_PARAMS_PTR;

struct CK_AES_CTR_PARAMS {
    CK_ULONG     ulCounterBits;
    CK_BYTE[16]  cb;
}

alias CK_AES_CTR_PARAMS * CK_AES_CTR_PARAMS_PTR;

struct CK_GCM_PARAMS {
    CK_BYTE_PTR       pIv;
    CK_ULONG          ulIvLen;
    CK_ULONG          ulIvBits;
    CK_BYTE_PTR       pAAD;
    CK_ULONG          ulAADLen;
    CK_ULONG          ulTagBits;
}

alias CK_GCM_PARAMS * CK_GCM_PARAMS_PTR;

struct CK_CCM_PARAMS {
    CK_ULONG          ulDataLen;
    CK_BYTE_PTR       pNonce;
    CK_ULONG          ulNonceLen;
    CK_BYTE_PTR       pAAD;
    CK_ULONG          ulAADLen;
    CK_ULONG          ulMACLen;
}

alias CK_CCM_PARAMS * CK_CCM_PARAMS_PTR;

/* Deprecated. Use CK_GCM_PARAMS */
struct CK_AES_GCM_PARAMS {
  CK_BYTE_PTR pIv;
  CK_ULONG ulIvLen;
  CK_ULONG ulIvBits;
  CK_BYTE_PTR pAAD;
  CK_ULONG ulAADLen;
  CK_ULONG ulTagBits;
}

alias CK_AES_GCM_PARAMS * CK_AES_GCM_PARAMS_PTR;

/* Deprecated. Use CK_CCM_PARAMS */
struct CK_AES_CCM_PARAMS {
    CK_ULONG          ulDataLen;
    CK_BYTE_PTR       pNonce;
    CK_ULONG          ulNonceLen;
    CK_BYTE_PTR       pAAD;
    CK_ULONG          ulAADLen;
    CK_ULONG          ulMACLen;
}

alias CK_AES_CCM_PARAMS * CK_AES_CCM_PARAMS_PTR;

struct CK_CAMELLIA_CTR_PARAMS {
    CK_ULONG          ulCounterBits;
    CK_BYTE[16]       cb;
}

alias CK_CAMELLIA_CTR_PARAMS * CK_CAMELLIA_CTR_PARAMS_PTR;

struct CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS {
    CK_BYTE[16]       iv;
    CK_BYTE_PTR       pData;
    CK_ULONG          length;
}

alias CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS *  CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_PTR;

struct CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
    CK_BYTE[16]       iv;
    CK_BYTE_PTR       pData;
    CK_ULONG          length;
}

alias CK_ARIA_CBC_ENCRYPT_DATA_PARAMS *  CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_PTR;

struct CK_DSA_PARAMETER_GEN_PARAM {
    CK_MECHANISM_TYPE  hash;
    CK_BYTE_PTR        pSeed;
    CK_ULONG           ulSeedLen;
    CK_ULONG           ulIndex;
}

alias CK_DSA_PARAMETER_GEN_PARAM * CK_DSA_PARAMETER_GEN_PARAM_PTR;

struct CK_ECDH_AES_KEY_WRAP_PARAMS {
    CK_ULONG           ulAESKeyBits;
    CK_EC_KDF_TYPE     kdf;
    CK_ULONG           ulSharedDataLen;
    CK_BYTE_PTR        pSharedData;
}

alias CK_ECDH_AES_KEY_WRAP_PARAMS * CK_ECDH_AES_KEY_WRAP_PARAMS_PTR;

alias CK_ULONG CK_JAVA_MIDP_SECURITY_DOMAIN;

alias CK_ULONG CK_CERTIFICATE_CATEGORY;

struct CK_RSA_AES_KEY_WRAP_PARAMS {
    CK_ULONG                      ulAESKeyBits;
    CK_RSA_PKCS_OAEP_PARAMS_PTR   pOAEPParams;
}

alias CK_RSA_AES_KEY_WRAP_PARAMS * CK_RSA_AES_KEY_WRAP_PARAMS_PTR;

struct CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
    CK_SSL3_RANDOM_DATA       RandomInfo;
    CK_VERSION_PTR            pVersion;
    CK_MECHANISM_TYPE         prfHashMechanism;
}

alias CK_TLS12_MASTER_KEY_DERIVE_PARAMS *  CK_TLS12_MASTER_KEY_DERIVE_PARAMS_PTR;

struct CK_TLS12_KEY_MAT_PARAMS {
    CK_ULONG                  ulMacSizeInBits;
    CK_ULONG                  ulKeySizeInBits;
    CK_ULONG                  ulIVSizeInBits;
    CK_BBOOL                  bIsExport;
    CK_SSL3_RANDOM_DATA       RandomInfo;
    CK_SSL3_KEY_MAT_OUT_PTR   pReturnedKeyMaterial;
    CK_MECHANISM_TYPE         prfHashMechanism;
}

alias CK_TLS12_KEY_MAT_PARAMS * CK_TLS12_KEY_MAT_PARAMS_PTR;

struct CK_TLS_KDF_PARAMS {
    CK_MECHANISM_TYPE         prfMechanism;
    CK_BYTE_PTR               pLabel;
    CK_ULONG                  ulLabelLength;
    CK_SSL3_RANDOM_DATA       RandomInfo;
    CK_BYTE_PTR               pContextData;
    CK_ULONG                  ulContextDataLength;
}

alias CK_TLS_KDF_PARAMS * CK_TLS_KDF_PARAMS_PTR;

struct CK_TLS_MAC_PARAMS {
    CK_MECHANISM_TYPE         prfHashMechanism;
    CK_ULONG                  ulMacLength;
    CK_ULONG                  ulServerOrClient;
}

alias CK_TLS_MAC_PARAMS * CK_TLS_MAC_PARAMS_PTR;

struct CK_GOSTR3410_DERIVE_PARAMS {
    CK_EC_KDF_TYPE            kdf;
    CK_BYTE_PTR               pPublicData;
    CK_ULONG                  ulPublicDataLen;
    CK_BYTE_PTR               pUKM;
    CK_ULONG                  ulUKMLen;
}

alias CK_GOSTR3410_DERIVE_PARAMS * CK_GOSTR3410_DERIVE_PARAMS_PTR;

struct CK_GOSTR3410_KEY_WRAP_PARAMS {
    CK_BYTE_PTR               pWrapOID;
    CK_ULONG                  ulWrapOIDLen;
    CK_BYTE_PTR               pUKM;
    CK_ULONG                  ulUKMLen;
    CK_OBJECT_HANDLE          hKey;
}

alias CK_GOSTR3410_KEY_WRAP_PARAMS * CK_GOSTR3410_KEY_WRAP_PARAMS_PTR;

struct CK_SEED_CBC_ENCRYPT_DATA_PARAMS {
    CK_BYTE[16]               iv;
    CK_BYTE_PTR               pData;
    CK_ULONG                  length;
}

alias CK_SEED_CBC_ENCRYPT_DATA_PARAMS *  CK_SEED_CBC_ENCRYPT_DATA_PARAMS_PTR;

struct CK_FUNCTION_LIST {
	version (Windows) {
		align(1) :
		CK_VERSION  version_;  /* Cryptoki version */
		mixin CK_FUNCTION_LIST_FENTRIES;
	}
	else {
		CK_VERSION  version_;  /* Cryptoki version */
		mixin CK_FUNCTION_LIST_FENTRIES;
	}
}
