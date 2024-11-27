/*-
 * @file   cmpClient.c
 * @brief  generic CMP client library demo/test client
 *
 * @author David von Oheimb, Siemens AG, David.von.Oheimb@siemens.com
 *
 *  Copyright 2007-2021 The OpenSSL Project Authors. All Rights Reserved.
 *  Copyright Nokia 2007-2019
 *  Copyright (c) 2015-2023 Siemens AG
 *
 *  Licensed under the Apache License 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You can obtain a copy in the file LICENSE in the source distribution
 *  or at https://www.openssl.org/source/license.html
 *  SPDX-License-Identifier: Apache-2.0
 */

#include <genericCMPClient.h>

#include <openssl/ssl.h>

#include <secutils/config/config.h>
#include <secutils/credentials/cert.h>
#include <secutils/credentials/verify.h>
#include <secutils/certstatus/crl_mgmt.h> /* for CRLMGMT_load_crl_cb */

#ifdef LOCAL_DEFS
# include "genericCMPClient_use.h"
#endif

#include <unistd.h> 

/*
 * Use cases are split between CMP use cases and others,
 * which do not use CMP and therefore do not need its complex setup.
 */
enum use_case { no_use_case,
                /* CMP use cases: */
                imprint, bootstrap, pkcs10, update,
                revocation /* 'revoke' already defined in unistd.h */, genm,
                default_case,
                /* Non-CMP use cases: */
                validate
};

#define RSA_SPEC "RSA:2048"
#define ECC_SPEC "EC:prime256v1"

#define CONFIG_DEFAULT "config/demo.cnf"
#define CONFIG_TEST "test_config.cnf" /* from OpenSSL test suite */

char *opt_config = CONFIG_DEFAULT; /* OpenSSL-style configuration file */
CONF *config = NULL; /* OpenSSL configuration structure */
char *opt_section = "EJBCA"; /* name(s) of config file section(s) to use */
#define DEFAULT_SECTION "default"
#define SECTION_NAME_MAX 40
char demo_sections[2 * (SECTION_NAME_MAX + 1)]; /* used for pattern "%s,%s" */
long opt_verbosity;

#define STR_OR_NONE(s) (s != NULL ? s : "(none)")
/* message transfer */
const char *opt_server;
const char *opt_proxy;
const char *opt_no_proxy;
const char *opt_path;
const char *opt_cdp_proxy;
const char *opt_crl_cache_dir;

long opt_keep_alive;
long opt_msg_timeout;
long opt_total_timeout;

/* server authentication */
const char *opt_trusted;
const char *opt_untrusted;
const char *opt_srvcert;
const char *opt_recipient;
const char *opt_expect_sender;
bool opt_ignore_keyusage;
bool opt_unprotected_errors;
#if OPENSSL_VERSION_NUMBER >= 0x30300000L || defined USE_LIBCMP
bool opt_no_cache_extracerts;
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30200000L || defined USE_LIBCMP
const char *opt_srvcertout;
#endif
const char *opt_extracertsout;
const char *opt_extracerts_dir;
const char *opt_extracerts_dir_format;
const char *opt_cacertsout;
const char *opt_cacerts_dir;
const char *opt_cacerts_dir_format;
const char *opt_oldwithold;
const char *opt_newwithnew;
const char *opt_newwithold;
const char *opt_oldwithnew;
const char *opt_template;
const char *opt_oldcrl;
const char *opt_crlout;

/* client authentication */
const char *opt_ref;
const char *opt_secret;
/* maybe it would be worth re-adding a -creds option combining -cert and -key */
const char *opt_cert;
const char *opt_own_trusted;
const char *opt_key;
const char *opt_keypass;
const char *opt_digest;
const char *opt_mac;
const char *opt_extracerts;
bool opt_unprotected_requests;

/* generic message */
const char *opt_cmd;
const char *opt_infotype;
static int infotype = NID_undef;
const char *opt_profile;
char *opt_geninfo;

/* certificate enrollment */
const char *opt_newkeytype;
bool opt_centralkeygen;
const char *opt_newkey;
const char *opt_newkeypass;
const char *opt_subject;
long opt_days;
const char *opt_reqexts;
char *opt_sans;
bool opt_san_nodefault;
const char *opt_policies;
char *opt_policy_oids;
bool opt_policy_oids_critical;
long opt_popo;
const char *opt_csr;
const char *opt_out_trusted;
bool opt_implicit_confirm;
bool opt_disable_confirm;
const char *opt_certout;
const char *opt_chainout;

/* certificate enrollment and revocation */
const char *opt_oldcert;
long opt_revreason;
const char *opt_issuer;
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
char *opt_serial;
#endif

/* TODO? add credentials format options */
/* TODO add opt_engine */

/* TLS connection */
bool opt_tls_used;
/* TODO re-add tls_creds */
const char *opt_tls_cert;
const char *opt_tls_key;
const char *opt_tls_keypass;
const char *opt_tls_extra;
const char *opt_tls_trusted;
const char *opt_tls_host;

/* client-side debugging */
static char *opt_reqin = NULL;
static bool opt_reqin_new_tid = 0;
static char *opt_reqout = NULL;
static char *opt_rspin = NULL;
static char *opt_rspout = NULL;

/* TODO further extend verification options and align with OpenSSL:apps/cmp.c */
bool opt_check_all;
bool opt_check_any;
const char *opt_crls;
bool opt_use_cdp;
const char *opt_cdps;
long opt_crls_timeout;
size_t opt_crl_maxdownload_size;
bool opt_use_aia;
const char *opt_ocsp;
long opt_ocsp_timeout;
bool opt_ocsp_last;
bool opt_stapling;

X509_VERIFY_PARAM *vpm = NULL;
CRLMGMT_DATA *cmdata = NULL;
STACK_OF(X509_CRL) *crls = NULL;

opt_t cmp_opts[] = {
    { "help", OPT_BOOL, {.num = -1}, { NULL },
      "Display this summary"},
    { "config", OPT_TXT, {.txt = NULL}, { NULL },
      "Configuration file to use. \"\" means none. Default 'config/demo.cnf'"},
    { "section", OPT_TXT, {.txt = NULL}, { NULL },
      "Section(s) in config file to use. \"\" means 'default'. Default 'EJBCA'"},
    { "verbosity", OPT_NUM, {.num = LOG_INFO}, {(const char **) &opt_verbosity},
      "Logging level; 3=ERR, 4=WARN, 6=INFO, 7=DEBUG, 8=TRACE. Default 6 = INFO"},

    OPT_HEADER("Generic message"),
    { "cmd", OPT_TXT, {.txt = NULL}, { &opt_cmd },
      "CMP request to send: ir/cr/p10cr/kur/rr/genm. Overrides 'use_case' if given"},
    { "infotype", OPT_TXT, {.txt = NULL}, { &opt_infotype },
      "InfoType name for requesting specific info in genm, "
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
      "with specific support"
#else
      "e.g., C<signKeyPairTypes>"
#endif
    },
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
    OPT_MORE("for 'caCerts' and 'rootCaCert'"),
#endif
#if OPENSSL_VERSION_NUMBER > 0x30300000L || defined USE_LIBCMP
    OPT_MORE("for 'caCerts', 'rootCaCert', 'certReqTemplate', and 'crlStatusList'"),
#endif
    { "profile", OPT_TXT, {.txt = NULL}, { &opt_profile },
      "Cert profile name to place in generalInfo field of PKIHeader of requests"},
    { "geninfo", OPT_TXT, {.txt = NULL}, { (const char **)&opt_geninfo },
      "Comma-separated list of OID and value to place in generalInfo PKIHeader"},
    OPT_MORE("of form <OID>:int:<n> or <OID>:str:<s>, e.g. \'1.2.3.4:int:56789, id-kp:str:name'"),
    { "template", OPT_TXT, {.txt = NULL}, { &opt_template },
      "File to save certTemplate received in genp of type certReqTemplate"},

    OPT_HEADER("Certificate enrollment"),
    { "newkeytype", OPT_TXT, {.txt = NULL}, { &opt_newkeytype },
      "Generate or request key for ir/cr/kur of given type, e.g., EC:secp521r1"},
    { "centralkeygen", OPT_BOOL, {.bit = false},
      { (const char **) &opt_centralkeygen},
      "Request central (server-side) key generation. Default is local generation"},
    { "newkey", OPT_TXT, {.txt = NULL}, { &opt_newkey },
      "Private or public key for for ir/cr/kur (defaulting to pubkey of -csr) if -newkeytype not given."},
    OPT_MORE("File to save new key if -newkeytype is given"),
    { "newkeypass", OPT_TXT, {.txt = NULL}, { &opt_newkeypass },
      "Pass phrase source for -newkey"},
    { "subject", OPT_TXT, {.txt = NULL}, { &opt_subject },
      "Distinguished Name (DN) of subject to use in the requested cert template"},
    OPT_MORE("For kur, default is subject of -csr arg, else subject of -oldcert"),
    { "days", OPT_NUM, {.num = 0}, { (const char **) &opt_days },
      "Requested validity time of new cert in number of days"},
    { "reqexts", OPT_TXT, {.txt = NULL}, { &opt_reqexts },
      "Name of config file section defining certificate request extensions"},
    OPT_MORE("Augments or replaces any extensions contained CSR given with -csr"),
    { "sans", OPT_TXT, {.txt = NULL}, { (const char **) &opt_sans },
      "Subject Alt Names (IPADDR/DNS/URI) to add as (critical) cert req extension"},
    { "san_nodefault", OPT_BOOL, {.bit = false},
      { (const char **) &opt_san_nodefault},
      "Do not take default SANs from reference certificate (see -oldcert)"},
    { "policies", OPT_TXT, {.txt = NULL}, { &opt_policies},
      "Name of config file section defining policies request extension"},
    { "policy_oids", OPT_TXT, {.txt = NULL}, {(const char **) &opt_policy_oids},
      "Policy OID(s) to add as certificate policies request extension"},
    { "policy_oids_critical", OPT_BOOL, {.bit = false},
      { (const char **) &opt_policy_oids_critical},
      "Flag the policy OID(s) given with -policies_ as critical"},
    { "popo", OPT_NUM, {.num = OSSL_CRMF_POPO_NONE - 1},
      { (const char **) &opt_popo },
      "Proof-of-Possession (POPO) method to use for ir/cr/kur where"},
    OPT_MORE("-1 = NONE, 0 = RAVERIFIED, 1 = SIGNATURE (default), 2 = KEYENC"),
    { "csr", OPT_TXT, {.txt = NULL}, { &opt_csr },
      "CSR file in PKCS#10 format to convert or to use in p10cr"},
    { "out_trusted", OPT_TXT, {.txt = NULL}, { &opt_out_trusted },
      "Certs to trust when validating newly enrolled certs; defaults to -srvcert"},
    { "implicit_confirm", OPT_BOOL, {.bit = false},
      { (const char **) &opt_implicit_confirm },
      "Request implicit confirmation of newly enrolled certificates"},
    { "disable_confirm", OPT_BOOL, {.bit = false},
      { (const char **) &opt_disable_confirm },
      "Do not confirm newly enrolled certificates w/o requesting implicit confirm"},
    { "certout", OPT_TXT, {.txt = NULL}, { &opt_certout },
      "File to save newly enrolled certificate, possibly with chain and key"},
    { "chainout", OPT_TXT, {.txt = NULL}, { &opt_chainout },
      "File to save the chain of the newly enrolled certificate"},

    OPT_HEADER("Certificate enrollment and revocation"),
    { "oldcert", OPT_TXT, {.txt = NULL}, { &opt_oldcert },
      "Certificate to be updated (defaulting to -cert) or to be revoked in rr;"},
    OPT_MORE("also used as reference (defaulting to -cert) for subject DN and SANs."),
    OPT_MORE("Its issuer used as recipient unless -srvcert, -recipient or -issuer given"),
    OPT_MORE("It is also used for CRLSource data in genm of type crlStatusList"),
    { "revreason", OPT_NUM, {.num = CRL_REASON_NONE},
      { (const char **) &opt_revreason },
      "Reason code to include in revocation request (rr)."},
    OPT_MORE("Values: 0..6, 8..10 (see RFC5280, 5.3.1) or -1. Default -1 = none included"),
    { "issuer", OPT_TXT, {.txt = NULL}, { &opt_issuer },
      "DN of the issuer to place in the certificate template of ir/cr/kur"
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
      "/rr"
#else
      ""
#endif
      ";"},
    OPT_MORE("also used as recipient if neither -recipient nor -srvcert are given"),
#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
    { "serial", OPT_TXT, {.txt = NULL}, {(const char **) &opt_serial},
      "Serial number of certificate to be revoked in revocation request (rr)"},
#endif
    /* Note: Lightweight CMP Profile SimpleLra does not allow CRL_REASON_NONE */

    /* TODO? OPT_HEADER("Credentials format"), */
    /* TODO add opt_engine */

    OPT_HEADER("Message transfer"),
    { "server", OPT_TXT, {.txt = NULL}, { &opt_server },
      "[http[s]://]host[:port][/path] of CMP server. Default port 80 or 443."},
    OPT_MORE("host may be a DNS name or an IP address; path can be overridden by -path"),
    { "proxy", OPT_TXT, {.txt = NULL}, { &opt_proxy },
      "[http[s]://]host[:port][/p] of proxy. Default port 80 or 443; p ignored."},
    OPT_MORE("Default from environment variable 'http_proxy', else 'HTTP_PROXY'"),
    { "no_proxy", OPT_TXT, {.txt = NULL}, { &opt_no_proxy },
      "List of addresses of servers not use HTTP(S) proxy for."},
    OPT_MORE("Default from environment variable 'no_proxy', else 'NO_PROXY', else none"),

    { "recipient", OPT_TXT, {.txt = NULL}, { &opt_recipient },
      "DN of CA. Default: -srvcert subject, -issuer, issuer of -oldcert or -cert,"},
    OPT_MORE("subject of the first -untrusted cert if any, or else the NULL-DN"),
    { "path", OPT_TXT, {.txt = NULL}, { &opt_path },
      "HTTP path (aka CMP alias) at the CMP server.  Default from -server, else \"/\""},
    {"keep_alive", OPT_NUM, {.num = 1 }, { (const char **)&opt_keep_alive },
     "Persistent HTTP connections. 0: no, 1 (the default): request, 2: require"},
    { "msg_timeout", OPT_NUM, {.num = 120}, { (const char **)&opt_msg_timeout },
      "Timeout per CMP message round trip (or 0 for none). Default 120 seconds"},
    { "total_timeout", OPT_NUM, {.num = 0}, {(const char **)&opt_total_timeout},
      "Overall time an enrollment incl. polling may take. Default: 0 = infinite"},

    OPT_HEADER("Server authentication"),
    { "trusted", OPT_TXT, {.txt = NULL}, { &opt_trusted },
      "Certificates to use as trust anchors when validating signed CMP responses"},
    { "untrusted", OPT_TXT, {.txt = NULL}, { &opt_untrusted },
      "Intermediate CA certs for chain construction for CMP/TLS/enrolled certs"},
    { "srvcert", OPT_TXT, {.txt = NULL}, { &opt_srvcert },
      "Server cert to pin and trust directly when validating signed CMP responses"},
    { "expect_sender", OPT_TXT, {.txt = NULL}, { &opt_expect_sender },
      "DN of expected sender of responses. Defaults to subject of -srvcert, if any"},
    { "ignore_keyusage", OPT_BOOL, {.bit = false},
      { (const char **)&opt_ignore_keyusage },
      "Ignore CMP signer cert key usage, else 'digitalSignature' must be allowed"},
    { "unprotected_errors", OPT_BOOL, {.bit = false},
      { (const char **) &opt_unprotected_errors },
      "Accept missing or invalid protection of regular error messages and negative"},
    OPT_MORE("certificate responses (ip/cp/kup), revocation responses (rp), and PKIConf"),
#if OPENSSL_VERSION_NUMBER >= 0x30300000L || defined USE_LIBCMP
    { "no_cache_extracerts", OPT_BOOL, {.bit = false},
      { (const char **) &opt_no_cache_extracerts },
      "Do not keep certificates received in the extraCerts CMP message field"},
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30200000L || defined USE_LIBCMP
    { "srvcertout", OPT_TXT, {.txt = NULL}, { &opt_srvcertout },
      "File to save server cert used and validated for CMP response protection"},
#endif
    { "extracertsout", OPT_TXT, {.txt = NULL}, { &opt_extracertsout },
      "File to save extra certificates received in the extraCerts field"},
    { "extracerts_dir", OPT_TXT, {.txt = NULL}, { &opt_extracerts_dir },
      "Path to save not self-issued extra certs received in the extraCerts field"},
    { "extracerts_dir_format", OPT_TXT, {.txt = "pem"},
      { &opt_extracerts_dir_format },
      "Format to use for saving those certs. Default \"pem\""},
    { "cacertsout", OPT_TXT, {.txt = NULL}, { &opt_cacertsout },
      "File to save certificates received in caPubs field or genp of type caCerts"},
    { "cacerts_dir", OPT_TXT, {.txt = NULL}, { &opt_cacerts_dir },
      "Path to save self-issued CA certs received in the caPubs field"},
    { "cacerts_dir_format", OPT_TXT, {.txt = "pem"},
      { &opt_cacerts_dir_format },
      "Format to use for saving those certs. Default \"pem\""},
    { "oldwithold", OPT_TXT, {.txt = NULL}, { &opt_oldwithold },
      "Root CA certificate to request update for in genm of type rootCaCert"},
    { "newwithnew", OPT_TXT, {.txt = NULL}, { &opt_newwithnew },
      "File to save NewWithNew cert received in genp of type rootCaKeyUpdate"},
    { "newwithold", OPT_TXT, {.txt = NULL}, { &opt_newwithold },
      "File to save NewWithOld cert received in genp of type rootCaKeyUpdate"},
    { "oldwithnew", OPT_TXT, {.txt = NULL}, { &opt_oldwithnew },
      "File to save OldWithNew cert received in genp of type rootCaKeyUpdate"},
    { "oldcrl", OPT_TXT, {.txt = NULL}, { &opt_oldcrl },
      "CRL to request update for in genm of type crlStatusList"},
    { "crlout", OPT_TXT, {.txt = NULL}, { &opt_crlout },
      "File to save new CRL received in genp of type 'crls'"},

    OPT_HEADER("Client authentication and protection"),
    { "ref", OPT_TXT, {.txt = NULL}, { &opt_ref },
      "Reference value to use as senderKID in case no -cert is given"},
    { "secret", OPT_TXT, {.txt = NULL}, { &opt_secret },
      "Source of secret value for authentication with a pre-shared key (PBM)"},
    { "cert", OPT_TXT, {.txt = NULL}, { &opt_cert },
      "Client cert (plus any extra one), needed unless using -secret for PBM."},
    OPT_MORE("This also used as default reference for subject DN and SANs."),
    OPT_MORE("Any further certs included are appended to the untrusted certs"),
    { "own_trusted", OPT_TXT, {.txt = NULL}, { &opt_own_trusted },
      "Optional certs to validate chain building for own CMP signer cert"},
    { "key", OPT_TXT, {.txt = NULL}, { &opt_key },
      "Key for the client certificate to use for protecting requests"},
    { "keypass", OPT_TXT, {.txt = NULL}, { &opt_keypass },
      "Pass phrase source for the client -key, -cert, and -oldcert"},
    { "digest", OPT_TXT, {.txt = NULL}, { &opt_digest },
      "Digest alg to use in msg protection and POPO signatures. Default \"sha256\""},
    OPT_MORE("See the man page or online doc for hints on available algorithms"),
    { "mac", OPT_TXT, {.txt = NULL}, { &opt_mac},
      "MAC algorithm to use in PBM-based message protection. Default \"hmac-sha1\""},
    OPT_MORE("See the man page or online doc for hints on available algorithms"),
    { "extracerts", OPT_TXT, {.txt = NULL}, { &opt_extracerts },
      "File(s) with certificates to append in extraCerts field of outgoing messages."},
    OPT_MORE("This can be used as the default CMP signer cert chain to include"),
    { "unprotected_requests", OPT_BOOL, {.bit = false},
      { (const char **) &opt_unprotected_requests },
      "Send request messages without CMP-level protection"},

    OPT_HEADER("TLS connection"),
    { "tls_used", OPT_BOOL, {.bit = false}, { (const char **) &opt_tls_used },
      "Enable using TLS (also when other TLS options are not set)"},
    { "tls_cert", OPT_TXT, {.txt = NULL}, { &opt_tls_cert },
      "Client certificate (plus any extra certs) for TLS connection"},
    { "tls_key", OPT_TXT, {.txt = NULL}, { &opt_tls_key },
      "Client private key for TLS connection"},
    { "tls_keypass", OPT_TXT, {.txt = NULL}, { &opt_tls_keypass },
      "Client key and cert pass phrase source for TLS connection"},
    { "tls_extra", OPT_TXT, {.txt = NULL}, { &opt_tls_extra },
      "Extra certificates to provide to TLS server during TLS handshake"},
    { "tls_trusted", OPT_TXT, {.txt = NULL}, { &opt_tls_trusted },
      "File(s) with certs to trust for TLS server verification (TLS trust anchor)"},
    { "tls_host", OPT_TXT, {.txt = NULL}, { &opt_tls_host },
      "Address (rather than -server) to be checked during TLS hostname validation"},

    OPT_HEADER("Debugging"),
    {"reqin", OPT_TXT, {.txt = NULL}, { (const char **) &opt_reqin},
     "Take sequence of CMP requests to send to server from file(s)"},
    {"reqin_new_tid", OPT_BOOL, {.bit = false},
     { (const char **) &opt_reqin_new_tid},
     "Use fresh transactionID for CMP requests read from -reqin"},
    {"reqout", OPT_TXT, {.txt = NULL}, { (const char **) &opt_reqout},
     "Save sequence of CMP requests to file(s)"},
    {"rspin", OPT_TXT, {.txt = NULL}, { (const char **) &opt_rspin},
     "Process sequence of CMP responses provided in file(s), skipping server"},
    {"rspout", OPT_TXT, {.txt = NULL}, { (const char **) &opt_rspout},
     "Save sequence of CMP responses to file(s)"},

    OPT_HEADER("CMP and TLS certificate status checking"),
    /* TODO extend verification options and align with OpenSSL:apps/cmp.c */
    { "check_all", OPT_BOOL, {.bit = false}, { (const char **) &opt_check_all},
      "Check status not only for leaf certs but for all certs (except root)"},
    { "check_any", OPT_BOOL, {.bit = false}, { (const char **) &opt_check_any},
      "Check status for those certs (except root) that contain a CDP or AIA entry"},
    { "crls", OPT_TXT, {.txt = NULL}, {&opt_crls},
      "Enable CRL-based status checking and first use CRLs from given file/URL(s)"},
    { "use_cdp", OPT_BOOL, {.bit = false}, { (const char **) &opt_use_cdp },
      "Enable CRL-based status checking and enable using any CDP entries in certs"},
    { "cdps", OPT_TXT, {.txt = NULL}, {&opt_cdps},
      "Enable CRL-based status checking and use given URL(s) as fallback CDP"},
    { "cdp_proxy", OPT_TXT, {.txt = NULL}, { &opt_cdp_proxy },
      "URL of the proxy server to send CDP URLs or cert isser names to"},
    { "crl_cache_dir", OPT_TXT, {.txt = NULL}, { &opt_crl_cache_dir },
      "Directory where to cache CRLs downloaded during verification."},
    { "crls_timeout", OPT_NUM, {.num = -1}, {(const char **)&opt_crls_timeout },
      "Timeout for CRL fetching, or 0 for none, -1 for default: 10 seconds"},
    { "crl_maxdownload_size", OPT_NUM, {.num = 0},
      { (const char **)&opt_crl_maxdownload_size},
      "Maximum size of a CRL to be downloaded. Default: 0 = OpenSSL default = 100 kiB"},
    { "use_aia", OPT_BOOL, {.bit = false}, { (const char **) &opt_use_aia },
      "Enable OCSP-based status checking and enable using any AIA entries in certs"},
    { "ocsp", OPT_TXT, {.txt = NULL}, {&opt_ocsp},
      "Enable OCSP-based status checking and use given OCSP responder(s) as fallback"},
    { "ocsp_timeout", OPT_NUM, {.num = -1}, {(const char **)&opt_ocsp_timeout },
      "Timeout for getting OCSP responses, or 0 for none, -1 for default: 10 seconds"},
    { "ocsp_last", OPT_BOOL, {.bit = false}, { (const char **) &opt_ocsp_last },
      "Do OCSP-based status checks last (else before using CRLs downloaded from CDPs)"},
    { "stapling", OPT_BOOL, {.bit = false}, { (const char **) &opt_stapling },
      "Enable OCSP stapling for TLS; is tried before any other cert status checks"},

    OPT_V_OPTIONS, /* excludes "crl_check" and "crl_check_all" */

    OPT_END
};

static size_t get_cert_filename(const X509 *cert, const char *prefix,
                                const char *suffix,
                                char *buf, size_t buf_len)
{
    if (buf == NULL || buf_len == 0)
        return 0;

    int ret = UTIL_safe_string_copy(prefix, buf, buf_len, NULL);
    if (ret < 0)
        return 0;
    size_t len = (size_t)ret;
    if (buf_len > len + 1 && buf[len] != '/' && buf[len] != '\\') {
        buf[len] = '/'; /* add missing path name separator */
        buf[++len] = '\0';
    }

    char subject[256], *p;
    if (X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName,
                                  subject, sizeof(subject)) <= 0)
        return 0;
    ret = UTIL_safe_string_copy(subject, buf + len, buf_len - len, NULL);
    if (ret < 0)
        return 0;
    for (p = buf + len; *p != '\0'; p++)
        if (*p == ' ')
            *p = '_';
    len += (size_t)ret;
    if ((ret = UTIL_safe_string_copy("_", buf + len, buf_len - len, NULL)) < 0)
        return 0;
    len += (size_t)ret;

    unsigned char sha1[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    X509_digest(cert, EVP_sha1(), sha1, &size);
    size_t res = UTIL_bintohex(sha1, size, false, '-', 4,
                               buf + len, buf_len - len, NULL);
    if (res == 0)
        return 0;
    len += res;
    if ((ret = UTIL_safe_string_copy(".", buf + len, buf_len - len, NULL)) < 0)
        return 0;
    len += (size_t)ret;

    ret = UTIL_safe_string_copy(suffix, buf + len, buf_len - len, NULL);
    if (ret < 0)
        return 0;
    for (p = buf + len; *p != '\0'; p++)
        *p = (char)tolower(*p);
    len += (size_t)ret;
    return len;
}


static
CMP_err save_certs(STACK_OF(X509) *certs, const char *field, const char *desc,
                   const char *dir, const char *file, const char *format)
{
    char desc_certs[80];

    snprintf(desc_certs, sizeof(desc_certs), "%s certs", desc);
    LOG(FL_TRACE, "Extracted %s from %s", desc_certs, field);

    if (file != NULL) {
        if (CERTS_save(certs, file, desc_certs) < 0) {
            LOG(FL_ERR, "Failed to store %s from %s in %s",
                desc_certs, field, file);
            CERTS_free(certs);
            return -49;
        }
    }

    if (dir != NULL) {
        int i, n = sk_X509_num(certs);

        if (n <= 0)
            LOG(FL_INFO, "No %s certificate in %s to store in %s",
                desc, field, dir);
        for (i = 0; i < n; i++) {
            X509 *cert = sk_X509_value(certs, i);
            bool save_self_issued = strcmp(field, "caPubs") == 0;

            if ((X509_check_issued(cert, cert) == X509_V_OK)
                != save_self_issued) {
                LOG(FL_WARN, "%s cert #%d in %s is%s self-issued and not stored",
                    desc, i + 1, field, save_self_issued ? " not" : "");
            } else {
                char path[FILENAME_MAX];

                if (get_cert_filename(cert, dir, format, path, sizeof(path)) == 0
                    || !FILES_store_cert(cert, path, FILES_get_format(format),
                                         desc_certs)) {
                    LOG(FL_ERR, "Failed to store %s cert #%d from %s in %s",
                        desc, i + 1, field, dir);
                    CERTS_free(certs);
                    return -52;
                }
            }
        }
    }
    CERTS_free(certs);
    return CMP_OK;
}

static CMP_err save_credentials(CMP_CTX *ctx, CREDENTIALS *new_creds,
                                enum use_case use_case)
{
    CMP_err err = save_certs(OSSL_CMP_CTX_get1_extraCertsIn(ctx),
                             "extraCerts", "extra", "creds",
                             "creds/extracerts.pem", "pem");

    if (err != CMP_OK)
        return err;

    if (use_case == revocation || use_case == genm || use_case == validate)
        return CMP_OK;

    err = save_certs(OSSL_CMP_CTX_get1_caPubs(ctx), "caPubs", "CA",
                     "creds/trusted", "creds/cacerts.pem", "pem");
    if (err != CMP_OK)
        return err;

    opt_newkey = "creds/manufacturer.pem";
    opt_newkeytype = "rsa:4096";
    if (use_case != pkcs10 && opt_newkey != NULL
            && (opt_newkeytype != NULL || opt_centralkeygen)) {
        const char *new_desc = "newly enrolled certificate and related chain and key";

        if (opt_chainout != NULL)
            LOG_warn("-chainout option is ignored");

        if (!CREDENTIALS_save(new_creds, "creds/manufacturer.crt",
                              "creds/manufacturer.pem", "pass:12345", "newly enrolled certificate and related chain and key")) {
            LOG_err("Failed to save newly enrolled credentials");
            return CMP_R_STORE_CREDS; /* unused: -54 */
        }
    } else {
        X509 *cert = CREDENTIALS_get_cert(new_creds);
        STACK_OF(X509) *certs = CREDENTIALS_get_chain(new_creds);

        if (opt_chainout != NULL && strcmp(opt_chainout, opt_certout) != 0) {
            if (!CERT_save(cert, "creds/manufacturer.crt", "newly enrolled certificate")) {
                return CMP_R_STORE_CREDS;
            }
            if (opt_chainout != NULL &&
                CERTS_save(certs, opt_chainout,
                           "chain of newly enrolled certificate") < 0) {
                return CMP_R_STORE_CREDS;
            }
        } else {
            if (!FILES_store_credentials(NULL /* key */, cert, certs, NULL,
                                         "creds/manufacturer.crt", FORMAT_PEM, NULL,
                                         "newly enrolled certificate and chain"))
                return CMP_R_STORE_CREDS;
        }
    }
    return CMP_OK;
}

void print_usage(const char * prog) {
    printf("Usage: %s [-h] -c [ir|kur] [-m mac_string] [--sn serial_number_string]\n", prog);
    printf("Options:\n");
    printf("  -h                          Print helpt              (Optional)\n");
    printf("  -c [ir|kur]                 Command IR or KUR        (Required)\n");
    printf("  -m mac_string               MAC address string       (Optional, default: 00:08:DC:74:43:DA)\n");
    printf("  -s serial_number_string     Serial number string     (Optional, default: IPS-601-25GW-07196)\n");
}

void cmp_ir(OSSL_CMP_CTX *ctx, CREDENTIALS *new_creds, const EVP_PKEY *new_key, const char *subject, OPTIONAL const X509_EXTENSIONS *exts) {
    int err = CMPclient_imprint(ctx, &new_creds, new_key, subject, exts);
    if (err != CMP_OK) {
        LOG(FL_ERR, "Cannot send imprint");

        char error_string[256];
        ERR_error_string_n(err, error_string, sizeof(error_string));
        LOG(FL_ERR, "OpenSSL error: %s", error_string);
    } else {
        save_credentials(ctx, new_creds, imprint);
    }

    
    CREDENTIALS_free(new_creds);
    KEY_free(new_key);
}

void cmp_kur(OSSL_CMP_CTX *ctx, CREDENTIALS *new_creds, const EVP_PKEY *new_key) {
    X509 *oldcert = CERT_load("creds/manufacturer.crt", "pass:12345", "cert to be updated", -1 /* no type check */, vpm);

    if (oldcert == NULL || !OSSL_CMP_CTX_set1_oldCert(ctx, oldcert)) {
      LOG(FL_ERR, "Couldn't load oldcert");
      exit(-1);
    }

    int err = CMPclient_update_anycert(ctx, &new_creds, oldcert, new_key);
    if (err != CMP_OK) {
        LOG(FL_ERR, "Cannot send update");

        char error_string[256];
        ERR_error_string_n(err, error_string, sizeof(error_string));
        LOG(FL_ERR, "OpenSSL error: %s", error_string);
    } else {
        save_credentials(ctx, new_creds, update);
    }

    CREDENTIALS_free(new_creds);
    X509_free(oldcert);
    KEY_free(new_key);
}

int main(int argc, char *argv[])
{
  
    char *command = NULL;
    char *mac = "00:08:DC:74:43:DA"; // Default
    char *serial_number = "IPS-601-25GW-07196"; // Default
    CMP_CTX *ctx = NULL;
    int err = 0;

    X509_STORE *own_truststore = NULL;
    X509_STORE *cmp_truststore = NULL;
    CREDENTIALS *cmp_creds = NULL;
    EVP_PKEY *new_pkey = NULL;
    X509_EXTENSIONS *exts = NULL;
    SSL_CTX *tls = NULL;
    X509 *oldcert = NULL;
    CREDENTIALS *new_creds = NULL;
    X509_REQ *csr = NULL;
    CREDENTIALS *tls_creds = NULL;
    X509_STORE *tls_trust = NULL;
    char *cert = NULL;
    char *key = NULL;

    enum cmd {
      ir,
      kur,
      unknown
    };

    enum cmd current_cmd = unknown;
    enum use_case usecase = unknown;

    OPT_init(cmp_opts);

    int opt;
    while ((opt = getopt(argc, argv, "hc:m:s:")) != -1) {
      switch (opt) {
        case 'h':
          print_usage(argv[0]);
          return -1;
        case 'c':
          command = optarg;
          if (strcmp(command, "ir") == 0) {
            current_cmd = ir;
            opt_section = "CloudCA,imprint";
            usecase = imprint;
          } else if (strcmp(command, "kur") == 0) {
            current_cmd = kur;
            opt_section = "CloudCA,update";
            usecase = update;
          }
          break;
        case 'm':
          mac = optarg;
          break;
        case 's':
          serial_number = optarg;
          break;
      }
    }

    config = CONF_load_options(NULL, "config/demo.cnf", opt_section, cmp_opts);

    opt_path = "/.well-known/cmp/p/PPKI%20QA";

    LOG_set_verbosity((severity)LOG_INFO);

    if (current_cmd == unknown) {
      LOG(FL_ERR, "Unknown command");
      print_usage(argv[0]);
      return -1;
    }

    char subject[256]; // Only for PoC purposes, otherwise it shall be calculated

    if (current_cmd == ir) { 
        LOG(FL_INFO, "Using MAC: %s, Serial Number: %s", mac, serial_number);
        snprintf(subject, sizeof(subject), "/unstructuredAddress=%s/CN=Sensformer V1/serialNumber=%s/OU=Quality System - For Test purpose only/O=Siemens/C=DE", mac, serial_number);
        opt_subject = subject;

        LOG(FL_INFO, "Using subject: %s", subject);
    }

    // Setup client
    CMPclient_init("simpleCMP_PoC", NULL);

    vpm = X509_VERIFY_PARAM_new();
    cmdata = CRLMGMT_DATA_new();

    CONF_update_vpm(config, opt_section, vpm);

    CRLMGMT_DATA_set_proxy_url(cmdata, opt_cdp_proxy);
    CRLMGMT_DATA_set_crl_max_download_size(cmdata, opt_crl_maxdownload_size);
    CRLMGMT_DATA_set_crl_cache_dir(cmdata, opt_crl_cache_dir);
    CRLMGMT_DATA_set_note(cmdata, "tls or cmp connection or new certificate");

    STACK_OF(X509) *untrusted_certs = NULL;

    if ((cmp_creds = CREDENTIALS_load(opt_cert, opt_key, opt_keypass, "credentials for CMP level")) == NULL) {
        LOG(FL_ERR, "Unable to set up credentials");
    }

    if (current_cmd == ir) {
        char *secret = FILES_get_pass(opt_secret, "PBM-based message protection");

        (void)CREDENTIALS_set_pwd(cmp_creds, secret);
    }
    
    (void)CREDENTIALS_set_pwdref(cmp_creds, OPENSSL_strdup(opt_ref));

    own_truststore = STORE_load(opt_own_trusted, "trusted certs for validating own CMP signer cert", vpm);

    STORE_set_parameters(own_truststore, NULL /* vpm */, false, false, NULL, false, NULL, -1, false, NULL, -1);

    cmp_truststore = STORE_load(opt_trusted, "trusted certs for CMP level", NULL /* no vpm: prevent strict checking */);

    STORE_set_parameters(cmp_truststore, vpm, opt_check_all, false /* stapling */, crls, opt_use_cdp, opt_cdps, (int)opt_crls_timeout, opt_use_aia, opt_ocsp, (int)opt_ocsp_timeout); //||

    err = CMPclient_prepare(&ctx, NULL /* libctx */, NULL /* propq */, LOG_console,
                            cmp_truststore, opt_recipient,
                            untrusted_certs,
                            cmp_creds, own_truststore,
                            opt_digest, opt_mac,
                            NULL, (int)opt_total_timeout,
                            NULL, opt_implicit_confirm);

    OSSL_CMP_CTX_set_log_verbosity(ctx, (int)opt_verbosity);

    // Set option flags
    OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_UNPROTECTED_ERRORS, 1);
    OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IGNORE_KEYUSAGE, 1);
    OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_VALIDITY_DAYS, 0);
    OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_DISABLE_CONFIRM, false);
    OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_UNPROTECTED_SEND, false);

    // Setup new key
    new_pkey = KEY_new("rsa:4096");

    // Setup TLS
    tls_trust = STORE_load(opt_tls_trusted, "trusted certs for TLS level", NULL);

    STORE_set_parameters(tls_trust, vpm, opt_check_all, opt_stapling, crls, opt_use_cdp, opt_cdps, (int)opt_crls_timeout, opt_use_aia, opt_ocsp, (int)opt_ocsp_timeout);
    STORE_set_crl_callback(tls_trust, CRLMGMT_load_crl_cb, cmdata);

    tls = TLS_new(tls_trust, OSSL_CMP_CTX_get0_untrusted(ctx), tls_creds, NULL, -1);
    STORE_set1_host_ip(tls_trust, opt_server, opt_server);

    // Setup HTTP
    err = CMPclient_setup_HTTP(ctx, "broker.sdo-qa.siemens.cloud:443", "/.well-known/cmp/p/PPKI%20QA", 1, 10, tls, NULL, 0);
    if (err != CMP_OK) {
        LOG(FL_ERR, "Cannot setup http");
    }

    // Send CMP
    if (current_cmd == ir) {
      cmp_ir(ctx, new_creds, new_pkey, subject, exts);
    } else if (current_cmd == kur) {
      cmp_kur(ctx, new_creds, new_pkey);
    }

    CREDENTIALS_free(new_creds);
    CREDENTIALS_free(cmp_creds);
    STORE_free(cmp_truststore);
    STORE_free(own_truststore);
    TLS_free(tls);
    STORE_free(tls_trust);
    CRLMGMT_DATA_free(cmdata);
    X509_VERIFY_PARAM_free(vpm);
    NCONF_free(config);
    X509_free(oldcert);
    X509_REQ_free(csr);
    CMPclient_finish(ctx);
}