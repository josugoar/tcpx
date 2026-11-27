#ifndef QUIC_H
#define QUIC_H

#include <errno.h>
#include <netdb.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/ssl.h>

#define CIDS_LEN 8
#define BUF_LEN 65536

typedef struct
{
    ngtcp2_cid cid;
    ngtcp2_conn *conn;
} cid_t;

[[maybe_unused]] static uint8_t data[BUF_LEN] = {0};
static size_t data_idx = 0;
static size_t data_head = 0;
static size_t data_tail = 0;

static cid_t cids[CIDS_LEN] = {0};

static int client_initial_cb(ngtcp2_conn *conn, void *user_data)
{
    fprintf(stderr, "D %s client_initial_cb\n", "quic");

    int errnum = ngtcp2_crypto_client_initial_cb(conn, user_data);
    if (errnum != 0)
    {
        fprintf(stderr, "W %s ngtcp2_crypto_client_initial_cb: %s\n", "quic", ngtcp2_strerror(errnum));
    }

    return errnum;
}

static int recv_client_initial_cb(ngtcp2_conn *conn, const ngtcp2_cid *dcid, void *user_data)
{
    fprintf(stderr, "D %s recv_client_initial_cb\n", "quic");

    int errnum = ngtcp2_crypto_recv_client_initial_cb(conn, dcid, user_data);
    if (errnum != 0)
    {
        fprintf(stderr, "W %s ngtcp2_crypto_recv_client_initial_cb: %s\n", "quic", ngtcp2_strerror(errnum));
    }

    return errnum;
}

static int recv_crypto_data_cb(ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level, uint64_t offset, const uint8_t *data, size_t datalen, void *user_data)
{
    fprintf(stderr, "D %s recv_crypto_data_cb\n", "quic");

    int errnum = ngtcp2_crypto_recv_crypto_data_cb(conn, encryption_level, offset, data, datalen, user_data);
    if (errnum != 0)
    {
        fprintf(stderr, "W %s ngtcp2_crypto_recv_crypto_data_cb: %s\n", "quic", ngtcp2_strerror(errnum));
    }

    return errnum;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
    (void)conn;
    (void)user_data;

    fprintf(stderr, "D %s handshake_completed_cb\n", "quic");

    return 0;
}

static int recv_version_negotiation_cb(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, const uint32_t *sv, size_t nsv, void *user_data)
{
    (void)conn;
    (void)hd;
    (void)sv;
    (void)nsv;
    (void)user_data;

    fprintf(stderr, "D %s recv_version_negotiation_cb\n", "quic");

    return 0;
}

static int encrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead, const ngtcp2_crypto_aead_ctx *aead_ctx, const uint8_t *plaintext, size_t plaintextlen, const uint8_t *nonce, size_t noncelen, const uint8_t *aad, size_t aadlen)
{
    fprintf(stderr, "D %s encrypt_cb\n", "quic");

    int errnum = ngtcp2_crypto_encrypt_cb(dest, aead, aead_ctx, plaintext, plaintextlen, nonce, noncelen, aad, aadlen);
    if (errnum != 0)
    {
        fprintf(stderr, "W %s ngtcp2_crypto_encrypt_cb: %s\n", "quic", ngtcp2_strerror(errnum));
    }

    return errnum;
}

static int decrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead, const ngtcp2_crypto_aead_ctx *aead_ctx, const uint8_t *ciphertext, size_t ciphertextlen, const uint8_t *nonce, size_t noncelen, const uint8_t *aad, size_t aadlen)
{
    fprintf(stderr, "D %s decrypt_cb\n", "quic");

    int errnum = ngtcp2_crypto_decrypt_cb(dest, aead, aead_ctx, ciphertext, ciphertextlen, nonce, noncelen, aad, aadlen);
    if (errnum != 0)
    {
        fprintf(stderr, "W %s ngtcp2_crypto_decrypt_cb: %s\n", "quic", ngtcp2_strerror(errnum));
    }

    return errnum;
}

static int hp_mask_cb(uint8_t *dest, const ngtcp2_crypto_cipher *hp, const ngtcp2_crypto_cipher_ctx *hp_ctx, const uint8_t *sample)
{
    fprintf(stderr, "D %s hp_mask_cb\n", "quic");

    int errnum = ngtcp2_crypto_hp_mask_cb(dest, hp, hp_ctx, sample);
    if (errnum != 0)
    {
        fprintf(stderr, "W %s ngtcp2_crypto_hp_mask_cb: %s\n", "quic", ngtcp2_strerror(errnum));
    }

    return errnum;
}

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)flags;
    (void)stream_id;
    (void)offset;
    (void)user_data;
    (void)stream_user_data;

    fprintf(stderr, "D %s recv_stream_data_cb\n", "quic");

    if (write(STDOUT_FILENO, data, datalen) == -1)
    {
        fprintf(stderr, "W %s write: %s\n", "quic", strerror(errno));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen, void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)stream_id;
    (void)offset;
    (void)user_data;
    (void)stream_user_data;

    fprintf(stderr, "D %s acked_stream_data_offset_cb\n", "quic");

    data_head += datalen;

    if (data_head == data_tail)
    {
        data_idx = 0;
        data_head = 0;
        data_tail = 0;
    }

    return 0;
}

static int stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
    (void)conn;
    (void)stream_id;
    (void)user_data;

    fprintf(stderr, "D %s stream_open_cb\n", "quic");

    return 0;
}

static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t app_error_code, void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)flags;
    (void)stream_id;
    (void)app_error_code;
    (void)user_data;
    (void)stream_user_data;

    fprintf(stderr, "D %s stream_close_cb\n", "quic");

    return 0;
}

static int recv_stateless_reset_cb(ngtcp2_conn *conn, const ngtcp2_pkt_stateless_reset *sr, void *user_data)
{
    (void)conn;
    (void)sr;
    (void)user_data;

    fprintf(stderr, "D %s recv_stateless_reset_cb\n", "quic");

    return 0;
}

static int recv_retry_cb(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data)
{
    fprintf(stderr, "D %s recv_retry_cb\n", "quic");

    int errnum = ngtcp2_crypto_recv_retry_cb(conn, hd, user_data);
    if (errnum != 0)
    {
        fprintf(stderr, "W %s ngtcp2_crypto_recv_retry_cb: %s\n", "quic", ngtcp2_strerror(errnum));
    }

    return errnum;
}

static int extend_max_local_streams_bidi_cb(ngtcp2_conn *conn, uint64_t max_streams, void *user_data)
{
    (void)conn;
    (void)max_streams;

    fprintf(stderr, "D %s extend_max_local_streams_bidi_cb\n", "quic");

    int64_t *pstream_id = (int64_t *)user_data;

    if (*pstream_id != -1)
    {
        return 0;
    }

    int errnum = ngtcp2_conn_open_bidi_stream(conn, pstream_id, NULL);
    if (errnum != 0)
    {
        fprintf(stderr, "W %s ngtcp2_conn_open_uni_stream: %s\n", "quic", ngtcp2_strerror(errnum));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int extend_max_local_streams_uni_cb(ngtcp2_conn *conn, uint64_t max_streams, void *user_data)
{
    (void)conn;
    (void)max_streams;
    (void)user_data;

    fprintf(stderr, "D %s extend_max_local_streams_uni_cb\n", "quic");

    return 0;
}

static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
    (void)rand_ctx;

    fprintf(stderr, "D %s rand_cb\n", "quic");

    for (size_t i = 0; i < destlen; ++i)
    {
        *dest = (uint8_t)rand();
    }
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data)
{
    (void)user_data;

    fprintf(stderr, "D %s get_new_connection_id_cb\n", "quic");

    int errnum = 0;

    cid->datalen = cidlen;
    errnum = wolfSSL_RAND_bytes(cid->data, cid->datalen);
    if (errnum != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "W %s wolfSSL_RAND_bytes: %s\n", "quic", wolfSSL_ERR_reason_error_string(errnum));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    errnum = wolfSSL_RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    if (errnum != WOLFSSL_SUCCESS)
    {
        fprintf(stderr, "W %s wolfSSL_RAND_bytes: %s\n", "quic", wolfSSL_ERR_reason_error_string(errnum));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    for (size_t i = 0; i < CIDS_LEN; ++i)
    {
        cid_t *quic_cid = &cids[i];

        if (quic_cid->conn)
        {
            continue;
        }

        quic_cid->cid = *cid;
        quic_cid->conn = conn;

        return 0;
    }

    return NGTCP2_ERR_CALLBACK_FAILURE;
}

static int remove_connection_id_cb(ngtcp2_conn *conn, const ngtcp2_cid *cid, void *user_data)
{
    (void)conn;
    (void)user_data;

    fprintf(stderr, "D %s remove_connection_id_cb\n", "quic");

    for (size_t i = 0; i < CIDS_LEN; ++i)
    {
        cid_t *quic_cid = &cids[i];

        if (!quic_cid->conn)
        {
            continue;
        }

        if (!ngtcp2_cid_eq(&quic_cid->cid, cid))
        {
            continue;
        }

        memset(quic_cid, 0, sizeof(*quic_cid));

        return 0;
    }

    return NGTCP2_ERR_CALLBACK_FAILURE;
}

static int update_key_cb(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret, ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv, ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv, const uint8_t *current_rx_secret, const uint8_t *current_tx_secret, size_t secretlen, void *user_data)
{
    fprintf(stderr, "D %s update_key_cb\n", "quic");

    int errnum = ngtcp2_crypto_update_key_cb(conn, rx_secret, tx_secret, rx_aead_ctx, rx_iv, tx_aead_ctx, tx_iv, current_rx_secret, current_tx_secret, secretlen, user_data);
    if (errnum != 0)
    {
        fprintf(stderr, "W %s ngtcp2_crypto_update_key_cb: %s\n", "quic", ngtcp2_strerror(errnum));
    }

    return errnum;
}

static int path_validation_cb(ngtcp2_conn *conn, uint32_t flags, const ngtcp2_path *path, const ngtcp2_path *old_path, ngtcp2_path_validation_result res, void *user_data)
{
    (void)conn;
    (void)flags;
    (void)path;
    (void)old_path;
    (void)res;
    (void)user_data;

    fprintf(stderr, "D %s path_validation_cb\n", "quic");

    return 0;
}

static int select_preferred_addr_cb(ngtcp2_conn *conn, ngtcp2_path *dest, const ngtcp2_preferred_addr *paddr, void *user_data)
{
    (void)conn;
    (void)dest;
    (void)paddr;
    (void)user_data;

    fprintf(stderr, "D %s select_preferred_addr_cb\n", "quic");

    return 0;
}

static int stream_reset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size, uint64_t app_error_code, void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)stream_id;
    (void)final_size;
    (void)app_error_code;
    (void)user_data;
    (void)stream_user_data;

    fprintf(stderr, "D %s stream_reset_cb\n", "quic");

    return 0;
}

static int extend_max_remote_streams_bidi_cb(ngtcp2_conn *conn, uint64_t max_streams, void *user_data)
{
    (void)conn;
    (void)max_streams;
    (void)user_data;

    fprintf(stderr, "D %s extend_max_remote_streams_bidi_cb\n", "quic");

    return 0;
}

static int extend_max_remote_streams_uni_cb(ngtcp2_conn *conn, uint64_t max_streams, void *user_data)
{
    (void)conn;
    (void)max_streams;
    (void)user_data;

    fprintf(stderr, "D %s extend_max_remote_streams_uni_cb\n", "quic");

    return 0;
}

static int extend_max_stream_data_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t max_data, void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)stream_id;
    (void)max_data;
    (void)user_data;
    (void)stream_user_data;

    fprintf(stderr, "D %s extend_max_stream_data_cb\n", "quic");

    return 0;
}

static int dcid_status_cb(ngtcp2_conn *conn, ngtcp2_connection_id_status_type type, uint64_t seq, const ngtcp2_cid *cid, const uint8_t *token, void *user_data)
{
    (void)conn;
    (void)type;
    (void)seq;
    (void)cid;
    (void)token;
    (void)user_data;

    fprintf(stderr, "D %s dcid_status_cb\n", "quic");

    return 0;
}

static int handshake_confirmed_cb(ngtcp2_conn *conn, void *user_data)
{
    (void)conn;
    (void)user_data;

    fprintf(stderr, "D %s handshake_confirmed_cb\n", "quic");

    return 0;
}

static int recv_new_token_cb(ngtcp2_conn *conn, const uint8_t *token, size_t tokenlen, void *user_data)
{
    (void)conn;
    (void)token;
    (void)tokenlen;
    (void)user_data;

    fprintf(stderr, "D %s recv_new_token_cb\n", "quic");

    return 0;
}

static void delete_crypto_aead_ctx_cb(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *aead_ctx, void *user_data)
{
    fprintf(stderr, "D %s delete_crypto_aead_ctx_cb\n", "quic");

    ngtcp2_crypto_delete_crypto_aead_ctx_cb(conn, aead_ctx, user_data);
}

static void delete_crypto_cipher_ctx_cb(ngtcp2_conn *conn, ngtcp2_crypto_cipher_ctx *cipher_ctx, void *user_data)
{
    fprintf(stderr, "D %s delete_crypto_cipher_ctx_cb\n", "quic");

    ngtcp2_crypto_delete_crypto_cipher_ctx_cb(conn, cipher_ctx, user_data);
}

static int recv_datagram_cb(ngtcp2_conn *conn, uint32_t flags, const uint8_t *data, size_t datalen, void *user_data)
{
    (void)conn;
    (void)flags;
    (void)data;
    (void)datalen;
    (void)user_data;

    fprintf(stderr, "D %s recv_datagram_cb\n", "quic");

    return 0;
}

static int ack_datagram_cb(ngtcp2_conn *conn, uint64_t dgram_id, void *user_data)
{
    (void)conn;
    (void)dgram_id;
    (void)user_data;

    fprintf(stderr, "D %s ack_datagram_cb\n", "quic");

    return 0;
}

static int lost_datagram_cb(ngtcp2_conn *conn, uint64_t dgram_id, void *user_data)
{
    (void)conn;
    (void)dgram_id;
    (void)user_data;

    fprintf(stderr, "D %s lost_datagram_cb\n", "quic");

    return 0;
}

static int get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data, void *user_data)
{
    fprintf(stderr, "D %s get_path_challenge_data_cb\n", "quic");

    int errnum = ngtcp2_crypto_get_path_challenge_data_cb(conn, data, user_data);
    if (errnum != 0)
    {
        fprintf(stderr, "W %s ngtcp2_crypto_get_path_challenge_data_cb: %s\n", "quic", ngtcp2_strerror(errnum));
    }

    return errnum;
}

static int stream_stop_sending_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t app_error_code, void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)stream_id;
    (void)app_error_code;
    (void)user_data;
    (void)stream_user_data;

    fprintf(stderr, "D %s stream_stop_sending_cb\n", "quic");

    return 0;
}

static int version_negotiation_cb(ngtcp2_conn *conn, uint32_t version, const ngtcp2_cid *client_dcid, void *user_data)
{
    fprintf(stderr, "D %s version_negotiation_cb\n", "quic");

    int errnum = ngtcp2_crypto_version_negotiation_cb(conn, version, client_dcid, user_data);
    if (errnum != 0)
    {
        fprintf(stderr, "W %s ngtcp2_crypto_version_negotiation_cb: %s\n", "quic", ngtcp2_strerror(errnum));
    }

    return errnum;
}

static int recv_rx_key_cb(ngtcp2_conn *conn, ngtcp2_encryption_level level, void *user_data)
{
    (void)conn;
    (void)level;
    (void)user_data;

    fprintf(stderr, "D %s recv_rx_key_cb\n", "quic");

    return 0;
}

static int recv_tx_key_cb(ngtcp2_conn *conn, ngtcp2_encryption_level level, void *user_data)
{
    (void)conn;
    (void)level;
    (void)user_data;

    fprintf(stderr, "D %s recv_tx_key_cb\n", "quic");

    return 0;
}

static int tls_early_data_rejected_cb(ngtcp2_conn *conn, void *user_data)
{
    (void)conn;
    (void)user_data;

    fprintf(stderr, "D %s tls_early_data_rejected_cb\n", "quic");

    return 0;
}

#endif
