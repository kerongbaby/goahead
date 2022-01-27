/*
    ws.c - WebSocket to GoAhead

 */
/************************************ Include *********************************/

#include    "goahead.h"

#define EVHTP_WS_MAGIC       "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PUBLIC int wsUpgrade(Webs *wp)
{
    char *key = websGetVar(wp, "sec-websocket-key", NULL); 
    size_t key_len = strlen(key);
    unsigned char buffer[128];
    memset(buffer, 0x0, sizeof(buffer));
    strcpy(buffer, key);
    strcat(buffer, EVHTP_WS_MAGIC);
    logmsg(2, "Response for websocket upgrade, wp key: %s", buffer);

    unsigned char digest[20];
    mbedtls_sha1_ret(buffer, strlen(buffer), digest);
    size_t len;
    mbedtls_base64_encode( buffer, sizeof( buffer ), &len, digest, sizeof(digest) );
    logmsg(2, "Response for websocket upgrade, wp key: %s", buffer);

    websSetStatus(wp, HTTP_CODE_SWITCH_PROTO);
    websWriteHeaders(wp, 0, NULL);
    websWriteHeader(wp, "Upgrade", "websocket");
    websWriteHeader(wp, "Connection", "Upgrade");
    websWriteHeader(wp, "Sec-WebSocket-Accept", buffer);
    char *upgrade = websGetVar(wp, "Upgrade", NULL);
    // if(NULL != upgrade)
    char *value = websGetVar(wp, "sec-websocket-protocol", NULL);
    if(NULL != value) {
        logmsg(2, "sec-websocket-protocol: %s", value);
        websWriteHeader(wp, "Sec-WebSocket-Protocol", value);
    }
    websWriteEndHeaders(wp);

    websDone(wp);
    return 1;
}
