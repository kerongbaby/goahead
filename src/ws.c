/*
    ws.c - WebSocket to GoAhead

 */
/************************************ Include *********************************/

#include    "goahead.h"

/**
 * @brief attempt to find the sec-webSocket-key from the input headers,
 *       append the magic string to it, sha1 encode it, then base64 encode
 *       into the output header "sec-websocket-accept"
 *
 * @param hdrs_in
 * @param hdrs_out
 *
 * @return 0 on success, -1 on error
 */
struct evhtp_ws_frame_hdr_s {
    uint8_t opcode : 4,
            rsv3   : 1,
            rsv2   : 1,
            rsv1   : 1,
            fin    : 1;

    #define OP_CONT          0x0
    #define OP_TEXT          0x1
    #define OP_BIN           0x2
    #define OP_NCONTROL_RES1 0x3
    #define OP_NCONTROL_RES2 0x4
    #define OP_NCONTROL_RES3 0x5
    #define OP_NCONTROL_RES4 0x6
    #define OP_NCONTROL_RES5 0x7
    #define OP_CLOSE         0x8
    #define OP_PING          0x9
    #define OP_PONG          0xA
    #define OP_CONTROL_RES1  0xB
    #define OP_CONTROL_RES2  0xC
    #define OP_CONTROL_RES3  0xD
    #define OP_CONTROL_RES4  0xE
    #define OP_CONTROL_RES5  0xF

    uint8_t len  : 7,
            mask : 1;
} __attribute__((packed));
//struct evhtp_ws_frame_hdr_s;
typedef struct evhtp_ws_frame_hdr_s evhtp_ws_frame_hdr;

struct evhtp_ws_frame_s {
    evhtp_ws_frame_hdr hdr;

    uint32_t masking_key;
    uint64_t payload_len;
};

typedef enum evhtp_ws_parser_state evhtp_ws_parser_state;
typedef struct evhtp_ws_frame_s     evhtp_ws_frame;

enum evhtp_ws_parser_state {
    ws_s_start = 0,
    ws_s_fin_rsv_opcode,
    ws_s_mask_payload_len,
    ws_s_ext_payload_len_16,
    ws_s_ext_payload_len_64,
    ws_s_masking_key,
    ws_s_payload,
};

struct Websocket {
    evhtp_ws_parser_state state;
    uint64_t              content_len;
    uint64_t              orig_content_len;
    uint64_t              content_idx;
    uint16_t              status_code;
    void                * usrdata;
    evhtp_ws_frame        frame;
    struct event        * pingev;
    uint8_t               pingct;
    bool                  ws_cont;
    char *path;
    char *protocol;
};

#define HAS_EXTENDED_PAYLOAD_HDR(__frame) ((__frame)->len >= 126)
#define EXTENDED_PAYLOAD_HDR_LEN(__sz) \
    ((__sz >= 126) ? ((__sz == 126) ? 16 : 64) : 0)

static uint32_t __MASK[] = {
    0x000000ff,
    0x0000ff00,
    0x00ff0000,
    0xff000000
};

static uint32_t __SHIFT[] = {
    0, 8, 16, 24
};

#define EVHTP_WS_MAGIC       "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PUBLIC void debugWebsocket(Webs *wp, const char *func, int line) {
    if(!(wp->flags & WEBS_SOCKET)) {
        // logmsg(2, "wp is not websocket");
        return;
    }
    logmsg(2, "debug websocket at %s line %d, wp is %p, websocket is: %p", func, line, wp, wp->websocket);
    Websocket *p = wp->websocket;
    if(NULL == p) {
        logmsg(2, "wp have not websocket");
        return;
    }
    logmsg(2, "debugWebsocket %p, state: %d", p, p->state);
}

PUBLIC int wsUpgrade(Webs *wp)
{
    char *key = websGetVar(wp, "sec-websocket-key", NULL); 
    size_t key_len = strlen(key);
    unsigned char buffer[128];
    memset(buffer, 0x0, sizeof(buffer));
    strcpy(buffer, key);
    strcat(buffer, EVHTP_WS_MAGIC);

    unsigned char digest[20];
    mbedtls_sha1_ret(buffer, strlen(buffer), digest);
    size_t len;
    mbedtls_base64_encode( buffer, sizeof( buffer ), &len, digest, sizeof(digest) );

    websSetStatus(wp, HTTP_CODE_SWITCH_PROTO);
    websWriteHeaders(wp, 0, NULL);
    websWriteHeader(wp, "Upgrade", "websocket");
    websWriteHeader(wp, "Connection", "Upgrade");
    websWriteHeader(wp, "Sec-WebSocket-Accept", buffer);
    // At this point, if the client supports one of the advertised versions,
    // it can repeat the WebSocket handshake using a new version value.
    char *value = websGetVar(wp, "sec-websocket-protocol", NULL);
    if(NULL != value) {
        logmsg(2, "sec-websocket-protocol: %s", value);
        websWriteHeader(wp, "Sec-WebSocket-Protocol", value);
    }
    websWriteEndHeaders(wp);
    wp->websocket = walloc(sizeof(*wp->websocket));
    memset(wp->websocket, 0x0, sizeof(*wp->websocket));
    wp->websocket->state = ws_s_start;
    wp->websocket->path = sclone(wp->path);
    wp->websocket->protocol = sclone(wp->protocol);

    websDone(wp);
    logmsg(2, "Create websocket instance.");
    return 1;
}

PUBLIC void wsPing(Webs *wp) {
    if(bufLen(&wp->output) > 0) {
        logmsg(2, "posible did not need PING");
        return;
    }

    logmsg(2, "websocket timeout, do PING");
    static unsigned char outbuf[2] = {0x89,0x00};
    Websocket *p = wp->websocket;
    p->pingct++;
    wp->state = WEBS_RUNNING;
    if(sizeof(outbuf) != websWriteBlock(wp, outbuf, sizeof(outbuf)))
        logmsg(2, "wsPing write failed? state: %d", wp->state);
    websDone(wp);
    wp->state = WEBS_COMPLETE;
}

PUBLIC void checkWebsocketTimeout(Webs *wp) {
    if(!(wp->flags & WEBS_SOCKET))
        return;

    websNoteRequestActivity(wp);
    websSetBackgroundWriter(wp, wsPing);
//    wsPing(wp);
}

static uint64_t ntoh64(const uint64_t input)
{
    uint64_t rval;
    uint8_t *data = (uint8_t *)&rval;

    data[0] = input >> 56;
    data[1] = input >> 48;
    data[2] = input >> 40;
    data[3] = input >> 32;
    data[4] = input >> 24;
    data[5] = input >> 16;
    data[6] = input >> 8;
    data[7] = input >> 0;

    return rval;
}

/* use and prepend existing evbuffer with websocket header */
void evhtp_ws_add_header(Webs *wp, size_t len, uint8_t opcode)
{
    uint8_t         pbuf[10];
    size_t          bufsz;

    pbuf[0] = opcode | 0x80;

    if (len <= 125) {
        pbuf[1]= (uint8_t) len;
        bufsz = 2;
    } else if (len > 125 && len <= 65535) {
        pbuf[1] = 126;
        bufsz = 4;
        pbuf[2] = (uint8_t) (len>>8);
        pbuf[3] = (uint8_t) (len & 0xff);
    } else {
        pbuf[1] = 127;
        pbuf[2] = (uint8_t) (len>>56 & 0xff);
        pbuf[3] = (uint8_t) (len>>48 & 0xff);
        pbuf[4] = (uint8_t) (len>>40 & 0xff);
        pbuf[5] = (uint8_t) (len>>32 & 0xff);
        pbuf[6] = (uint8_t) (len>>24 & 0xff);
        pbuf[7] = (uint8_t) (len>>16 & 0xff);
        pbuf[8] = (uint8_t) (len>> 8 & 0xff);
        pbuf[9] = (uint8_t) (len & 0xff);
        bufsz = 10;
    }
    websWriteBlock(wp, pbuf, bufsz);
}

/* formulate a pong response */
static void ws_pong(Webs *wp)
{
    /* take in buffer and prepend a pong header*/
    evhtp_ws_add_header(wp, 0, OP_PONG);
}

bool parseWebsocketIncoming(Webs *wp) {
    WebsBuf     *rxbuf;
    char        *end, c;
    rxbuf = &wp->rxbuf;

//    debugWebsocket(wp, __func__, __LINE__);
    int cc;
    Websocket *p = wp->websocket;
//    logmsg(2, "parseWebsocketIncoming, Websocket: %p", p);
    switch (p->state)
    {
    case ws_s_start:
        p->state            = ws_s_fin_rsv_opcode;
        p->content_len      = 0;
        p->orig_content_len = 0;
        p->content_idx      = 0;
        p->status_code      = 0;
    /* fall-through */
    case ws_s_fin_rsv_opcode:
        if((cc = bufGetc(rxbuf)) < 0) {
            p->state = ws_s_start;
            wp->state = WEBS_COMPLETE;
            return 0;
        }
        p->frame.hdr.fin    = (cc & 0x80)? 1:0;
        p->frame.hdr.opcode = (cc & 0xF);
        //sanity check 1
        if(
            p->frame.hdr.fin != OP_CONT && p->frame.hdr.fin != OP_TEXT &&
            p->frame.hdr.fin != OP_BIN  && p->frame.hdr.fin != OP_PING &&
            p->frame.hdr.fin != OP_PONG && p->frame.hdr.fin != OP_CLOSE
        )
        {
            logmsg(2, "Warning: websockets - invalid opcode %d\n", p->frame.hdr.opcode);
            return 0;
        }

        //sanity check 2
        if(p->ws_cont && p->frame.hdr.opcode !=OP_CONT)
        {
            logmsg(2, "Warning: websockets - expecting a continue frame but got opcode %d\n", p->frame.hdr.opcode);
            return -1;
        }

        //sanity check 3
        if (!p->ws_cont && p->frame.hdr.opcode == OP_CONT)
        {
            logmsg(2, "Warning: websockets - not expecting a continue frame but got opcode OP_CONT\n");
            return -1;
        }

        p->ws_cont = !p->frame.hdr.fin;

        p->state = ws_s_mask_payload_len;
        // logmsg(2, "ws_s_fin_rsv_opcode: %02X", p->frame.hdr.opcode);
        break;

    case ws_s_mask_payload_len:
        if((cc = bufGetc(rxbuf)) < 0) {
            logmsg(2, "Warning: websockets - ws_s_mask_payload_len failed");
            return 0;
        }

        p->frame.hdr.mask   = ((cc & 0x80) ? 1 : 0);
        p->frame.hdr.len    = (cc & 0x7F);
        // logmsg(2, "ws_s_mask_payload_len: %02X", p->frame.hdr.len);
        switch (EXTENDED_PAYLOAD_HDR_LEN(p->frame.hdr.len)) {
            case 0:
                p->frame.payload_len = p->frame.hdr.len;
                p->content_len       = p->frame.payload_len;
                p->orig_content_len  = p->content_len;

                if (p->frame.hdr.mask == 1) {
                    p->state = ws_s_masking_key;
                    break;
                }

                p->state = ws_s_payload;
                break;
            case 16:
                p->state = ws_s_ext_payload_len_16;
                break;
            case 64:
                p->state = ws_s_ext_payload_len_64;
                break;
            default:
                return -1;
        } /* switch */
        break;

    case ws_s_ext_payload_len_16: {
        logmsg(2, "ws_s_ext_payload_len_16");
        unsigned char t[2];
        if(bufGetBlk(wp, t, sizeof(t)) < sizeof(t)) {
            logmsg(2, "Warning: websockets - ws_s_ext_payload_len_16 short");
            return 0;
        }
#if 0
        if (MIN_READ((const char *)(data + len) - &data[i], 2) < 2) {
            return i;
        }
#endif
        p->frame.payload_len = ntohs(*(uint16_t *)t);
//            p.frame.payload_len = p.frame.payload_len << 8 | (bufGetc(rxbuf) & 0xff);
        p->content_len       = p->frame.payload_len;
        //printf("16 - content_len = %d\n",  (int)p->content_len);
        logmsg(2, "16 - content_len = %d",  (int)p->content_len);
        p->orig_content_len  = p->content_len;

        // i += 2;

        if (p->frame.hdr.mask == 1) {
            p->state = ws_s_masking_key;
            break;
        }

        p->state = ws_s_payload;
        break;
    }
    case ws_s_ext_payload_len_64: {
        logmsg(2, "ws_s_ext_payload_len_64");
        unsigned char t[8];
        if(bufGetBlk(rxbuf, t, sizeof(t)) < sizeof(t)) {
            logmsg(2, "Warning: websockets - ws_s_ext_payload_len_64 short");
            return 0;
        }

#if 0
        if (MIN_READ((const char *)(data + len) - &data[i], 8) < 8) {
            return i;
        }
#endif

        p->frame.payload_len = ntoh64(*(uint64_t *)t);
        p->content_len       = p->frame.payload_len;
        p->orig_content_len  = p->content_len;
        logmsg(2, "64 - content_len = %d",  (int)p->content_len);
        if (p->frame.hdr.mask == 1) {
            p->state = ws_s_masking_key;;
            break;
        }

        p->state = ws_s_payload;
        break;
    }
    case ws_s_masking_key: {
        unsigned char t[4];
        if(bufGetBlk(rxbuf, t, sizeof(t)) < sizeof(t)) {
            logmsg(2, "Warning: websockets - ws_s_masking_key short");
            return 0;
        }
        p->frame.masking_key = *(uint32_t *)t;
        // logmsg(2, "ws_s_masking_key: %08X", p->frame.masking_key);
        p->state = ws_s_payload;
        break;
    }

    case ws_s_payload: {
    // logmsg(2, "ws_s_payload, opcode: %02X", p->frame.hdr.opcode);
        /* op_close case */
        if (p->frame.hdr.opcode == OP_CLOSE && p->status_code == 0) {
            logmsg(2, "websockets - onClose");
            logmsg(2, "websockets - ws_s_payload length: %d", bufLen(wp));
            uint64_t index;
            uint32_t mkey;
            int      j1;
            int      j2;
            int      m1;
            int      m2;
            char     buf[2];
            if(bufLen(wp) < 2) {
            // if (MIN_READ((const char *)(data + len) - &data[i], 2) < 2) {
                return 0;
            }

            index           = p->content_idx;
            mkey            = p->frame.masking_key;

            /* our mod4 for the current index */
            j1              = index % 4;
            /* our mod4 for one past the index. */
            j2              = (index + 1) % 4;

            /* the masks we will be using to xor the buffers */
            m1              = (mkey & __MASK[j1]) >> __SHIFT[j1];
            m2              = (mkey & __MASK[j2]) >> __SHIFT[j2];
            bufGetBlk(wp, buf, sizeof(buf));
            buf[0]          = buf[0] ^ m1;
            buf[1]          = buf[1] ^ m2;

            p->status_code  = ntohs(*(uint16_t *)buf);
            p->content_len -= 2;
            p->content_idx += 2;
            /* RFC states that there could be a message after the
                * OP_CLOSE 2 byte header, so just drop down and attempt
                * to parse it.
                */
        }

//                bufFlush(&wp->output);
        // logmsg(2, "1 output buf len: %0d rxbuf len: %d, content length: %d, content_idx %d", bufLen(&wp->output), bufLen(rxbuf), p->content_len, p->content_idx);
        if(bufLen(rxbuf) < p->content_len) {
            logmsg(2, "TODO: handle error for content short");
        }

        if(bufLen(rxbuf) > 0) {
            int  z;
            while(p->content_idx < p->content_len) {
                int           j = p->content_idx % 4;
                unsigned char xformed_oct;
                xformed_oct     = (p->frame.masking_key & __MASK[j]) >> __SHIFT[j];
                rxbuf->servp[p->content_idx] ^= xformed_oct;
                p->content_idx += 1;
//                if(p->content_idx >= p->content_len)                    break;
            }
            p->state = ws_s_start;
        // logmsg(2, "websockets - hook code: %02X, content length: %d, content_idx: %d", p->frame.hdr.opcode, p->content_len, p->content_idx);
        }
        else if (p->frame.hdr.opcode == OP_CONT) //0 size on a cont frame -- something isn't right.
            return -1;

        fini:

        /* did we get it all? */
        if (p->content_len == 0)
        {
            /* this is the end, set it to restart if another frame is coming (p->frame.hdr.fin==0) 
                or for the next request                                                              */
            p->state = ws_s_start;
            if(p->frame.hdr.fin == 1 )
            {
                p->ws_cont = 0;
//                        req->ws_cont = 0;
                /*currently, this always returns 0 */
//                        (void)(hooks->on_msg_fini)(p);
                logmsg(2, "websockets - fin");
            }
        }

        break;
    }
    default:
        break;
    }

    if(p->state == ws_s_mask_payload_len
    || p->state == ws_s_masking_key
    || p->state == ws_s_payload
    || p->state == ws_s_ext_payload_len_16
    || p->state == ws_s_ext_payload_len_64) {
        return 1;
    }

    if(p->frame.hdr.opcode == OP_PING) {
        logmsg(2, "websockets - PING - PONG");
        ws_pong(wp);
        wp->state = WEBS_RUNNING;
        websDone(wp);
        wp->state = WEBS_COMPLETE;
        return 1;
    } else  if(p->frame.hdr.opcode == OP_PONG) {
        p->pingct--;
        logmsg(2, "websockets - PONG Recv, ping count: %d", p->pingct);
        wp->state = WEBS_COMPLETE;
        return 1;
    } else if(p->frame.hdr.opcode == OP_CLOSE) {
        logmsg(2, "websockets - CLOSE, state: %d", p->status_code);
        websDone(wp);
        wp->flags &= ~WEBS_KEEP_ALIVE;
        wp->state = WEBS_COMPLETE;
        // TODO: free websocket instance.
        return 1;
    } else if(p->frame.hdr.opcode == OP_TEXT) {
        wp->path = sclone(p->path);
        wp->method = sclone("POST");
        wp->protocol = sclone(p->protocol);
        wp->state = WEBS_READY;
        websRouteRequest(wp);
        p->content_idx = 0;
        p->state = ws_s_start;
        return 1;
    } else
    logmsg(2, "websockets - code: %02X, content length: %d", p->frame.hdr.opcode, p->content_len);

    wp->state = WEBS_READY;
    return 0;
}

static bool websocketHandler(Webs *wp) {
    WebsFileInfo    info;
    char            *tmp, *date;
    ssize           nchars;
    int             code;
    assert(websValid(wp));
    assert(wp->method);
    assert(wp->websocket);
    Websocket *p = wp->websocket;
    // logmsg(2, "websocketHandler - code: %02X, content length: %d", p->frame.hdr.opcode, p->content_len);
    WebsBuf *buf = &wp->rxbuf;
    bufAddNull(buf);
    logmsg(2, "%s ", buf->servp);
    bufFlush(buf);

    evhtp_ws_add_header(wp, 5, OP_TEXT);
    websWriteBlock(wp, "HELLO", 5);
    websDone(wp);
    // prepare for next message.
    wp->state = WEBS_BEGIN;
    return 1;
}

static void websocketClose() {
    logmsg(2, "%s %d", __func__, __LINE__);
}

PUBLIC void websSocketOpen(void)
{
    websDefineHandler("websocket", 0, websocketHandler, websocketClose, 0);
}

#if 0

ssize_t
evhtp_ws_parser_run(evhtp_request_t *req, evhtp_ws_hooks * hooks,
                    const char * data, size_t len) {
    uint8_t      byte;
    char         c;
    size_t       i=0;
    const char * p_start;
    const char * p_end;
    uint64_t     to_read;
    Websocket * p = req->ws_parser;

    if (!hooks) {
        return (ssize_t)len;
    }	

    //printf("\nparser run, len=%d state=%d\n", (int)len, (int)p->state);
    while(i<len)
    {
        int res;
        byte = (uint8_t)data[i];
        switch (p->state) {
            case ws_s_start:
                memset(&p->frame, 0, sizeof(p->frame));

                p->state            = ws_s_fin_rsv_opcode;
                p->content_len      = 0;
                p->orig_content_len = 0;
                p->content_idx      = 0;
                p->status_code      = 0;

                if (hooks->on_msg_start) {
                    if ((hooks->on_msg_start)(p)) {
                        return i;
                    }
                }
            /* fall-through */
            case ws_s_fin_rsv_opcode:
                p->frame.hdr.fin    = (byte & 0x80)? 1:0;
                p->frame.hdr.opcode = (byte & 0xF);

                //printf("parser run, opcode=%d ws_cont=%d\n", (int)p->frame.hdr.opcode, (int) req->ws_cont);

                //sanity check 1
                if(
                    p->frame.hdr.fin != OP_CONT && p->frame.hdr.fin != OP_TEXT &&
                    p->frame.hdr.fin != OP_BIN  && p->frame.hdr.fin != OP_PING &&
                    p->frame.hdr.fin != OP_PONG && p->frame.hdr.fin != OP_CLOSE
                )
                {
                    fprintf(stderr,"Warning: websockets - invalid opcode %d\n", p->frame.hdr.opcode);
                    return -1;
                }

                //sanity check 2
                if(req->ws_cont && p->frame.hdr.opcode !=OP_CONT)
                {
                    fprintf(stderr,"Warning: websockets - expecting a continue frame but got opcode %d\n", p->frame.hdr.opcode);
                    return -1;
                }

                //sanity check 3
                if (!req->ws_cont && p->frame.hdr.opcode == OP_CONT)
                {
                    fprintf(stderr,"Warning: websockets - not expecting a continue frame but got opcode OP_CONT\n");
                    return -1;
                }

                req->ws_cont = !p->frame.hdr.fin;

                p->state = ws_s_mask_payload_len;
                i++;
                break;
            case ws_s_mask_payload_len:
                p->frame.hdr.mask   = ((byte & 0x80) ? 1 : 0);
                p->frame.hdr.len    = (byte & 0x7F);
                i++;
                switch (EXTENDED_PAYLOAD_HDR_LEN(p->frame.hdr.len)) {
                    case 0:
                        p->frame.payload_len = p->frame.hdr.len;
                        p->content_len       = p->frame.payload_len;
                        p->orig_content_len  = p->content_len;

                        if (p->frame.hdr.mask == 1) {
                            p->state = ws_s_masking_key;
                            break;
                        }

                        p->state = ws_s_payload;
                        break;
                    case 16:
                        p->state = ws_s_ext_payload_len_16;
                        break;
                    case 64:
                        p->state = ws_s_ext_payload_len_64;
                        break;
                    default:
                        return -1;
                } /* switch */
                break;
            case ws_s_ext_payload_len_16:
                if (MIN_READ((const char *)(data + len) - &data[i], 2) < 2) {
                    return i;
                }

                p->frame.payload_len = ntohs(*(uint16_t *)&data[i]);
                p->content_len       = p->frame.payload_len;
                //printf("16 - content_len = %d\n",  (int)p->content_len);
                p->orig_content_len  = p->content_len;

                i += 2;

                if (p->frame.hdr.mask == 1) {
                    p->state = ws_s_masking_key;
                    break;
                }

                p->state = ws_s_payload;

                break;
            case ws_s_ext_payload_len_64:
                if (MIN_READ((const char *)(data + len) - &data[i], 8) < 8) {
                    return i;
                }


                p->frame.payload_len = ntoh64(*(uint64_t *)&data[i]);
                p->content_len       = p->frame.payload_len;
                p->orig_content_len  = p->content_len;
                //printf("64 - content_len = %d\n",  (int)p->content_len);

                i += 8;

                if (p->frame.hdr.mask == 1) {
                    p->state = ws_s_masking_key;;
                    break;
                }

                p->state = ws_s_payload;
                break;
            case ws_s_masking_key:
            {
                int min= MIN_READ((const char *)(data + len) - &data[i], 4);
                if (min < 4) 
                {
                    return i;
                }
                p->frame.masking_key = *(uint32_t *)&data[i];
                i += 4;
                p->state = ws_s_payload;
                if(min==4) // i==len, so go directly to finish.
                    goto fini;
                break;
            }
            case ws_s_payload:

                /* op_close case */
                if (p->frame.hdr.opcode == OP_CLOSE && p->status_code == 0) {
                    uint64_t index;
                    uint32_t mkey;
                    int      j1;
                    int      j2;
                    int      m1;
                    int      m2;
                    char     buf[2];

                    if (MIN_READ((const char *)(data + len) - &data[i], 2) < 2) {
                        return i;
                    }

                    index           = p->content_idx;
                    mkey            = p->frame.masking_key;

                    /* our mod4 for the current index */
                    j1              = index % 4;
                    /* our mod4 for one past the index. */
                    j2              = (index + 1) % 4;

                    /* the masks we will be using to xor the buffers */
                    m1              = (mkey & __MASK[j1]) >> __SHIFT[j1];
                    m2              = (mkey & __MASK[j2]) >> __SHIFT[j2];

                    buf[0]          = data[i] ^ m1;
                    buf[1]          = data[i + 1] ^ m2;

                    p->status_code  = ntohs(*(uint16_t *)buf);
                    p->content_len -= 2;
                    p->content_idx += 2;
                    i += 2;

                    /* RFC states that there could be a message after the
                     * OP_CLOSE 2 byte header, so just drop down and attempt
                     * to parse it.
                     */
                }

                /* check for data */
                p_start = &data[i];
                p_end   = (const char *)(data + len);
                to_read = MIN_READ(p_end - p_start, p->content_len);
                if (to_read > 0) {
                    int  z;
                    //char buf[to_read];
                    /* reuse existing buffer */
                    char *buf = (char*)data;
                    for (z = 0; z < to_read; z++) {
                        int           j = p->content_idx % 4;
                        unsigned char xformed_oct;

                        xformed_oct     = (p->frame.masking_key & __MASK[j]) >> __SHIFT[j];
                        buf[z]          = (unsigned char)p_start[z] ^ xformed_oct;

                        p->content_idx += 1;
                    }

                    if (hooks->on_msg_data) {
                        if ((hooks->on_msg_data)(p, buf, to_read)) {
                            return -1;
                        }
                    }
                    p->content_len -= to_read;
                    i += to_read;
                }
                else if (p->frame.hdr.opcode == OP_CONT) //0 size on a cont frame -- something isn't right.
                    return -1;

                fini:
        
                //printf("length=%d, fin= %d\n", (int)p->content_len, (int)p->frame.hdr.fin);

                /* did we get it all? */
                if (p->content_len == 0)
                {
                    /* this is the end, set it to restart if another frame is coming (p->frame.hdr.fin==0) 
                       or for the next request                                                              */
                    p->state = ws_s_start;
                    if(p->frame.hdr.fin == 1 )
                    {
                        req->ws_cont = 0;
                        /*currently, this always returns 0 */
                        (void)(hooks->on_msg_fini)(p);
                        return i;
                    }
                }
                break;
        } /* switch */

    } /* while */

    return i;
}         /* evhtp_ws_parser_run */

#endif // 0
#if 0
/* send ping */
static void ws_ping(evhtp_request_t *req)
{
    struct evbuffer    * resp;
    static unsigned char outbuf[2] = {0x89,0x00};

    resp    = evbuffer_new();
    evbuffer_add_reference(resp, outbuf, 2, NULL, NULL);
    evhtp_send_reply_body(req, resp);
    evbuffer_free(resp);
}

/* formulate a pong response */
static void ws_pong(evhtp_request_t *req)
{
    /* take in buffer and prepend a pong header*/
    if(evhtp_ws_add_header(req->buffer_in, OP_PONG))
        evhtp_send_reply_body(req, req->buffer_in);
}

/* do a ping from within the event loop */
static void ws_ping_cb(evutil_socket_t fd, short events, void* arg)
{
    evhtp_request_t *req = (evhtp_request_t *)arg;
    Websocket *p = req->ws_parser;

    ws_ping(req);
    p->pingct++;
    if(p->pingct >2)
    {
        event_del(p->pingev);
        event_free(p->pingev);
        p->pingev=NULL;
        evhtp_ws_disconnect(req);
    }
}

/* insert a regularly timed ping into the event loop */
static void ws_start_ping(evhtp_request_t *req, int interval)
{
    evthr_t * thr = req->conn->thread;
    struct event_base *base = evthr_get_base(thr);
    Websocket *p = req->ws_parser;
    struct timeval timeout;

    timeout.tv_sec= (time_t) interval;
    timeout.tv_usec=0;

    p->pingev = event_new(base, -1, EV_PERSIST, ws_ping_cb, (void*)req);
    event_add(p->pingev, &timeout);
    p->pingct = 0;
}

#endif