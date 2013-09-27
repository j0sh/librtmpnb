#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/queue.h>

#include "librtmpnb/rtmp_sys.h"
#include "librtmpnb/log.h"

#ifdef linux
#include <linux/netfilter_ipv4.h>
#endif

#define MAXC 100    /* max clients */
#define MAXS MAXC   /* max streams */
typedef struct subscriber {
    struct client *c;
    LIST_ENTRY(subscriber) next;
} Subscriber;

typedef struct stream {
    AVal name;
    int id;           // source id
    int metadata_sz;
    int avc_seq_sz;
    int aac_seq_sz;
    uint8_t *metadata;
    uint8_t *avc_seq;
    uint8_t aac_seq[4];
    RTMP *producer;
    struct subscriber sub_storage[MAXS];
    LIST_HEAD(Subscribers, subscriber) subscribers;
} Stream;
static Stream streams[MAXS];

typedef struct client {
    RTMP *rtmp;
    Stream *instreams[MAXS];
    Stream *outstreams[MAXS];
    LIST_ENTRY(client) next;
} Client;
static Client clients[MAXC];

LIST_HEAD(Clients, client) clients_head;

static RTMP contexts[MAXC];
static RTMP *http_contexts[MAXC];
static RTMP *active_contexts[MAXC];

#define RTMPIDX(r) ((r) - &contexts[0])
#define CLIENTIDX(c) ((c) - &clients[0])

static int setup_listen(int port)
{
    struct sockaddr_in addr;
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), tmp = 1;
    int sockflags;
    char *iface = "0.0.0.0";

    if (-1 == sockfd) {
        fprintf(stderr, "%s, couldn't create socket", __FUNCTION__);
        return -1;
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(iface);
    addr.sin_port = htons(port);
    sockflags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, sockflags | O_NONBLOCK);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr))) {
        fprintf(stderr, "%s, TCP bind failed for port number: %d\n",
                __FUNCTION__, port);
        return -1;
    }

    if (listen(sockfd, 10) == -1) {
        fprintf(stderr, "%s, listen failed", __FUNCTION__);
        closesocket(sockfd);
        return -1;
    }
    printf("Listening on port %d\n", port);
    return sockfd;
}

/*     each stream has 5 chunks; the last 2 are unknown.
       0 and 1 are used for signalling large chunk/channel IDs,
       while 2 and 3 are used for protocol control.

       stream       channel id      type
          1              4            data
          1              5           audio
          1              6           video
          2              9            data
          2             10           audio
                ... and so on ...           */
static inline int calc_channel(int stream_id, int type_offset)
{
    return (stream_id - 1) * 5 + type_offset;
}
static inline int data_channel(int stream_id)
{
    return calc_channel(stream_id, 4);
}
static inline int audio_channel(int stream_id)
{
    return calc_channel(stream_id, 5);
}
static inline int video_channel(int stream_id)
{
    return calc_channel(stream_id, 6);
}

#define SAVC(x) static const AVal av_##x = AVC(#x)
#define STR2AVAL(av,str) av.av_val = str; av.av_len = strlen(av.av_val)

SAVC(createStream);
SAVC(connect);
SAVC(releaseStream);
SAVC(closeStream);
SAVC(publish);
SAVC(_result);
SAVC(_error);
SAVC(error);
SAVC(fmsVer);
SAVC(capabilities);
SAVC(mode);
SAVC(level);
SAVC(code);
SAVC(description);
SAVC(objectEncoding);
SAVC(onStatus);
SAVC(details);
SAVC(clientid);
SAVC(play);

static int send_createstream_resp(RTMP *r, double txn, double ID)
{
    RTMPPacket packet;
    char pbuf[256], *pend = pbuf + sizeof(pbuf);

    packet.m_nChannel = 0x03;     // control channel (invoke)
    packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
    packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = 0;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = pbuf;

    char *enc = packet.m_body;
    enc = AMF_EncodeString(enc, pend, &av__result);
    enc = AMF_EncodeNumber(enc, pend, txn);
    *enc++ = AMF_NULL;
    enc = AMF_EncodeNumber(enc, pend, ID);

    packet.m_nBodySize = enc - packet.m_body;

    r->m_stream_id = ID;
    return RTMP_SendPacket(r, &packet, FALSE);
}

static int send_error(RTMP *r, double txn, char *desc)
{
    char pbuf[384], *pend = pbuf + sizeof(pbuf), *enc;
    RTMPPacket packet;
    AVal av;

    packet.m_nChannel = 0x03;     // control channel (invoke)
    packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
    packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = 0;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = pbuf;

    enc = packet.m_body;
    enc = AMF_EncodeString(enc, pend, &av__error);
    enc = AMF_EncodeNumber(enc, pend, txn);
    *enc++ = AMF_NULL;
    *enc++ = AMF_OBJECT;
    STR2AVAL(av, "error");
    enc = AMF_EncodeNamedString(enc, pend, &av_level, &av);
    STR2AVAL(av, "NetConnection.Call.Failed");
    enc = AMF_EncodeNamedString(enc, pend, &av_code, &av);
    STR2AVAL(av, desc);
    enc = AMF_EncodeNamedString(enc, pend, &av_description, &av);
    *enc++ = 0;
    *enc++ = 0;
    *enc++ = AMF_OBJECT_END;

    packet.m_nBodySize = enc - packet.m_body;
    return RTMP_SendPacket(r, &packet, FALSE);
}

static int send_onstatus(RTMP *r, double txn, int streamid, int chan,
    char *level, char *code, char *desc)
{
    char pbuf[384], *pend = pbuf + sizeof(pbuf), *enc;
    RTMPPacket packet;
    AVal av;

    packet.m_nChannel = chan;
    packet.m_headerType = 0; /* RTMP_PACKET_SIZE_LARGE; */
    packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = streamid;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = pbuf;

    enc = packet.m_body;
    enc = AMF_EncodeString(enc, pend, &av_onStatus);
    enc = AMF_EncodeNumber(enc, pend, txn);
    *enc++ = AMF_NULL;
    *enc++ = AMF_OBJECT;
    STR2AVAL(av, level);
    enc = AMF_EncodeNamedString(enc, pend, &av_level, &av);
    STR2AVAL(av, code);
    enc = AMF_EncodeNamedString(enc, pend, &av_code, &av);
    STR2AVAL(av, desc);
    enc = AMF_EncodeNamedString(enc, pend, &av_description, &av);
    STR2AVAL(av, "none");
    enc = AMF_EncodeNamedString(enc, pend, &av_details, &av);
    enc = AMF_EncodeNamedString(enc, pend, &av_clientid, &av);
    *enc++ = 0;
    *enc++ = 0;
    *enc++ = AMF_OBJECT_END;

    packet.m_nBodySize = enc - packet.m_body;
    return RTMP_SendPacket(r, &packet, FALSE);
}

static int send_play_error(RTMP *r, AMFObject *obj, RTMPPacket *pkt,
    char *desc)
{
    double txn = AMFProp_GetNumber(AMF_GetProp(obj, NULL, 1));
    int sid = r->m_stream_id, chan = audio_channel(sid);
    return send_onstatus(r, txn, sid, chan, "error",
                         "NetStream.Play.BadName", desc);
}

static int send_play_start(RTMP *r, char *desc)
{
    int sid = r->m_stream_id, chan = audio_channel(sid);
    return send_onstatus(r, 0, sid, chan, "status",
                         "NetStream.Play.Start", desc);
}

static int send_play_reset(RTMP *r, char *desc)
{
    int sid = r->m_stream_id, chan = audio_channel(sid);
    return send_onstatus(r, 0, sid, chan, "status",
                         "NetStream.Play.Reset", desc);
}

static int send_play_stop(RTMP *r, char *sname)
{
    char desc[128];
    int sid = r->m_stream_id, chan = audio_channel(sid);
    int size = snprintf(desc, sizeof(desc), "Stream %s has stopped ",
                        sname);
    return send_onstatus(r, 0, sid, chan, "status",
                         "NetStream.Play.Stop", desc);
}

static int send_publish_error(RTMP *r, AMFObject *obj, RTMPPacket *pkt,
    char *desc)
{
    double txn = AMFProp_GetNumber(AMF_GetProp(obj, NULL, 1));
    int sid = pkt->m_nInfoField2, chan = pkt->m_nChannel;
    return send_onstatus(r, txn, sid, chan, "error",
                         "NetStream.Publish.BadName", desc);
}

static int send_publish_start(RTMP *r, AMFObject *obj, RTMPPacket *pkt, char *sname)
{
    double txn = AMFProp_GetNumber(AMF_GetProp(obj, NULL, 1));
    int sid = pkt->m_nInfoField2, chan = pkt->m_nChannel;
    return send_onstatus(r, txn, sid, chan, "status",
                         "NetStream.Publish.Start",
                         "Stream is now published");
}

static int send_chunksize(RTMP *r, int size)
{
    RTMPPacket packet = {0};
    char pbuf[4], *pend = pbuf + sizeof(pbuf);
    packet.m_nChannel = 0x02;
    packet.m_headerType = 1;
    packet.m_packetType = 0x01;
    packet.m_body = pbuf;
    packet.m_nBodySize = 4;
    AMF_EncodeInt32(pbuf, pend, size);
    r->m_outChunkSize = size;
    return RTMP_SendPacket(r, &packet, FALSE);
}

static int send_cxn_resp(RTMP *r, double txn)
{
  RTMPPacket packet;
  char pbuf[384], *pend = pbuf + sizeof(pbuf), *enc;
  AMFObject obj;
  AMFObjectProperty p, op;
  AVal av;

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = 0; /* RTMP_PACKET_SIZE_MEDIUM; */
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av__result);
  enc = AMF_EncodeNumber(enc, pend, txn);
  *enc++ = AMF_OBJECT;

  STR2AVAL(av, "FMS/3,5,1,525");
  enc = AMF_EncodeNamedString(enc, pend, &av_fmsVer, &av);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_capabilities, 31.0);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_mode, 1.0);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  *enc++ = AMF_OBJECT;

  STR2AVAL(av, "status");
  enc = AMF_EncodeNamedString(enc, pend, &av_level, &av);
  STR2AVAL(av, "NetConnection.Connect.Success");
  enc = AMF_EncodeNamedString(enc, pend, &av_code, &av);
  STR2AVAL(av, "Connection succeeded.");
  enc = AMF_EncodeNamedString(enc, pend, &av_description, &av);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_objectEncoding, r->m_fEncoding);
  STR2AVAL(p.p_name, "version");
  STR2AVAL(p.p_vu.p_aval, "3,5,1,525");
  p.p_type = AMF_STRING;
  obj.o_num = 1;
  obj.o_props = &p;
  op.p_type = AMF_OBJECT;
  STR2AVAL(op.p_name, "data");
  op.p_vu.p_object = obj;
  enc = AMFProp_Encode(&op, enc, pend);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  packet.m_nBodySize = enc - packet.m_body;

  if (RTMP_NB_OK != send_chunksize(r, 1400)) return RTMP_NB_ERROR;
  return RTMP_SendPacket(r, &packet, FALSE);

}

static inline int chan(int stream_id, int pkt_type) // choose channel
{
    switch (pkt_type) {
    case RTMP_PACKET_TYPE_AUDIO: return audio_channel(stream_id);
    case RTMP_PACKET_TYPE_VIDEO: return video_channel(stream_id);
    default: return data_channel(stream_id);
    }
}

static int send_media(RTMP *r, RTMPPacket *inpkt)
{
    RTMPPacket packet;
    if (!RTMP_IsConnected(r)) return RTMP_NB_ERROR;
    memset(&packet, 0, sizeof(RTMPPacket));
    packet.m_nChannel = chan(r->m_stream_id, inpkt->m_packetType);
    packet.m_packetType = inpkt->m_packetType;
    packet.m_nTimeStamp = inpkt->m_nTimeStamp;
    packet.m_nBodySize = inpkt->m_nBodySize;
    packet.m_body = inpkt->m_body;
    packet.m_nInfoField2 = r->m_stream_id;
    return RTMP_SendPacket(r, &packet, FALSE);
}

static void process_cxn(RTMP *r, AMFObject *obj)
{
    AMFObject cobj;
    AVal pname, pval;
    AMFProp_GetObject(AMF_GetProp(obj, NULL, 2), &cobj);
    int i;
    for (i = 0; i < cobj.o_num; i++) {
        pname = cobj.o_props[i].p_name;
	    pval.av_val = NULL;
	    pval.av_len = 0;
	    if (cobj.o_props[i].p_type == AMF_STRING)
	        pval = cobj.o_props[i].p_vu.p_aval;
        if (AVMATCH(&pname, &av_objectEncoding))
            r->m_fEncoding = cobj.o_props[i].p_vu.p_number;
    }
}

static void copy_aval(AVal *src, AVal *dst)
{
    dst->av_len = src->av_len;
    dst->av_val = malloc(src->av_len + 1);
    if (!dst->av_val) {
        RTMP_Log(RTMP_LOGERROR, "Unable to malloc av_val!");
        exit(1);
    }
    memcpy(dst->av_val, src->av_val, src->av_len);
    dst->av_val[dst->av_len] = '\0';
}

static void free_aval(AVal *val)
{
    free(val->av_val);
    val->av_val = NULL;
    val->av_len = 0;
}

static int send_streaminfo(RTMP *r, Stream *st)
{
    int err;
    RTMPPacket packet = {0};
    packet.m_headerType = 0; // this should only be sent at the
    packet.m_nTimeStamp = 0; // beginning of a stream
    packet.m_nInfoField2 = r->m_stream_id;
    if (st->metadata_sz) {
        packet.m_nChannel = audio_channel(r->m_stream_id);
        packet.m_packetType = RTMP_PACKET_TYPE_INFO;
        packet.m_body = st->metadata;
        packet.m_nBodySize = st->metadata_sz;
        if (RTMP_NB_OK != (err = RTMP_SendPacket(r, &packet, FALSE)))
            return err;
    }
    if (st->avc_seq_sz) {
        packet.m_nChannel = video_channel(r->m_stream_id);
        packet.m_packetType = RTMP_PACKET_TYPE_VIDEO;
        packet.m_body = st->avc_seq;
        packet.m_nBodySize = st->avc_seq_sz;
        if (RTMP_NB_OK != (err = RTMP_SendPacket(r, &packet, FALSE)))
            return err;
    }
    if (st->aac_seq_sz) {
        packet.m_nChannel = audio_channel(r->m_stream_id);
        packet.m_packetType = RTMP_PACKET_TYPE_AUDIO;
        packet.m_body = st->aac_seq;
        packet.m_nBodySize = st->aac_seq_sz;
        if (RTMP_NB_OK != (err = RTMP_SendPacket(r, &packet, FALSE)))
            return err;
    }
    return RTMP_NB_OK;
}

static int send_playmsgs(RTMP *r, Stream *st, int reset)
{
    if (RTMP_NB_OK != RTMP_SendCtrl(r, 0, r->m_stream_id, 0))
        return RTMP_NB_ERROR;
    if (reset) {
        if (RTMP_NB_OK != send_play_reset(r, "Resetting stream")) {
            return RTMP_NB_ERROR;
        }
    }
    if (RTMP_NB_OK != send_play_start(r, "Playing stream")) {
        return RTMP_NB_ERROR;
    }
    return send_streaminfo(r, st);
}

static int process_play(RTMP *r, AMFObject *obj, RTMPPacket *pkt)
{
    int i, idx = RTMPIDX(r), reset = 0, err, empty = -1, exists = 0;
    AVal name;
    Stream *st;
    Subscriber *sub;
    Client *c;
    AMFProp_GetString(AMF_GetProp(obj, NULL, 3), &name);
    if (obj->o_num > 6)
        reset = AMFProp_GetBoolean(AMF_GetProp(obj, NULL, 6));

    if (!name.av_len) {
        RTMP_Log(RTMP_LOGWARNING, "%s No stream name given",
                 __FUNCTION__);
        return RTMP_NB_ERROR;
    }
    for (i = 0; i < MAXS; i++) {
        if (!streams[i].name.av_val) {
            if (empty < 0) empty = i;
            continue;
        }
        if (AVMATCH(&name, &streams[i].name)) break;
    }
    if (i == MAXS) {
        if (empty < 0) {
            RTMP_Log(RTMP_LOGWARNING, "%s No stream found",
                     __FUNCTION__);
            return RTMP_NB_OK;
        }
        // create the stream
        i = empty;
        copy_aval(&name, &streams[i].name);
        RTMP_Log(RTMP_LOGINFO, "%s No stream %s found; waiting",
                               __FUNCTION__, streams[i].name.av_val);
    } else exists = 1;
    // set consumer in stream
    st = &streams[i];
    c = &clients[idx];
    sub = &st->sub_storage[idx];
    sub->c = c;
    LIST_INSERT_HEAD(&st->subscribers, sub, next);
    // set stream in client context
    for (i = 0; i < MAXS; i++) {
        if (c->outstreams[i]) continue;
        c->outstreams[i] = st;
        break;
    }
    if (i == MAXS) {
        RTMP_Log(RTMP_LOGWARNING, "%s Maximum # of streams reached",
                 __FUNCTION__);
        return send_play_error(r, obj, pkt,
                               "Maximum number of streams reached");
    }
    if (!exists) return RTMP_NB_OK;
    return send_playmsgs(r, st, reset);
}

static int process_publish(RTMP *r, AMFObject *obj, RTMPPacket *pkt)
{
    int i, empty = -1, idx;
    Stream *st;
    AVal name;
    Subscriber *sub;
    AMFProp_GetString(AMF_GetProp(obj, NULL, 3), &name);
    if (!name.av_len) {
        RTMP_Log(RTMP_LOGWARNING, "%s No stream name given",
                 __FUNCTION__);
        send_publish_error(r, obj, pkt, "No stream name given");
        return RTMP_NB_ERROR;
    }
    for (i = 0; i < MAXS; i++) {
        if (!streams[i].name.av_len && empty < 0) empty = i;
        if (!AVMATCH(&name, &streams[i].name)) continue;
        if (!streams[i].producer) break;
        RTMP_Log(RTMP_LOGERROR, "%s Stream already exists",
                 __FUNCTION__);
        send_publish_error(r, obj, pkt, "Stream already exists");
        return RTMP_NB_ERROR;
    }
    if (i == MAXS && empty < 0) {
        RTMP_Log(RTMP_LOGERROR, "%s Ran out of publishing slots",
                 __FUNCTION__);
        send_publish_error(r, obj, pkt,
                           "No more publishing slots available");
        return RTMP_NB_OK;
    } else if (i == MAXS && empty >= 0) i = empty;

    clients[RTMPIDX(r)].instreams[i] = &streams[i];
    streams[i].producer = r;
    streams[i].id = pkt->m_nInfoField2;
    copy_aval(&name, &streams[i].name);
    RTMP_Log(RTMP_LOGINFO, "%s Publishing %s",
             __FUNCTION__, streams[i].name.av_val);
    st = &streams[i];
    LIST_FOREACH(sub, &st->subscribers, next) {
        RTMP *cr = &contexts[CLIENTIDX(sub->c)];
        if (RTMP_NB_OK != send_playmsgs(cr, st, 1)) {
            // do something here! close cxn?
        }
    }
    return send_publish_start(r, obj, pkt, streams[i].name.av_val);
}

void cleanup_stream(Stream *s)
{
    int i, count = 0;
    AVal *name = &s->name;
    RTMP *r;
    Subscriber *sub;
    LIST_FOREACH(sub, &s->subscribers, next) {
        r = &contexts[CLIENTIDX(sub->c)];
        RTMP_SendCtrl(r, 1, r->m_stream_id, 0);
        send_play_stop(r, name->av_val);
        count++;
    }
    s->producer = NULL;
    if (!count) free_aval(name);
    if (s->metadata) free(s->metadata);
    if (s->avc_seq) free(s->avc_seq);
    s->metadata = s->avc_seq = NULL;
    s->metadata_sz = s->avc_seq_sz = s->aac_seq_sz = 0;
}

static int process_close(RTMP *r, AMFObject *obj, RTMPPacket *pkt)
{
    int i;
    for (i = 0; i < MAXS; i++) {
        if (streams[i].id == pkt->m_nInfoField2 &&
            r == streams[i].producer) break;
    }
    if (i == MAXS) {
        RTMP_Log(RTMP_LOGERROR, "%s Stream not found for id %d",
                 __FUNCTION__, pkt->m_nInfoField2);
        return RTMP_NB_ERROR;
    }
    RTMP_Log(RTMP_LOGINFO, "%s Closing %s",
             __FUNCTION__, streams[i].name.av_val);
    cleanup_stream(&streams[i]);
    return RTMP_NB_OK;
}

static int nb_streams = 0;
static int handle_invoke(RTMP *r, RTMPPacket *pkt)
{
    uint8_t *body = pkt->m_body;
    int bsz = pkt->m_nBodySize, ret = RTMP_NB_OK;
    double txn;
    AMFObject obj;
    AVal method;

    if (RTMP_PACKET_TYPE_FLEX_MESSAGE ==  pkt->m_packetType) {
        body++;
        bsz--;
    }
    if (0x02 != *body) {
        RTMP_Log(RTMP_LOGWARNING, "%s Sanity failed; no string method"
                 " in invoke packet", __FUNCTION__);
        return RTMP_NB_ERROR;
    }
    if (AMF_Decode(&obj, body, bsz, FALSE) < 0) {
        RTMP_Log(RTMP_LOGERROR, "%s Error decoding invoke packet",
                 __FUNCTION__);
        return RTMP_NB_ERROR;
    }
    AMF_Dump(&obj);
    AMFProp_GetString(AMF_GetProp(&obj, NULL, 0), &method);
    txn = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 1));
    RTMP_Log(RTMP_LOGDEBUG, "%s Client invoking <%s>",
             __FUNCTION__, method.av_val);

    if (AVMATCH(&method, &av_connect)) {
        process_cxn(r, &obj);
        send_cxn_resp(r, txn);
    } else if (AVMATCH(&method, &av_createStream)) {
        send_createstream_resp(r, txn, ++nb_streams);
    } else if (AVMATCH(&method, &av_play)) {
        ret = process_play(r, &obj, pkt);
    } else if (AVMATCH(&method, &av_publish)) {
        ret = process_publish(r, &obj, pkt);
    } else if (AVMATCH(&method, &av_closeStream)) {
        ret = process_close(r, &obj, pkt);
    } else send_error(r, txn, "Unknown method");
    AMF_Reset(&obj);
    return ret;
}

static int handle_notify(RTMP *r, RTMPPacket *pkt)
{
    // XXX hack for leading whitespace in 0x0f messages
    char *body = pkt->m_body;
    int size = pkt->m_nBodySize;
    while (!*body) {
        body++;
        size--;
    }
    if (!memcmp("\x02\x00\x0d@setDataFrame\x02\x00\x0aonMetaData",
                body, 29)) {
        Stream *st;
        int sid = pkt->m_nInfoField2, i;
        for (i = 0; i < MAXS && sid != streams[i].id; i++) {
            if (!streams[i].name.av_val) continue;
        }
        if (i == MAXS) {
            RTMP_Log(RTMP_LOGWARNING, "%s No notify stream found",
                     __FUNCTION__);
            return RTMP_NB_ERROR; // send message to client ??
        }
        st = &streams[i];
        if (st->metadata_sz && st->metadata) {
            RTMP_Log(RTMP_LOGINFO, "%s Resetting metadata",
                     __FUNCTION__);
            free(st->metadata);
            st->metadata_sz = 0;
        }
        body += 16; // skip @setDataFrame only
        size -= 16;
        st->metadata = malloc(size);
        if (!st->metadata) {
            RTMP_Log(RTMP_LOGERROR, "Unable to malloc metadata!");
            exit(1);
        }
        st->metadata_sz = size;
        memcpy(st->metadata, body, size);
        RTMP_Log(RTMP_LOGINFO, "%s Setting metadata", __FUNCTION__);
    }
    return RTMP_NB_OK;
}

static int handle_control(RTMP *r, RTMPPacket *pkt)
{
    char *body = pkt->m_body;
    int bsz = pkt->m_nBodySize, control_id;
    if (bsz < 6) goto control_error; // includes 4-byte control id
    control_id = AMF_DecodeInt16(body);
    body += 2;
    bsz -= 2;
    switch (control_id) {
    default:
        RTMP_Log(RTMP_LOGWARNING, "%s Unhandled control %d",
                 __FUNCTION__, control_id);
    }
    return RTMP_NB_OK;
control_error:
    RTMP_Log(RTMP_LOGWARNING, "%s Not enough bytes in control packet",
             __FUNCTION__);
    return RTMP_NB_ERROR;
}

static int handle_chunksize(RTMP *r, RTMPPacket *packet)
{
    if (packet->m_nBodySize < 4) {
        RTMP_Log(RTMP_LOGWARNING, "%s Not enough bytes in packet",
                 __FUNCTION__);
        return RTMP_NB_ERROR;
    }
    r->m_inChunkSize = AMF_DecodeInt32(packet->m_body);
    RTMP_Log(RTMP_LOGINFO, "%s Incoming chunk size changed to %d",
             __FUNCTION__, r->m_inChunkSize);
    return RTMP_NB_OK;
}

static int handle_media(RTMP *r, RTMPPacket *pkt)
{
    int i, err, id = pkt->m_nInfoField2;
    Stream *st;
    Subscriber *sub;
    for (i = 0; i < MAXS && id != streams[i].id; i++) ;
    if (i == MAXS) {
        RTMP_Log(RTMP_LOGERROR, "%s Stream %d not found!",
                 __FUNCTION__, id);
        return RTMP_NB_ERROR;
    }
    st = &streams[i];
    switch(pkt->m_packetType) {
    case RTMP_PACKET_TYPE_AUDIO:
        if (pkt->m_nBodySize <= 2) break;
        if (160 == (pkt->m_body[0] & 0xf0) && !pkt->m_body[1]) {
            RTMP_Log(RTMP_LOGINFO, "%s Got AAC sequence header",
                     __FUNCTION__);
            if (4 != pkt->m_nBodySize) {
                RTMP_Log(RTMP_LOGWARNING,
                         "%s AAC seq header unexpected size %d!",
                         __FUNCTION__, pkt->m_nBodySize);
                return RTMP_NB_OK;
            }
            st->aac_seq_sz = pkt->m_nBodySize;
            memcpy(st->aac_seq, pkt->m_body, st->aac_seq_sz);
        }
        break;
    case RTMP_PACKET_TYPE_VIDEO:
        if (7 == (pkt->m_body[0] & 0x0f) && !pkt->m_body[1]) {
            if (st->avc_seq && st->avc_seq_sz != pkt->m_nBodySize) {
                RTMP_Log(RTMP_LOGWARNING,
                         "%s Clearing previous AVC sequence header",
                         __FUNCTION__);
                free(st->avc_seq);
                st->avc_seq_sz = 0;
                st->avc_seq = malloc(pkt->m_nBodySize);
                RTMP_Log(RTMP_LOGINFO, "%s Resizing AVC sequence hdr",
                         __FUNCTION__);
            } else if (!st->avc_seq) {
                st->avc_seq = malloc(pkt->m_nBodySize);
                RTMP_Log(RTMP_LOGINFO, "%s Got AVC sequence header",
                         __FUNCTION__);
            }
            if (!st->avc_seq) {
                RTMP_Log(RTMP_LOGERROR, "Unable to malloc AVC seq!");
                exit(1);
            }
            st->avc_seq_sz = pkt->m_nBodySize;
            memcpy(st->avc_seq, pkt->m_body, st->avc_seq_sz);
        }
        break;
    default: break;
    }
    LIST_FOREACH(sub, &st->subscribers, next) {
        RTMP *cr = &contexts[CLIENTIDX(sub->c)];
        if (RTMP_NB_OK != (err = send_media(cr, pkt))) return err;
    }
    return RTMP_NB_OK;
}

static int handle_packet(RTMP *r, RTMPPacket *pkt)
{
    switch (pkt->m_packetType) {
    case RTMP_PACKET_TYPE_CHUNK_SIZE:
        return handle_chunksize(r, pkt);
    case RTMP_PACKET_TYPE_FLEX_MESSAGE:
    case RTMP_PACKET_TYPE_INVOKE:
        return handle_invoke(r, pkt);
    case RTMP_PACKET_TYPE_INFO:
        return handle_notify(r, pkt);
    case RTMP_PACKET_TYPE_AUDIO:
    case RTMP_PACKET_TYPE_VIDEO:
        return handle_media(r, pkt);
    case RTMP_PACKET_TYPE_CONTROL:
        return handle_control(r, pkt);
    case RTMP_PACKET_TYPE_SERVER_BW:
        RTMP_Log(RTMP_LOGINFO, "%s Got server BW; not doing anything",
                 __FUNCTION__);
        break;
    case RTMP_PACKET_TYPE_BYTES_READ_REPORT:
        RTMP_Log(RTMP_LOGINFO, "%s Got Bytes Read Report",
                 __FUNCTION__);
        break;
    default:
        fprintf(stderr, "Got unhandled packet type %d\n",
                pkt->m_packetType);
        return RTMP_NB_ERROR;
    }
    return RTMP_NB_OK;
}

static int setup_client(int *socks, int fd, int is_http)
{
    RTMP *r;
    struct sockaddr_in dest;
    int i, sockflags = fcntl(fd, F_GETFL, 0);
    char ip[INET6_ADDRSTRLEN];
    socklen_t destlen = sizeof(struct sockaddr_in);
    getsockname(fd, (struct sockaddr*)&dest, &destlen);

    for (i = 0; i < MAXC; i++) {
        if (socks[i] == -1) break;
    }
    if (MAXC == i) {
        RTMP_Log(RTMP_LOGERROR, "No more client slots; increase?\n");
        return -1;
    }

    fcntl(fd, F_SETFL, sockflags | O_NONBLOCK);
    socks[i] = fd;
    if (is_http) {
        r = RTMP_Alloc();
        if (!r) {
            RTMP_Log(RTMP_LOGERROR, "Couldn't alloc RTMP context!\n");
            exit(1);
        }
        http_contexts[i] = r;
    } else r = &contexts[i];
    LIST_INSERT_HEAD(&clients_head, &clients[i], next);

    r = &contexts[i];
    RTMP_Init(r);
    r->m_sb.sb_socket = fd;
    if (is_http) r->Link.protocol = RTMP_FEATURE_SHTTP;
    active_contexts[i] = r;
    clients[i].rtmp = r;

    // ipv4 only for now
    if (!inet_ntop(dest.sin_family, &dest.sin_addr, ip, destlen)) {
        RTMP_Log(RTMP_LOGERROR, "Couldn't get incoming IP address!");
        return -1;
    }
    printf("%s accepted connection from %s at index %d\n",
           __FUNCTION__, ip, i);

    return 0;
}

static int cleanup_client(int *socks, int i)
{
    int smax = -1, j;
    RTMP *r = active_contexts[i];
    Client *c = &clients[i];
    printf("closing connection at index %d sockfd %d\n", i, socks[i]);
    if (!(r->Link.protocol & RTMP_FEATURE_SHTTP)) RTMP_Close(r);
    else {
        // for http, only close the socket but keep other state intact
        RTMPSockBuf_Close(&r->m_sb);
        r->m_sb.sb_socket = -1;
    }
    socks[i] = -1;
    for (j = 0; j < MAXC; j++) {
        if (socks[j] > smax) smax = socks[j];
    }
    // clear any streams
    if (!c || r != c->rtmp) {
        RTMP_Log(RTMP_LOGWARNING, "%s RTMP and client context "
                 "mismatch", __FUNCTION__);
        return smax;
    }
    for (j = 0; j < MAXS; j++) {
        int k;
        Stream *s = c->instreams[j];
        if (s) cleanup_stream(s);
        s = c->outstreams[j];
        if (!s) continue;
        LIST_REMOVE(&s->sub_storage[i], next);
        c->outstreams[j] = NULL;
    }
    c->rtmp = NULL;
    LIST_REMOVE(c, next);
    return smax;
}

static int unwrap_http(RTMP **rtmp)
{
    int ret, i;
    AVal clientid;
    RTMP *r = *rtmp;
    if (r->m_contentLength) return RTMP_NB_OK; // have unread content
    if (RTMP_NB_OK != (ret = HTTP_SRead(r, &clientid))) return ret;
    if (AVMATCH(&clientid, &r->m_clientID)) {
        printf("thinger is already matched; do nothing\n");
        return RTMP_NB_EAGAIN;
    } else if (!clientid.av_val && r->m_clientID.av_val) {
        printf("OPEN message ??\n");
        return RTMP_NB_EAGAIN;
    } else if (!r->m_clientID.av_val && clientid.av_val) {
        // not ideal but Good Enough here
        printf("Searching for an existing clientid!\n");
        for (i = 0; i < MAXC; i++) {
            if (!http_contexts[i]) continue;
            if (AVMATCH(&clientid, &http_contexts[i]->m_clientID)) {
                // transplant the fd and buffer
                if (http_contexts[i]->m_sb.sb_socket ==
                    r->m_sb.sb_socket) break;
                memcpy(&http_contexts[i]->m_sb, &r->m_sb,
                       sizeof(RTMPSockBuf));
                break;
            }
        }
        if (i == MAXC) printf("Matching RTMP context not found!\n");
    }
    // return OK if we have leftovers for actual RTMP packets
    return r->m_sb.sb_size ? RTMP_NB_OK : RTMP_NB_EAGAIN;
}

static int serve_client(RTMP *r)
{
    RTMPPacket pkt;
    int ret = RTMPSockBuf_Fill(&r->m_sb);
    if (RTMP_NB_ERROR == ret || r->m_sb.sb_size <= 0)
        return RTMP_NB_ERROR;
    memset(&pkt, 0, sizeof(RTMPPacket));
srv_loop:
    if (r->Link.protocol & RTMP_FEATURE_SHTTP &&
        RTMP_NB_OK != (ret = unwrap_http(&r))) return ret;
    ret = RTMP_ServeNB(r, &pkt);
    switch(ret) {
    case RTMP_NB_ERROR:
    case RTMP_NB_EAGAIN:
        return ret;
    case RTMP_NB_OK:
       ret = handle_packet(r, &pkt);
       RTMPPacket_Free(&pkt);
        if (RTMP_NB_ERROR == ret) return ret;
    default:
        if (r->m_sb.sb_size > 0) goto srv_loop;
    }
    return 1;
}

int main()
{
    memset(streams, 0, sizeof(streams));
    memset(&contexts, 0, sizeof(contexts));
    memset(http_contexts, 0, sizeof(http_contexts));
    memset(active_contexts, 0, sizeof(active_contexts));
    LIST_INIT(&clients_head);
    int rtmpfd = setup_listen(1935);
    int httpfd = setup_listen(8080);
    int socks[MAXC], nb_socks = 0, i, smax = httpfd, nb_listeners = 2;
    fd_set rset, wset;

    if (httpfd < 0 || rtmpfd < 0) return 0;
    memset(socks, -1, sizeof(socks));
    socks[nb_socks++] = rtmpfd;
    socks[nb_socks++] = httpfd;

    RTMP_LogSetLevel(RTMP_LOGDEBUG);
while (1) {
    struct timeval t = {1, 0};
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int ret, sockfd;
    Client *c;

    FD_ZERO(&rset);
    FD_ZERO(&wset);
    for (i = 0; i < nb_listeners; i++) FD_SET(socks[i], &rset);
    LIST_FOREACH(c, &clients_head, next) {
        i = CLIENTIDX(c);
        FD_SET(socks[i], &rset);
        if (active_contexts[i]->wb.wb_ready) FD_SET(socks[i], &wset);
    }
    ret = select(smax + 1, &rset, &wset, NULL, &t);
    if (-1 == ret) goto cleanup;

    // check listeners
    for (i = 0; i < nb_listeners; i++) {
        int lfd = socks[i];
        if (!FD_ISSET(lfd, &rset)) continue;
        sockfd = accept(lfd, (struct sockaddr *) &addr, &addrlen);
        if (sockfd <= 0 && EAGAIN != errno) {
            fprintf(stderr, "%s: accept failed", __FUNCTION__);
        } else if (sockfd >= 0) {
            ret = setup_client(socks, sockfd, lfd == httpfd);
            if (ret < 0) continue;
            nb_socks++;
            smax = sockfd > smax ? sockfd : smax;
        }
    }

    // check clients
    LIST_FOREACH(c, &clients_head, next) {
        int ret;
        i = CLIENTIDX(c);
        if (-1 == socks[i] ||!FD_ISSET(socks[i], &rset)) continue;
        if (RTMP_NB_ERROR != serve_client(active_contexts[i])) continue;
        smax = cleanup_client(socks, i);
        nb_socks--;
    }
    LIST_FOREACH(c, &clients_head, next) {
        i = CLIENTIDX(c);
        if (-1 == socks[i] || !FD_ISSET(socks[i], &wset)) continue;
        if (RTMP_NB_ERROR != RTMP_WriteQueued(active_contexts[i])) continue;
        smax = cleanup_client(socks, i);
        nb_socks--;
    }
}

    printf("Hello, World!\n");
    return 0;
cleanup:
    for (i = 0; i < MAXC; i++) {
        if (-1 != socks[i]) cleanup_client(socks, i);
    }
    printf("goodbye, sad world\n");
    return 0;
}
