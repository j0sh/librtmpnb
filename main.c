#include <stdio.h>
#include <string.h>
#include <sys/fcntl.h>

#include "librtmpnb/rtmp_sys.h"
#include "librtmpnb/log.h"

#ifdef linux
#include <linux/netfilter_ipv4.h>
#endif

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
    return sockfd;
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

static int send_createstream_resp(RTMP *r, double txn, double ID)
{
    RTMPPacket packet;
    char *pbuf = RTMP_PacketBody(r, 256), *pend = pbuf + 256;

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

    return RTMP_SendPacket(r, &packet, FALSE);
}

static int send_error(RTMP *r, double txn, char *desc)
{
    char *pbuf = RTMP_PacketBody(r, 384), *pend = pbuf + 384, *enc;
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

static int send_cxn_resp(RTMP *r, double txn)
{
  RTMPPacket packet;
  char *pbuf = RTMP_PacketBody(r, 384), *pend = pbuf + 384, *enc;
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

static int nb_streams = 0;
static void handle_invoke(RTMP *r, RTMPPacket *pkt)
{
    uint8_t *body = pkt->m_body;
    int bsz = pkt->m_nBodySize;
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
        return;
    }
    if (AMF_Decode(&obj, body, bsz, FALSE) < 0) {
        RTMP_Log(RTMP_LOGERROR, "%s Error decoding invoke packet",
                 __FUNCTION__);
        return;
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
    } else if (AVMATCH(&method, &av_publish)) {
    } else send_error(r, txn, "Unknown method");
    AMF_Reset(&obj);
}

static void handle_packet(RTMP *r, RTMPPacket *pkt)
{
    switch (pkt->m_packetType) {
    case RTMP_PACKET_TYPE_FLEX_MESSAGE:
    case RTMP_PACKET_TYPE_INVOKE:
        handle_invoke(r, pkt);
        break;
    case RTMP_PACKET_TYPE_AUDIO:
    case RTMP_PACKET_TYPE_VIDEO:
        break;
    default:
        fprintf(stderr, "Got unhandled packet type %d\n",
                pkt->m_packetType);
    }
}

#define MAXC 100
static int setup_client(RTMP *rtmps, int *socks, int fd)
{
    RTMP *r;
    struct sockaddr_in dest;
    int i, sockflags = fcntl(fd, F_GETFL, 0);
    socklen_t destlen = sizeof(struct sockaddr_in);
    getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &dest, &destlen);

    for (i = 0; i < MAXC; i++) {
        if (socks[i] == -1) break;
    }
    if (MAXC == i) {
        RTMP_Log(RTMP_LOGERROR, "No more client slots; increase?\n");
        return -1;
    }

    fcntl(fd, F_SETFL, sockflags | O_NONBLOCK);
    socks[i] = fd;
    r = &rtmps[i];
    RTMP_Init(r);
    r->m_sb.sb_socket = fd;

    printf("%s accepted connection from %s at index %d\n",
           __FUNCTION__, inet_ntoa(dest.sin_addr), i);

    return 0;
}

static int cleanup_client(RTMP *rtmps, int *socks, int i)
{
    int smax = -1;
    printf("closing connection at index %d\n", i);
    RTMP_Close(&rtmps[i]);
    close(socks[i]);
    socks[i] = -1;
    for (i = 0; i < MAXC; i++) {
        if (socks[i] > smax) smax = socks[i];
    }
    return smax;
}

static int serve_client(RTMP *r)
{
    RTMPPacket pkt;
    int ret = RTMPSockBuf_Fill(&r->m_sb);
    if (RTMP_NB_ERROR == ret || r->m_sb.sb_size <= 0)
        return RTMP_NB_ERROR;
    memset(&pkt, 0, sizeof(RTMPPacket));
srv_loop:
    ret = RTMP_ServeNB(r, &pkt);
    switch(ret) {
    case RTMP_NB_ERROR:
    case RTMP_NB_EAGAIN:
        return ret;
    case RTMP_NB_OK:
       handle_packet(r, &pkt);
       RTMPPacket_Free(&pkt);
    default:
        if (r->m_sb.sb_size > 0) goto srv_loop;
    }
    return 1;
}

int main()
{
    RTMP rtmps[MAXC];
    memset(rtmps, 0, sizeof(rtmps));
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

    FD_ZERO(&rset);
    FD_ZERO(&wset);
    for (i = 0; i < MAXC; i++) {
        if (-1 == socks[i]) continue;
        FD_SET(socks[i], &rset);
        if (i < nb_listeners) continue;
        if (rtmps[i].wq_ready) FD_SET(socks[i], &wset);
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
            ret = setup_client(rtmps, socks, sockfd);
            if (ret < 0) continue;
            nb_socks++;
            smax = sockfd > smax ? sockfd : smax;
        }
    }

    // check clients
    for (i = nb_listeners; i < MAXC; i++) {
        RTMP *r = &rtmps[i];
        if (-1 == socks[i] ||!FD_ISSET(socks[i], &rset)) continue;
        if (RTMP_NB_ERROR != serve_client(r)) continue;
        smax = cleanup_client(rtmps, socks, i);
        nb_socks--;
    }
    for (i = nb_listeners; i < MAXC; i++) {
        if (-1 == socks[i] || !FD_ISSET(socks[i], &wset)) continue;
        if (RTMP_NB_ERROR != RTMP_WriteQueued(&rtmps[i])) continue;
        smax = cleanup_client(rtmps, socks, i);
        nb_socks--;
    }
}

    printf("Hello, World!\n");
    return 0;
cleanup:
    for (i = 0; i < MAXC; i++) {
        RTMP_Close(&rtmps[i]);
        if (-1 != socks[i]) close(socks[i]);
    }
    printf("goodbye, sad world\n");
    return 0;
}
