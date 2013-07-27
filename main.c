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
    char *iface = "0.0.0.0";

    if (-1 == sockfd) {
        fprintf(stderr, "%s, couldn't create socket", __FUNCTION__);
        return -1;
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(iface);
    addr.sin_port = htons(port);

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
    char pbuf[256], *pend = pbuf+sizeof(pbuf);

    packet.m_nChannel = 0x03;     // control channel (invoke)
    packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
    packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = 0;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

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
    char pbuf[384];
    char *pend = pbuf + sizeof(pbuf), *enc;
    RTMPPacket packet;
    AVal av;

    packet.m_nChannel = 0x03;     // control channel (invoke)
    packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
    packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = 0;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

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
  char pbuf[384], *pend = pbuf+sizeof(pbuf);
  AMFObject obj;
  AMFObjectProperty p, op;
  AVal av;

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = 0; /* RTMP_PACKET_SIZE_MEDIUM; */
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
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

static int serve(RTMP *r)
{
    int ret = 0;
    RTMPPacket pkt;
    fd_set rset;
    fd_set wset;

    memset(&pkt, 0, sizeof(RTMPPacket));

    while (1) {
        struct timeval t = {1, 0};
        FD_SET(r->m_sb.sb_socket, &rset);
        FD_SET(r->m_sb.sb_socket, &wset);
        int ret = select(r->m_sb.sb_socket + 1, &rset, NULL, NULL, &t);
        if (-1 == ret) {
            fprintf(stderr, "Error in select\n");
            goto serve_error;
        }
        if (!FD_ISSET(r->m_sb.sb_socket, &rset)) continue;
        if (!RTMP_IsConnected(r)) goto serve_cleanup;
        ret = RTMPSockBuf_Fill(&r->m_sb);
        if (RTMP_NB_ERROR == ret || r->m_sb.sb_size <= 0) goto serve_error;
srv_loop:
        ret = RTMP_ServeNB(r, &pkt);
        switch(ret) {
        case RTMP_NB_ERROR: goto serve_error;
        case RTMP_NB_EAGAIN: continue;
        case RTMP_NB_OK:
            handle_packet(r, &pkt);
            RTMPPacket_Free(&pkt);
        default:
            if (r->m_sb.sb_size > 0) goto srv_loop;
        }
    }

serve_cleanup:
    RTMPPacket_Free(&pkt);
    return 0;
serve_error:
    fprintf(stderr, "Server Error\n");
    RTMPPacket_Free(&pkt);
    return -1;
}

int main()
{
    RTMP rtmp;
    memset(&rtmp, 0, sizeof(RTMP));
    int listenfd = setup_listen(1935);

    if (listenfd < 0) return 0;

    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int sockfd =
        accept(listenfd, (struct sockaddr *) &addr, &addrlen);

    if (sockfd <= 0) {
        fprintf(stderr, "%s: accept failed", __FUNCTION__);
    }

    struct sockaddr_in dest;
    char destch[16];
    int sockflags;
    socklen_t destlen = sizeof(struct sockaddr_in);
    getsockopt(sockfd, SOL_IP, SO_ORIGINAL_DST, &dest, &destlen);
    strcpy(destch, inet_ntoa(dest.sin_addr));
    printf("%s: accepted connection from %s to %s\n", __FUNCTION__,
           inet_ntoa(addr.sin_addr), destch);
    sockflags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, sockflags | O_NONBLOCK);

    RTMP_LogSetLevel(RTMP_LOGERROR);
    RTMP_Init(&rtmp);
    rtmp.m_sb.sb_socket = sockfd;

    if (serve(&rtmp) < 0) goto cleanup;

    printf("Hello, World!\n");
    return 0;
cleanup:
    RTMP_Close(&rtmp);
    printf("goodbye, sad world\n");
    return 0;
}
