#include <stdio.h>
#include <string.h>
#include <sys/fcntl.h>

#include "librtmpnb/rtmp_sys.h"
#include "librtmpnb/log.h"

#ifdef linux
#include <linux/netfilter_ipv4.h>
#endif

static int setup_listen()
{
    struct sockaddr_in addr;
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), tmp = 1;
    int port = 1935;
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
srv_loop:
        ret = RTMP_ServeNB(r, &pkt);
        switch(ret) {
        case RTMP_NB_ERROR: goto serve_error;
        case RTMP_NB_EAGAIN: continue;
        case RTMP_NB_OK:
            printf("Got packet! type %d\n", pkt.m_packetType);
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
    int listenfd = setup_listen();

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
