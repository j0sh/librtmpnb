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
        fprintf(stderr, "%s, TCP bind failed for port number: %d", __FUNCTION__,
                port);
        return -1;
    }

    if (listen(sockfd, 10) == -1) {
        fprintf(stderr, "%s, listen failed", __FUNCTION__);
        closesocket(sockfd);
        return -1;
    }
    return sockfd;
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
    if (RTMP_NB_OK != RTMP_Serve(&rtmp)) {
        fprintf(stderr, "Handshake failed\n");
        goto cleanup;
    }

    printf("Hello, World!\n");
    return 0;
cleanup:
    RTMP_Close(&rtmp);
    printf("goodbye, sad world\n");
    return 0;
}
