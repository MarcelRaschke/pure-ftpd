#include <config.h>

#if !defined(NO_INETD) || defined(IN_PURE_MRTGINFO)
# include "ftpd.h"

# ifdef WITH_DMALLOC
#  include <dmalloc.h>
# endif

# define TCP_STATE_CNX 1UL

static unsigned int count(in_port_t server_port, const char * const file)
{
    int f;
    int r;
    int c;
    int b = 0;
    int e = 0;
    unsigned int d = 0U;
    char buf[2049];

    if ((f = open(file, O_RDONLY)) == -1) {
        return 0;
    }
    buf[2048] = 0;

    for (;;) {
        while ((r = (int) read(f, buf + e, (size_t) (2048U - e)))
               < (ssize_t) 0 && errno == EINTR);
        if (r <= (ssize_t) 0) {    /* ignore errors. 0 is okay, in fact common. */
            break;
        }
        e += r;

        /*
         * b is the offset of the start of the first line to be parsed
         * and e the end of the available data
         */
        c = b;
        while (c < e && buf[c] != '\n') {
            c++;
        }
        while (c < e) {
            buf[c++] = 0;
            while (b < c && buf[b] != ':' && buf[b] != '\n') {
                b++;
            }
            if (b < c && buf[b] == ':') {
                b++;
                while (b < e && buf[b] != ':') {
                    b++;
                }
                b++;
                if (strtoul(buf + b, NULL, 16) ==
                    (unsigned long) server_port) {
                    while (b < e && buf[b] != ':') {
                        b++;
                    }
                    if (buf[b] == ':') {
                        b++;
                        while (b < e && buf[b] != ' ') {
                            b++;
                        }
                        if (buf[b] == ' ') {
                            b++;
                            if (strtoul(buf + b, NULL, 16) == TCP_STATE_CNX) {
                                d++;
                            }
                        }
                    }
                }
            }
            b = c;
            while (c < e && buf[c] != '\n') {
                c++;
            }
        }
        if (e > b) {
            (void) memmove(buf, buf + b, (size_t) (e - b));   /* safe */
        }
        e -= b;
        b = 0;
    }
    close(f);

    return d;
}

unsigned int daemons(const in_port_t server_port)
{
    unsigned int nbcnx;

    nbcnx = count(server_port, "/proc/net/tcp");
    nbcnx += count(server_port, "/proc/net/tcp6");

    return nbcnx;
}

#ifndef IN_PURE_MRTGINFO
static unsigned int count_perip(in_port_t server_port,
                                const struct sockaddr_storage *peer,
                                const char * const file)
{
    int f;
    int r;
    int c;
    int b = 0;
    int e = 0;
    unsigned int d = 0U;
    char buf[2049];
    unsigned char peer_bytes[16];
    size_t peer_len;
    int is_ipv6 = (STORAGE_FAMILY(*peer) == AF_INET6);

    if (is_ipv6) {
        memcpy(peer_bytes, &STORAGE_SIN_ADDR6_CONST(*peer), 16);
        peer_len = 16;
    } else {
        memcpy(peer_bytes, &STORAGE_SIN_ADDR_CONST(*peer), 4);
        peer_len = 4;
    }

    if ((f = open(file, O_RDONLY)) == -1) {
        return 0;
    }
    buf[2048] = 0;

    for (;;) {
        while ((r = (int) read(f, buf + e, (size_t) (2048U - e)))
               < (ssize_t) 0 && errno == EINTR);
        if (r <= (ssize_t) 0) {
            break;
        }
        e += r;

        c = b;
        while (c < e && buf[c] != '\n') {
            c++;
        }
        while (c < e) {
            buf[c++] = 0;
            while (b < c && buf[b] != ':' && buf[b] != '\n') {
                b++;
            }
            if (b < c && buf[b] == ':') {
                b++;
                while (b < e && buf[b] != ':') {
                    b++;
                }
                b++;
                if (strtoul(buf + b, NULL, 16) ==
                    (unsigned long) server_port) {
                    while (b < e && buf[b] != ' ') {
                        b++;
                    }
                    if (buf[b] == ' ') {
                        unsigned char remote_bytes[16];
                        char *hex_start = buf + b + 1;
                        char *colon;
                        size_t hex_len;
                        size_t i;
                        int match = 1;

                        colon = strchr(hex_start, ':');
                        if (colon != NULL) {
                            hex_len = (size_t)(colon - hex_start);
                            if ((hex_len == 8 && peer_len == 4) ||
                                (hex_len == 32 && peer_len == 16)) {
                                for (i = 0; i < peer_len; i++) {
                                    unsigned int byte_val;
                                    char hex_byte[3];
                                    hex_byte[0] = hex_start[i * 2];
                                    hex_byte[1] = hex_start[i * 2 + 1];
                                    hex_byte[2] = 0;
                                    byte_val = (unsigned int) strtoul(hex_byte, NULL, 16);
                                    remote_bytes[i] = (unsigned char) byte_val;
                                }
                                if (peer_len == 4) {
                                    unsigned char swapped[4];
                                    swapped[0] = remote_bytes[3];
                                    swapped[1] = remote_bytes[2];
                                    swapped[2] = remote_bytes[1];
                                    swapped[3] = remote_bytes[0];
                                    memcpy(remote_bytes, swapped, 4);
                                } else {
                                    unsigned char swapped[16];
                                    for (i = 0; i < 4; i++) {
                                        swapped[i * 4 + 0] = remote_bytes[i * 4 + 3];
                                        swapped[i * 4 + 1] = remote_bytes[i * 4 + 2];
                                        swapped[i * 4 + 2] = remote_bytes[i * 4 + 1];
                                        swapped[i * 4 + 3] = remote_bytes[i * 4 + 0];
                                    }
                                    memcpy(remote_bytes, swapped, 16);
                                }
                                for (i = 0; i < peer_len; i++) {
                                    if (remote_bytes[i] != peer_bytes[i]) {
                                        match = 0;
                                        break;
                                    }
                                }
                                if (match) {
                                    while (b < e && buf[b] != ' ') {
                                        b++;
                                    }
                                    b++;
                                    if (strtoul(buf + b, NULL, 16) == TCP_STATE_CNX) {
                                        d++;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            b = c;
            while (c < e && buf[c] != '\n') {
                c++;
            }
        }
        if (e > b) {
            (void) memmove(buf, buf + b, (size_t) (e - b));
        }
        e -= b;
        b = 0;
    }
    close(f);

    return d;
}

unsigned int daemons_perip(const in_port_t server_port,
                           const struct sockaddr_storage *peer)
{
    unsigned int nbcnx;

    if (STORAGE_FAMILY(*peer) == AF_INET6) {
        nbcnx = count_perip(server_port, peer, "/proc/net/tcp6");
    } else {
        nbcnx = count_perip(server_port, peer, "/proc/net/tcp");
    }

    return nbcnx;
}
#endif

#else
extern signed char v6ready;
#endif
