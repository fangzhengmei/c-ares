/* MIT License
 *
 * Copyright (c) Massachusetts Institute of Technology
 * Copyright (c) The c-ares project and its contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ares_private.h"
#ifdef HAVE_SYS_UIO_H
#  include <sys/uio.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#  include <netinet/tcp.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#ifdef NETWARE
#  include <sys/filio.h>
#endif

#include <assert.h>
#include <fcntl.h>
#include <limits.h>

static ares_conn_err_t ares_socket_deref_error(int err)
{
  switch (err) {
#if defined(EWOULDBLOCK)
    case EWOULDBLOCK:
      return ARES_CONN_ERR_WOULDBLOCK;
#endif
#if defined(EAGAIN) && (!defined(EWOULDBLOCK) || EAGAIN != EWOULDBLOCK)
    case EAGAIN:
      return ARES_CONN_ERR_WOULDBLOCK;
#endif
    case EINPROGRESS:
      return ARES_CONN_ERR_WOULDBLOCK;
    case ENETDOWN:
      return ARES_CONN_ERR_NETDOWN;
    case ENETUNREACH:
      return ARES_CONN_ERR_NETUNREACH;
    case ECONNABORTED:
      return ARES_CONN_ERR_CONNABORTED;
    case ECONNRESET:
      return ARES_CONN_ERR_CONNRESET;
    case ECONNREFUSED:
      return ARES_CONN_ERR_CONNREFUSED;
    case ETIMEDOUT:
      return ARES_CONN_ERR_CONNTIMEDOUT;
    case EHOSTDOWN:
      return ARES_CONN_ERR_HOSTDOWN;
    case EHOSTUNREACH:
      return ARES_CONN_ERR_HOSTUNREACH;
    case EINTR:
      return ARES_CONN_ERR_INTERRUPT;
    case EAFNOSUPPORT:
      return ARES_CONN_ERR_AFNOSUPPORT;
    case EADDRNOTAVAIL:
      return ARES_CONN_ERR_BADADDR;
    default:
      break;
  }

  return ARES_CONN_ERR_FAILURE;
}

/*! Map the error code left by a socket callback that reported failure
 *  (a negative return value).  A compliant callback sets errno (or
 *  WSASetLastError()); one that returns a negative value without doing so
 *  would otherwise leave SOCKERRNO at zero or at a stale value set by an
 *  unrelated call -- for example a leftover EAGAIN, which would make a hard
 *  failure look like ARES_CONN_ERR_WOULDBLOCK and strand the query waiting
 *  for an event that never comes.  Treat the missing error code as a generic
 *  failure so the connection goes through the normal error/retry path.
 *
 *  \return Connection error mapped from SOCKERRNO, or ARES_CONN_ERR_FAILURE
 *          when the callback left no error code.
 */
static ares_conn_err_t ares_socket_deref_negative(void)
{
  if (SOCKERRNO == 0) {
    SET_SOCKERRNO(EIO);
  }
  return ares_socket_deref_error(SOCKERRNO);
}

/*! Validate the structure of a source sockaddr handed back by an
 *  application-provided receive callback.  Only the structure is checked
 *  here; whether the address actually matches the queried server is a
 *  separate semantic check in ares_conn_read() (RFC 5452 section 9.1).
 *
 *  \param[in] from      Source address buffer the callback was asked to fill,
 *                       or NULL when no address was requested.
 *  \param[in] from_len  Pointer to the address length, or NULL alongside a
 *                       NULL from.
 *  \return ARES_CONN_ERR_SUCCESS when the structure is well-formed or no
 *          address was provided; ARES_CONN_ERR_INVALID otherwise.
 */
static ares_conn_err_t
  ares_socket_validate_recv_addr(const struct sockaddr    *from,
                                 const ares_socklen_t     *from_len)
{
  size_t addr_len;

  if (from == NULL || from_len == NULL) {
    return ARES_CONN_ERR_SUCCESS;
  }

  if (*from_len <= 0) {
    return ARES_CONN_ERR_INVALID;
  }
  addr_len = (size_t)*from_len;

  switch (from->sa_family) {
    case AF_INET:
      if (addr_len < sizeof(struct sockaddr_in)) {
        return ARES_CONN_ERR_INVALID;
      }
      break;
    case AF_INET6:
      if (addr_len < sizeof(struct sockaddr_in6)) {
        return ARES_CONN_ERR_INVALID;
      }
      break;
    case AF_UNSPEC:
      /* The callback did not report a source address.  The semantic check in
       * ares_conn_read() drops the datagram where an address is required. */
      break;
    default:
      return ARES_CONN_ERR_INVALID;
  }

  return ARES_CONN_ERR_SUCCESS;
}

ares_bool_t ares_sockaddr_addr_eq(const struct sockaddr  *sa,
                                  const struct ares_addr *aa)
{
  const void *addr1;
  const void *addr2;

  if (sa->sa_family == aa->family) {
    switch (aa->family) {
      case AF_INET:
        addr1 = &aa->addr.addr4;
        addr2 = &(CARES_INADDR_CAST(const struct sockaddr_in *, sa))->sin_addr;
        if (memcmp(addr1, addr2, sizeof(aa->addr.addr4)) == 0) {
          return ARES_TRUE; /* match */
        }
        break;
      case AF_INET6:
        addr1 = &aa->addr.addr6;
        addr2 =
          &(CARES_INADDR_CAST(const struct sockaddr_in6 *, sa))->sin6_addr;
        if (memcmp(addr1, addr2, sizeof(aa->addr.addr6)) == 0) {
          return ARES_TRUE; /* match */
        }
        break;
      default:
        break; /* LCOV_EXCL_LINE */
    }
  }
  return ARES_FALSE; /* different */
}

ares_bool_t ares_sockaddr_addr_port_eq(const struct sockaddr  *sa,
                                       const struct ares_addr *aa,
                                       unsigned short          port)
{
  unsigned short sa_port;

  if (!ares_sockaddr_addr_eq(sa, aa)) {
    return ARES_FALSE;
  }

  /* ares_sockaddr_addr_eq() only matches AF_INET and AF_INET6 */
  if (sa->sa_family == AF_INET) {
    sa_port = (CARES_INADDR_CAST(const struct sockaddr_in *, sa))->sin_port;
  } else {
    sa_port = (CARES_INADDR_CAST(const struct sockaddr_in6 *, sa))->sin6_port;
  }

  /* A port of 0 means the source port was not reported, so only the address
   * can be checked. */
  if (sa_port != 0 && ntohs(sa_port) != port) {
    return ARES_FALSE;
  }

  return ARES_TRUE;
}

ares_conn_err_t ares_socket_write(ares_channel_t *channel, ares_socket_t fd,
                                  const void *data, size_t len, size_t *written,
                                  const struct sockaddr *sa,
                                  ares_socklen_t         salen)
{
  int             flags = 0;
  ares_ssize_t    rv;
  ares_conn_err_t err = ARES_CONN_ERR_SUCCESS;

#ifdef HAVE_MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif

  rv = channel->sock_funcs.asendto(fd, data, len, flags, sa, salen,
                                   channel->sock_func_cb_data);
  if (rv > 0) {
    if ((size_t)rv > len) {
      /* The callback claims to have written more than it was given.  Never
       * report an impossible byte count to the caller, which would desync its
       * output buffer tracking. */
      SET_SOCKERRNO(EMSGSIZE);
      return ARES_CONN_ERR_TOOLARGE;
    }
    *written = (size_t)rv;
    return ARES_CONN_ERR_SUCCESS;
  }

  if (rv == 0) {
    err = ares_socket_deref_error(SOCKERRNO);
  } else {
    err = ares_socket_deref_negative();
  }
  return err;
}

/*! Core receive path shared by ares_socket_recv() and
 *  ares_socket_recvfrom().  The receive callback is application code, so every
 *  value it returns is validated here before anything it produced reaches the
 *  DNS parser:
 *  - a length larger than the destination buffer is rejected instead of
 *    overflowing the connection's input buffer;
 *  - a negative result without an error code is mapped to a deterministic
 *    failure rather than a stale errno such as EAGAIN;
 *  - the source sockaddr, when requested, must be well-formed.
 *
 *  \param[in]     channel     Channel owning the socket functions.
 *  \param[in]     s           Socket to read from.
 *  \param[in]     is_tcp      ARES_TRUE for a connected TCP socket.
 *  \param[out]    data        Destination buffer.
 *  \param[in]     data_len    Size of the destination buffer.
 *  \param[in]     flags       Flags passed to the callback.
 *  \param[in,out] from        Source address buffer, or NULL.
 *  \param[in,out] from_len    Source address length pointer, or NULL.
 *  \param[out]    read_bytes  Number of validated bytes read.
 *  \return ARES_CONN_ERR_SUCCESS on success (including a 0-byte UDP datagram),
 *          ARES_CONN_ERR_CONNCLOSED on a TCP peer shutdown, or a deterministic
 *          connection error when the callback misbehaved or failed.
 */
static ares_conn_err_t
  ares_socket_recvfrom_core(ares_channel_t *channel, ares_socket_t s,
                            ares_bool_t is_tcp, void *data, size_t data_len,
                            int flags, struct sockaddr *from,
                            ares_socklen_t *from_len, size_t *read_bytes)
{
  ares_ssize_t rv;

  *read_bytes = 0;

  rv = channel->sock_funcs.arecvfrom(s, data, data_len, flags, from, from_len,
                                     channel->sock_func_cb_data);

  if (rv > 0) {
    ares_conn_err_t err;

    /* The returned length must not exceed the buffer the callback was given.
     * A lying callback must not be allowed to make the caller consume or
     * parse memory past the end of its buffer. */
    if ((size_t)rv > data_len) {
      SET_SOCKERRNO(EMSGSIZE);
      return ARES_CONN_ERR_TOOLARGE;
    }

    /* Validate the structure of any source address before a semantic
     * comparison against the queried server can touch it. */
    err = ares_socket_validate_recv_addr(from, from_len);
    if (err != ARES_CONN_ERR_SUCCESS) {
      SET_SOCKERRNO(EINVAL);
      return err;
    }

    *read_bytes = (size_t)rv;
    return ARES_CONN_ERR_SUCCESS;
  }

  if (rv == 0) {
    /* UDP allows 0-byte packets and is connectionless, so this is success */
    if (!is_tcp) {
      return ARES_CONN_ERR_SUCCESS;
    } else {
      return ARES_CONN_ERR_CONNCLOSED;
    }
  }

  /* If we're here, rv<0 */
  return ares_socket_deref_negative();
}

ares_conn_err_t ares_socket_recv(ares_channel_t *channel, ares_socket_t s,
                                 ares_bool_t is_tcp, void *data,
                                 size_t data_len, size_t *read_bytes)
{
  return ares_socket_recvfrom_core(channel, s, is_tcp, data, data_len, 0, NULL,
                                   NULL, read_bytes);
}

ares_conn_err_t ares_socket_recvfrom(ares_channel_t *channel, ares_socket_t s,
                                     ares_bool_t is_tcp, void *data,
                                     size_t data_len, int flags,
                                     struct sockaddr *from,
                                     ares_socklen_t  *from_len,
                                     size_t          *read_bytes)
{
  return ares_socket_recvfrom_core(channel, s, is_tcp, data, data_len, flags,
                                   from, from_len, read_bytes);
}

ares_conn_err_t ares_socket_enable_tfo(const ares_channel_t *channel,
                                       ares_socket_t         fd)
{
  ares_bool_t opt = ARES_TRUE;

  if (channel->sock_funcs.asetsockopt(fd, ARES_SOCKET_OPT_TCP_FASTOPEN,
                                      (void *)&opt, sizeof(opt),
                                      channel->sock_func_cb_data) != 0) {
    return ARES_CONN_ERR_NOTIMP;
  }

  return ARES_CONN_ERR_SUCCESS;
}

ares_status_t ares_socket_configure(ares_channel_t *channel, int family,
                                    ares_bool_t is_tcp, ares_socket_t fd)
{
  union {
    struct sockaddr     sa;
    struct sockaddr_in  sa4;
    struct sockaddr_in6 sa6;
  } local;

  ares_socklen_t bindlen = 0;
  int            rv;
  unsigned int   bind_flags = 0;

  /* Set the socket's send and receive buffer sizes. */
  if (channel->socket_send_buffer_size > 0) {
    rv = channel->sock_funcs.asetsockopt(
      fd, ARES_SOCKET_OPT_SENDBUF_SIZE,
      (void *)&channel->socket_send_buffer_size,
      sizeof(channel->socket_send_buffer_size), channel->sock_func_cb_data);
    if (rv != 0 && SOCKERRNO != ENOSYS) {
      return ARES_ECONNREFUSED; /* LCOV_EXCL_LINE: UntestablePath */
    }
  }

  if (channel->socket_receive_buffer_size > 0) {
    rv = channel->sock_funcs.asetsockopt(
      fd, ARES_SOCKET_OPT_RECVBUF_SIZE,
      (void *)&channel->socket_receive_buffer_size,
      sizeof(channel->socket_receive_buffer_size), channel->sock_func_cb_data);
    if (rv != 0 && SOCKERRNO != ENOSYS) {
      return ARES_ECONNREFUSED; /* LCOV_EXCL_LINE: UntestablePath */
    }
  }

  /* Bind to network interface if configured */
  if (ares_strlen(channel->local_dev_name)) {
    /* Prior versions silently ignored failure, so we need to maintain that
     * compatibility */
    (void)channel->sock_funcs.asetsockopt(
      fd, ARES_SOCKET_OPT_BIND_DEVICE, channel->local_dev_name,
      (ares_socklen_t)ares_strlen(channel->local_dev_name),
      channel->sock_func_cb_data);
  }

  /* Bind to ip address if configured */
  if (family == AF_INET && channel->local_ip4) {
    memset(&local.sa4, 0, sizeof(local.sa4));
    local.sa4.sin_family      = AF_INET;
    local.sa4.sin_addr.s_addr = htonl(channel->local_ip4);
    bindlen                   = sizeof(local.sa4);
  } else if (family == AF_INET6 &&
             memcmp(channel->local_ip6, ares_in6addr_any._S6_un._S6_u8,
                    sizeof(channel->local_ip6)) != 0) {
    /* Only if not link-local and an ip other than "::" is specified */
    memset(&local.sa6, 0, sizeof(local.sa6));
    local.sa6.sin6_family = AF_INET6;
    memcpy(&local.sa6.sin6_addr, channel->local_ip6,
           sizeof(channel->local_ip6));
    bindlen = sizeof(local.sa6);
  }


  if (bindlen && channel->sock_funcs.abind != NULL) {
    bind_flags |= ARES_SOCKET_BIND_CLIENT;
    if (is_tcp) {
      bind_flags |= ARES_SOCKET_BIND_TCP;
    }
    if (channel->sock_funcs.abind(fd, bind_flags, &local.sa, bindlen,
                                  channel->sock_func_cb_data) != 0) {
      return ARES_ECONNREFUSED;
    }
  }

  return ARES_SUCCESS;
}

ares_bool_t ares_sockaddr_to_ares_addr(struct ares_addr      *ares_addr,
                                       unsigned short        *port,
                                       const struct sockaddr *sockaddr)
{
  if (sockaddr->sa_family == AF_INET) {
    /* NOTE: memcpy sockaddr_in due to alignment issues found by UBSAN due to
     *       dnsinfo packing on MacOS */
    struct sockaddr_in sockaddr_in;
    memcpy(&sockaddr_in, sockaddr, sizeof(sockaddr_in));

    ares_addr->family = AF_INET;
    memcpy(&ares_addr->addr.addr4, &(sockaddr_in.sin_addr),
           sizeof(ares_addr->addr.addr4));

    if (port) {
      *port = ntohs(sockaddr_in.sin_port);
    }
    return ARES_TRUE;
  }

  if (sockaddr->sa_family == AF_INET6) {
    /* NOTE: memcpy sockaddr_in6 due to alignment issues found by UBSAN due to
     *       dnsinfo packing on MacOS */
    struct sockaddr_in6 sockaddr_in6;
    memcpy(&sockaddr_in6, sockaddr, sizeof(sockaddr_in6));

    ares_addr->family = AF_INET6;
    memcpy(&ares_addr->addr.addr6, &(sockaddr_in6.sin6_addr),
           sizeof(ares_addr->addr.addr6));
    if (port) {
      *port = ntohs(sockaddr_in6.sin6_port);
    }
    return ARES_TRUE;
  }

  return ARES_FALSE;
}

ares_conn_err_t ares_socket_open(ares_socket_t *sock, ares_channel_t *channel,
                                 int af, int type, int protocol)
{
  ares_socket_t s;

  *sock = ARES_SOCKET_BAD;

  s =
    channel->sock_funcs.asocket(af, type, protocol, channel->sock_func_cb_data);

  if (s == ARES_SOCKET_BAD) {
    return ares_socket_deref_error(SOCKERRNO);
  }

  *sock = s;

  return ARES_CONN_ERR_SUCCESS;
}

ares_conn_err_t ares_socket_connect(ares_channel_t *channel,
                                    ares_socket_t sockfd, ares_bool_t is_tfo,
                                    const struct sockaddr *addr,
                                    ares_socklen_t         addrlen)
{
  ares_conn_err_t err   = ARES_CONN_ERR_SUCCESS;
  unsigned int    flags = 0;

  if (is_tfo) {
    flags |= ARES_SOCKET_CONN_TCP_FASTOPEN;
  }

  do {
    int rv;

    rv = channel->sock_funcs.aconnect(sockfd, addr, addrlen, flags,
                                      channel->sock_func_cb_data);

    if (rv < 0) {
      err = ares_socket_deref_error(SOCKERRNO);
    } else {
      err = ARES_CONN_ERR_SUCCESS;
    }
  } while (err == ARES_CONN_ERR_INTERRUPT);

  return err;
}

void ares_socket_close(ares_channel_t *channel, ares_socket_t s)
{
  if (channel == NULL || s == ARES_SOCKET_BAD) {
    return;
  }

  channel->sock_funcs.aclose(s, channel->sock_func_cb_data);
}

void ares_set_socket_callback(ares_channel_t           *channel,
                              ares_sock_create_callback cb, void *data)
{
  if (channel == NULL) {
    return;
  }
  channel->sock_create_cb      = cb;
  channel->sock_create_cb_data = data;
}

void ares_set_socket_configure_callback(ares_channel_t           *channel,
                                        ares_sock_config_callback cb,
                                        void                     *data)
{
  if (channel == NULL || channel->optmask & ARES_OPT_EVENT_THREAD) {
    return;
  }
  channel->sock_config_cb      = cb;
  channel->sock_config_cb_data = data;
}

void ares_set_pending_write_cb(ares_channel_t       *channel,
                               ares_pending_write_cb callback, void *user_data)
{
  if (channel == NULL || channel->optmask & ARES_OPT_EVENT_THREAD) {
    return;
  }
  channel->notify_pending_write_cb      = callback;
  channel->notify_pending_write_cb_data = user_data;
}
