#!/usr/bin/env python3
# Mock SOCKS5 proxy for testing private broadcast
# Redirects all .onion connections to a specified local port
# Usage: python3 mock_socks5_proxy.py <listen_port> <redirect_host> <redirect_port>

import socket
import select
import sys
import threading
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')
logger = logging.getLogger('mock_socks5')

def recvall(s, n):
    """Receive n bytes from a socket, or fail."""
    rv = bytearray()
    while n > 0:
        d = s.recv(n)
        if not d:
            raise IOError('Unexpected end of stream')
        rv.extend(d)
        n -= len(d)
    return rv

def forward_sockets(a, b):
    """Forward data between two sockets until one closes."""
    a.setblocking(False)
    b.setblocking(False)
    sockets = [a, b]
    done = False
    while not done:
        try:
            rlist, _, xlist = select.select(sockets, [], sockets, 1.0)
            if len(xlist) > 0:
                break
            for s in rlist:
                try:
                    data = s.recv(4096)
                    if data is None or len(data) == 0:
                        done = True
                        break
                    if s == a:
                        b.sendall(data)
                    else:
                        a.sendall(data)
                except (BlockingIOError, socket.error):
                    pass
        except Exception as e:
            logger.debug(f"Forward error: {e}")
            break

def handle_connection(conn, redirect_host, redirect_port):
    """Handle a single SOCKS5 connection."""
    try:
        # SOCKS5 greeting
        ver = recvall(conn, 1)[0]
        if ver != 0x05:
            logger.error(f'Invalid SOCKS version {ver}')
            return

        nmethods = recvall(conn, 1)[0]
        methods = bytearray(recvall(conn, nmethods))

        # Accept no-auth or username/password
        if 0x00 in methods:
            conn.sendall(bytearray([0x05, 0x00]))  # No auth
        elif 0x02 in methods:
            conn.sendall(bytearray([0x05, 0x02]))  # Username/password
            # Read and accept any credentials
            ver = recvall(conn, 1)[0]
            ulen = recvall(conn, 1)[0]
            username = recvall(conn, ulen)
            plen = recvall(conn, 1)[0]
            password = recvall(conn, plen)
            conn.sendall(bytearray([0x01, 0x00]))  # Auth success
        else:
            conn.sendall(bytearray([0x05, 0xFF]))  # No acceptable method
            return

        # Read connect request
        ver, cmd, _, atyp = recvall(conn, 4)
        if ver != 0x05:
            logger.error(f'Invalid SOCKS version in request: {ver}')
            return
        if cmd != 0x01:  # Only CONNECT supported
            logger.error(f'Unsupported command: {cmd}')
            conn.sendall(bytearray([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
            return

        # Read address
        if atyp == 0x01:  # IPv4
            addr = socket.inet_ntoa(recvall(conn, 4))
        elif atyp == 0x03:  # Domain name
            n = recvall(conn, 1)[0]
            addr = recvall(conn, n).decode('utf-8')
        elif atyp == 0x04:  # IPv6
            addr = socket.inet_ntop(socket.AF_INET6, recvall(conn, 16))
        else:
            logger.error(f'Unknown address type: {atyp}')
            return

        port_hi, port_lo = recvall(conn, 2)
        port = (port_hi << 8) | port_lo

        logger.info(f'Connect request to {addr}:{port}')

        # Send success response (before connecting, like real Tor does)
        conn.sendall(bytearray([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

        # Redirect all connections (especially .onion) to the target
        logger.info(f'Redirecting to {redirect_host}:{redirect_port}')
        try:
            with socket.create_connection((redirect_host, redirect_port), timeout=10) as target:
                logger.info(f'Connected to target, forwarding data...')
                forward_sockets(conn, target)
        except Exception as e:
            logger.error(f'Failed to connect to target: {e}')

    except Exception as e:
        logger.exception(f'Error handling connection: {e}')
    finally:
        try:
            conn.close()
        except:
            pass

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <listen_port> <redirect_host> <redirect_port>")
        print(f"Example: {sys.argv[0]} 9050 127.0.0.1 18545")
        sys.exit(1)

    listen_port = int(sys.argv[1])
    redirect_host = sys.argv[2]
    redirect_port = int(sys.argv[3])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', listen_port))
    server.listen(10)

    logger.info(f'Mock SOCKS5 proxy listening on 127.0.0.1:{listen_port}')
    logger.info(f'Redirecting all connections to {redirect_host}:{redirect_port}')

    try:
        while True:
            conn, addr = server.accept()
            logger.debug(f'Connection from {addr}')
            thread = threading.Thread(target=handle_connection, args=(conn, redirect_host, redirect_port))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        logger.info('Shutting down...')
    finally:
        server.close()

if __name__ == '__main__':
    main()
