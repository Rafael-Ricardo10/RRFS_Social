# -*- coding: utf-8 -*-
"""RRFS Social - servidor STUN mínimo (RFC 5389, só Binding).
Cada instalação responde "qual é o seu endereço visto de fora?". Assim as
chamadas (WebRTC) conseguem atravessar NAT usando os próprios usuários como
STUN, sem depender de servidores públicos."""
import socket
import struct
import ipaddress
import threading

from .util import log

MAGIC = 0x2112A442


def responder(data, addr):
    """Monta a resposta Binding para um pedido STUN válido (ou None)."""
    if len(data) < 20:
        return None
    tipo, ln, cookie = struct.unpack('>HHI', data[:8])
    if tipo != 0x0001 or cookie != MAGIC or ln != len(data) - 20:
        return None
    txid = data[8:20]
    try:
        ip = ipaddress.ip_address(addr[0].split('%')[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    xp = addr[1] ^ (MAGIC >> 16)
    if ip.version == 4:
        corpo = struct.pack('>BBH', 0, 1, xp) + struct.pack(
            '>I', int(ip) ^ MAGIC)
    else:
        mask = struct.pack('>I', MAGIC) + txid
        corpo = struct.pack('>BBH', 0, 2, xp) + bytes(
            a ^ b for a, b in zip(ip.packed, mask))
    attr = struct.pack('>HH', 0x0020, len(corpo)) + corpo
    return struct.pack('>HHI', 0x0101, len(attr), MAGIC) + txid + attr


class StunServer:
    def __init__(self, porta):
        self.porta, self.ativo = int(porta), False
        self.sock = None

    def iniciar(self):
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.bind(('::', self.porta))
        except OSError:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(('0.0.0.0', self.porta))
            except OSError as e:
                log.info("STUN indisponível na porta %s: %s", self.porta, e)
                return False
        s.settimeout(1.0)
        self.sock, self.ativo = s, True
        threading.Thread(target=self._loop, name='STUN', daemon=True).start()
        return True

    def _loop(self):
        n, t0 = 0, 0.0
        import time
        while self.ativo:
            try:
                data, addr = self.sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                break
            if time.time() - t0 > 1:        # limita a ~300 respostas/s
                t0, n = time.time(), 0
            n += 1
            if n > 300:
                continue
            r = responder(data, addr)
            if r:
                try:
                    self.sock.sendto(r, addr)
                except OSError:
                    pass

    def parar(self):
        self.ativo = False
        try:
            self.sock.close()
        except Exception:
            pass
