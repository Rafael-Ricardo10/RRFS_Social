# -*- coding: utf-8 -*-
"""RRFS Social - identidade/transporte Tox (libtoxcore via ctypes).
Pacotes lossless customizados: 160 = JSON fragmentado, 161 = pedaço binário
de arquivo. libtoxcore NÃO é thread-safe: tudo sob uma RLock."""
import os
import time
import json
import queue
import struct
import ctypes
import socket
import secrets
import threading
import ctypes.util

from .util import (log, PACOTE_DADOS, PACOTE_BIN, MAX_FRAGMENTO,
                   MAX_FRAGMENTOS_MSG, ERRO_SENDQ, TIMEOUT_FRAGMENTOS,
                   TOX_ADDRESS_SIZE)

_LIB = None


def carregar_libtoxcore():
    global _LIB
    if _LIB is not None:
        return _LIB
    nomes = ['libtoxcore.so', 'libtoxcore.so.2', 'libtoxcore.so.1',
             'libtoxcore.so.0', 'libtoxcore.dylib', 'libtoxcore.dll',
             'toxcore.dll']
    achado = ctypes.util.find_library('toxcore')
    if achado:
        nomes.insert(0, achado)
    erro = None
    for nome in nomes:
        try:
            lib = ctypes.CDLL(nome)
            _assinaturas(lib)
            _LIB = lib
            return lib
        except (OSError, AttributeError) as e:
            erro = e
    raise RuntimeError(f"libtoxcore não encontrada/compatível: {erro}")


def _assinaturas(lib):
    vp, ci = ctypes.c_void_p, ctypes.c_int
    u8p = ctypes.POINTER(ctypes.c_uint8)
    u32, u16 = ctypes.c_uint32, ctypes.c_uint16
    st, cb, cp = ctypes.c_size_t, ctypes.c_bool, ctypes.c_char_p
    eri = ctypes.POINTER(ci)

    def fn(nome, rt, at):
        f = getattr(lib, nome)
        f.restype, f.argtypes = rt, at

    fn('tox_options_new', vp, [eri])
    fn('tox_options_free', None, [vp])
    fn('tox_options_set_ipv6_enabled', None, [vp, cb])
    fn('tox_options_set_udp_enabled', None, [vp, cb])
    fn('tox_options_set_local_discovery_enabled', None, [vp, cb])
    fn('tox_options_set_savedata_type', None, [vp, ci])
    fn('tox_options_set_savedata_data', None, [vp, u8p, st])
    fn('tox_new', vp, [vp, eri])
    fn('tox_kill', None, [vp])
    fn('tox_bootstrap', cb, [vp, cp, u16, u8p, eri])
    fn('tox_add_tcp_relay', cb, [vp, cp, u16, u8p, eri])
    fn('tox_iteration_interval', u32, [vp])
    fn('tox_iterate', None, [vp, vp])
    fn('tox_self_get_address', None, [vp, u8p])
    fn('tox_self_get_connection_status', ci, [vp])
    fn('tox_get_savedata_size', st, [vp])
    fn('tox_get_savedata', None, [vp, u8p])
    fn('tox_friend_add', u32, [vp, u8p, u8p, st, eri])
    fn('tox_friend_add_norequest', u32, [vp, u8p, eri])
    fn('tox_friend_delete', cb, [vp, u32, eri])
    fn('tox_friend_get_public_key', cb, [vp, u32, u8p, eri])
    fn('tox_friend_send_lossless_packet', cb, [vp, u32, u8p, st, eri])
    fn('tox_self_get_friend_list_size', st, [vp])
    fn('tox_self_get_friend_list', None, [vp, ctypes.POINTER(u32)])
    fn('tox_callback_self_connection_status', None, [vp, vp])
    fn('tox_callback_friend_request', None, [vp, vp])
    fn('tox_callback_friend_connection_status', None, [vp, vp])
    fn('tox_callback_friend_lossless_packet', None, [vp, vp])
    for nome, rt, at in (
            ('tox_options_set_start_port', None, [vp, u16]),
            ('tox_options_set_end_port', None, [vp, u16]),
            ('tox_options_set_tcp_port', None, [vp, u16]),
            ('tox_self_get_dht_id', None, [vp, u8p]),
            ('tox_self_get_udp_port', u16, [vp, eri])):
        try:
            f = getattr(lib, nome)
            f.restype, f.argtypes = rt, at
        except AttributeError:
            log.warning("libtoxcore sem %s (recurso opcional)", nome)


def medir_latencia_nos(nos, timeout=1.5):
    res, trava, fila = {}, threading.Lock(), list(enumerate(nos))

    def trab():
        while True:
            with trava:
                if not fila:
                    return
                i, no = fila.pop()
            rtt = None
            try:
                tcp = int((no.get('tcp_ports') or [no['porta']])[0])
                t0 = time.time()
                c = socket.create_connection((no['ip'], tcp), timeout=timeout)
                rtt = (time.time() - t0) * 1000.0
                c.close()
            except Exception:
                pass
            with trava:
                res[i] = rtt

    ths = [threading.Thread(target=trab, daemon=True)
           for _ in range(min(24, max(1, len(nos))))]
    for t in ths:
        t.start()
    for t in ths:
        t.join(timeout * 4 + 5)
    out = [(res.get(i), n) for i, n in enumerate(nos)]
    out.sort(key=lambda x: (x[0] is None, x[0] or 0))
    return out


class NoTox:
    """ler_save() -> bytes|None ; gravar_save(bytes): a identidade Tox (que
    contém a chave privada) é guardada cifrada pelo cofre do usuário."""

    def __init__(self, ler_save, gravar_save, log_fn=None, porta_ini=0,
                 porta_fim=0, tcp_porta=0):
        self.lib = carregar_libtoxcore()
        self.ler_save, self.gravar_save = ler_save, gravar_save
        self.log = log_fn or (lambda m: log.info(m))
        self.tox = None
        self._rodando = False
        self._trava = threading.RLock()
        self._amigos = {}
        self._frag = {}
        self._fila = queue.Queue()
        self._porta_ini, self._porta_fim = porta_ini, porta_fim
        self._tcp_pedida = int(tcp_porta or 0)
        self.tcp_porta = 0
        self.cb_msg = self.cb_bin = self.cb_amigo = None
        self.cb_pedido = self.cb_rede = None
        self._criar()

    # ── criação ─────────────────────────────────────────────
    def _criar(self):
        with self._trava:
            dados = self.ler_save() or b''
            buf_save = ((ctypes.c_uint8 * len(dados)).from_buffer_copy(dados)
                        if dados else None)
            tentativas = [(self._porta_ini, self._porta_fim, self._tcp_pedida)]
            if self._tcp_pedida:
                tentativas.append((self._porta_ini, self._porta_fim, 0))
            if self._porta_ini:
                tentativas.append((0, 0, 0))
            for ini, fim, tcp in tentativas:
                e0 = ctypes.c_int(0)
                op = self.lib.tox_options_new(ctypes.byref(e0))
                if not op:
                    raise RuntimeError("Falha ao criar Tox_Options")
                self.lib.tox_options_set_ipv6_enabled(op, True)
                self.lib.tox_options_set_udp_enabled(op, True)
                self.lib.tox_options_set_local_discovery_enabled(op, True)
                if buf_save is not None:
                    self.lib.tox_options_set_savedata_type(op, 1)
                    self.lib.tox_options_set_savedata_data(op, buf_save,
                                                           len(dados))
                try:
                    self.lib.tox_options_set_start_port(op, ini)
                    self.lib.tox_options_set_end_port(op, fim)
                    self.lib.tox_options_set_tcp_port(op, tcp)
                except AttributeError:
                    tcp = 0
                e2 = ctypes.c_int(0)
                self.tox = self.lib.tox_new(op, ctypes.byref(e2))
                self.lib.tox_options_free(op)
                if self.tox:
                    self.tcp_porta = tcp
                    break
                self.log(f"tox_new falhou (código {e2.value}); alternativa")
            if not self.tox:
                raise RuntimeError("Falha ao criar instância Tox")
            self._registrar_callbacks()
            self._carregar_amigos()
            self._salvar_sem_trava()
        self.log(f"Identidade pronta: {self.endereco_hex()[:16]}...")

    def _registrar_callbacks(self):
        vp, u8p = ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8)
        CB_SELF = ctypes.CFUNCTYPE(None, vp, ctypes.c_int, vp)
        CB_REQ = ctypes.CFUNCTYPE(None, vp, u8p, u8p, ctypes.c_size_t, vp)
        CB_CONN = ctypes.CFUNCTYPE(None, vp, ctypes.c_uint32, ctypes.c_int, vp)
        CB_PKT = ctypes.CFUNCTYPE(None, vp, ctypes.c_uint32, u8p,
                                  ctypes.c_size_t, vp)

        def ao_rede(tox, status, ud):
            self.log("Rede Tox: " + {0: 'Offline', 1: 'Conectado (TCP)',
                                     2: 'Conectado (UDP)'}.get(status, '?'))
            if self.cb_rede:
                try:
                    self.cb_rede(status)
                except Exception:
                    log.exception("cb_rede")

        def ao_pedido(tox, chave_ptr, msg_ptr, tam, ud):
            try:
                chave = bytes(ctypes.cast(
                    chave_ptr, ctypes.POINTER(ctypes.c_uint8 * 32)
                ).contents).hex().upper()
                texto = bytes(ctypes.cast(
                    msg_ptr, ctypes.POINTER(ctypes.c_uint8 * tam)
                ).contents).decode('utf-8', 'replace') if tam else ''
                if self.cb_pedido:
                    self.cb_pedido(chave, texto)
            except Exception:
                log.exception("ao_pedido")

        def ao_amigo(tox, numero, status, ud):
            self._amigos.setdefault(numero, {})['status'] = status
            if self.cb_amigo:
                try:
                    self.cb_amigo(numero, status)
                except Exception:
                    log.exception("cb_amigo")

        def ao_pacote(tox, numero, ptr, tam, ud):
            try:
                bruto = bytes(ctypes.cast(
                    ptr, ctypes.POINTER(ctypes.c_uint8 * tam)).contents)
            except Exception:
                return
            self._pacote(numero, bruto)

        self._c = (CB_SELF(ao_rede), CB_REQ(ao_pedido),
                   CB_CONN(ao_amigo), CB_PKT(ao_pacote))
        L = self.lib
        L.tox_callback_self_connection_status(self.tox, self._c[0])
        L.tox_callback_friend_request(self.tox, self._c[1])
        L.tox_callback_friend_connection_status(self.tox, self._c[2])
        L.tox_callback_friend_lossless_packet(self.tox, self._c[3])

    def _carregar_amigos(self):
        tam = self.lib.tox_self_get_friend_list_size(self.tox)
        if not tam:
            return
        buf = (ctypes.c_uint32 * tam)()
        self.lib.tox_self_get_friend_list(self.tox, buf)
        for numero in buf:
            e = ctypes.c_int(0)
            kb = (ctypes.c_uint8 * 32)()
            ok = self.lib.tox_friend_get_public_key(self.tox, numero, kb,
                                                    ctypes.byref(e))
            self._amigos[numero] = {
                'chave_publica': bytes(kb).hex().upper() if ok else '',
                'status': 0}

    # ── recepção / fragmentação ─────────────────────────────
    def _pacote(self, numero, bruto):
        if not bruto:
            return
        if bruto[0] == PACOTE_BIN:
            if len(bruto) > 13:
                self._fila.put((numero, bruto[1:]))
            return
        if len(bruto) < 9 or bruto[0] != PACOTE_DADOS:
            return
        fid = bruto[1:5]
        idx = struct.unpack('>H', bruto[5:7])[0]
        total = struct.unpack('>H', bruto[7:9])[0]
        if total < 1 or total > MAX_FRAGMENTOS_MSG or idx >= total:
            return
        k = (numero, fid)
        reg = self._frag.setdefault(k, {'t': time.time(), 'total': total,
                                        'partes': {}})
        if reg['total'] != total:
            self._frag.pop(k, None)
            return
        reg['t'] = time.time()
        reg['partes'][idx] = bruto[9:]
        if len(reg['partes']) < total:
            return
        completo = b''.join(reg['partes'][i] for i in range(total))
        self._frag.pop(k, None)
        try:
            msg = json.loads(completo.decode('utf-8'))
        except Exception:
            return
        if isinstance(msg, dict):
            self._fila.put((numero, msg))

    # ── envio ───────────────────────────────────────────────
    def _enviar_pkt(self, numero, pkt, cancelado=None):
        buf = (ctypes.c_uint8 * len(pkt)).from_buffer_copy(pkt)
        tent = 0
        while True:
            if cancelado is not None and cancelado.is_set():
                raise RuntimeError('Cancelado')
            erro = ctypes.c_int(0)
            with self._trava:
                if not self.tox:
                    raise RuntimeError('Tox parado')
                ok = self.lib.tox_friend_send_lossless_packet(
                    self.tox, numero, buf, len(pkt), ctypes.byref(erro))
            if ok:
                return
            if erro.value == ERRO_SENDQ:
                if self._amigos.get(numero, {}).get('status', 0) == 0:
                    raise RuntimeError('Contato desconectou durante o envio')
                tent += 1
                time.sleep(min(0.02 * (1 + tent // 10), 0.5))
                continue
            raise RuntimeError(f'Falha ao enviar (código {erro.value})')

    def enviar(self, numero, mensagem, cancelado=None):
        if self._amigos.get(numero, {}).get('status', 0) == 0:
            raise RuntimeError('Contato desconectado')
        bruto = json.dumps(mensagem, ensure_ascii=False,
                           separators=(',', ':')).encode('utf-8')
        fid = secrets.token_bytes(4)
        total = max(1, -(-len(bruto) // MAX_FRAGMENTO))
        if total > MAX_FRAGMENTOS_MSG:
            raise RuntimeError('Mensagem grande demais')
        for idx in range(total):
            pedaco = bruto[idx * MAX_FRAGMENTO:(idx + 1) * MAX_FRAGMENTO]
            self._enviar_pkt(numero, bytes([PACOTE_DADOS]) + fid
                             + struct.pack('>HH', idx, total) + pedaco,
                             cancelado)

    def enviar_bin(self, numero, fid8, seq, dados, cancelado=None):
        if self._amigos.get(numero, {}).get('status', 0) == 0:
            raise RuntimeError('Contato desconectado')
        self._enviar_pkt(numero, bytes([PACOTE_BIN]) + fid8
                         + struct.pack('>I', seq) + dados, cancelado)

    # ── identidade / amigos ─────────────────────────────────
    def _salvar_sem_trava(self):
        if not self.tox:
            return
        tam = self.lib.tox_get_savedata_size(self.tox)
        buf = (ctypes.c_uint8 * tam)()
        self.lib.tox_get_savedata(self.tox, buf)
        self.gravar_save(bytes(buf))

    def salvar(self):
        with self._trava:
            self._salvar_sem_trava()

    def endereco_hex(self):
        buf = (ctypes.c_uint8 * TOX_ADDRESS_SIZE)()
        with self._trava:
            if not self.tox:
                return ''
            self.lib.tox_self_get_address(self.tox, buf)
        return bytes(buf).hex().upper()

    def pubkey_hex(self):
        return self.endereco_hex()[:64]

    def status_rede(self):
        with self._trava:
            return self.lib.tox_self_get_connection_status(self.tox) \
                if self.tox else 0

    def status_amigo(self, numero):
        return self._amigos.get(numero, {}).get('status', 0)

    def buscar_amigo_por_chave(self, pub):
        pub = pub.upper()
        for n, i in list(self._amigos.items()):
            if i.get('chave_publica', '').upper() == pub:
                return n
        return None

    def listar_amigos(self):
        return [{'numero': n, 'chave_publica': i.get('chave_publica', ''),
                 'status': i.get('status', 0)}
                for n, i in sorted(self._amigos.items())]

    def adicionar_amigo(self, endereco_hex, texto):
        """Retorna (numero, novo?)."""
        endereco_hex = endereco_hex.strip().upper()
        bruto = bytes.fromhex(endereco_hex)
        if len(bruto) != TOX_ADDRESS_SIZE:
            raise ValueError('Chave inválida')
        pub = bruto[:32].hex().upper()
        existente = self.buscar_amigo_por_chave(pub)
        if existente is not None:
            return existente, False
        if pub == self.pubkey_hex():
            raise ValueError('Esta é a sua própria chave')
        buf = (ctypes.c_uint8 * TOX_ADDRESS_SIZE).from_buffer_copy(bruto)
        m = texto.encode('utf-8')[:200]
        mb = (ctypes.c_uint8 * max(1, len(m))).from_buffer_copy(m or b'\0')
        erro = ctypes.c_int(0)
        with self._trava:
            n = self.lib.tox_friend_add(self.tox, buf, mb, len(m),
                                        ctypes.byref(erro))
        if erro.value in (4, 6, 7):
            raise ValueError(f'Chave inválida (código {erro.value})')
        if erro.value != 0:
            raise RuntimeError(f'Tox recusou a chave (código {erro.value})')
        self._amigos[n] = {'chave_publica': pub, 'status': 0}
        self.salvar()
        return n, True

    def aceitar_amigo(self, pub_hex):
        pub_hex = pub_hex.upper()
        existente = self.buscar_amigo_por_chave(pub_hex)
        if existente is not None:
            return existente
        buf = (ctypes.c_uint8 * 32).from_buffer_copy(bytes.fromhex(pub_hex))
        erro = ctypes.c_int(0)
        with self._trava:
            n = self.lib.tox_friend_add_norequest(self.tox, buf,
                                                  ctypes.byref(erro))
        if erro.value != 0:
            return None
        self._amigos[n] = {'chave_publica': pub_hex, 'status': 0}
        self.salvar()
        return n

    def remover_amigo(self, numero):
        erro = ctypes.c_int(0)
        with self._trava:
            if self.tox:
                self.lib.tox_friend_delete(self.tox, numero,
                                           ctypes.byref(erro))
        self._amigos.pop(numero, None)
        try:
            self.salvar()
        except Exception:
            pass

    # ── rede ────────────────────────────────────────────────
    def dht_id_hex(self):
        try:
            buf = (ctypes.c_uint8 * 32)()
            with self._trava:
                if not self.tox:
                    return ''
                self.lib.tox_self_get_dht_id(self.tox, buf)
            return bytes(buf).hex().upper()
        except AttributeError:
            return ''

    def porta_udp(self):
        try:
            e = ctypes.c_int(0)
            with self._trava:
                return int(self.lib.tox_self_get_udp_port(
                    self.tox, ctypes.byref(e))) if self.tox else 0
        except AttributeError:
            return 0

    def _bootstrap_um(self, ip, porta, chave_hex, tcp=0):
        try:
            chave = bytes.fromhex(chave_hex)
            if len(chave) != 32:
                return False
            buf = (ctypes.c_uint8 * 32).from_buffer_copy(chave)
            host = str(ip).encode()
            with self._trava:
                if not self.tox:
                    return False
                e = ctypes.c_int(0)
                ok = self.lib.tox_bootstrap(self.tox, host, int(porta), buf,
                                            ctypes.byref(e))
                if tcp:
                    e2 = ctypes.c_int(0)
                    self.lib.tox_add_tcp_relay(self.tox, host, int(tcp), buf,
                                               ctypes.byref(e2))
            return bool(ok)
        except Exception as ex:
            log.debug("bootstrap %s: %s", ip, ex)
            return False

    def bootstrap_simples(self, nos):
        n = 0
        for no in nos:
            tcp = int((no.get('tcp_ports') or [no['porta']])[0])
            if self._bootstrap_um(no['ip'], no['porta'],
                                  no['chave_publica'], tcp):
                n += 1
        return n

    def bootstrap_otimizado(self, nos, max_relays=8):
        if not nos:
            return 0
        medidos = medir_latencia_nos(nos)
        vivos = [(r, n) for r, n in medidos if r is not None]
        relays = set(id(n) for _, n in vivos[:max_relays])
        ok = 0
        for r, no in medidos:
            tcp = int((no.get('tcp_ports') or [no['porta']])[0]) \
                if (not vivos or id(no) in relays) else 0
            if self._bootstrap_um(no['ip'], no['porta'], no['chave_publica'],
                                  tcp):
                ok += 1
        return ok

    def aplicar_dica(self, d):
        if not d:
            return 0
        n = 0
        for ip in list(d.get('ips', [])) + list(d.get('ips_globais', [])):
            if self._bootstrap_um(ip, d['porta'], d['dht_id'],
                                  d.get('tcp_porta', 0)):
                n += 1
        return n

    # ── laços ───────────────────────────────────────────────
    def iniciar_loop(self):
        self._rodando = True
        for alvo, nome in ((self._loop, 'Tox-Loop'),
                           (self._loop_salvar, 'Tox-Save'),
                           (self._loop_msgs, 'Tox-Dispatch')):
            threading.Thread(target=alvo, name=nome, daemon=True).start()

    def _loop(self):
        ult = time.time()
        while self._rodando:
            with self._trava:
                if not self._rodando or not self.tox:
                    break
                self.lib.tox_iterate(self.tox, None)
                intervalo = self.lib.tox_iteration_interval(self.tox)
            if time.time() - ult > 15:
                t = time.time()
                for k in [k for k, v in list(self._frag.items())
                          if t - v['t'] > TIMEOUT_FRAGMENTOS]:
                    self._frag.pop(k, None)
                ult = t
            time.sleep(max(intervalo, 10) / 1000.0)

    def _loop_salvar(self):
        while self._rodando:
            for _ in range(30):
                if not self._rodando:
                    return
                time.sleep(1)
            try:
                self.salvar()
            except Exception:
                log.exception("salvar periódico")

    def _loop_msgs(self):
        while self._rodando:
            try:
                numero, msg = self._fila.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                if isinstance(msg, (bytes, bytearray)):
                    if self.cb_bin:
                        self.cb_bin(numero, bytes(msg))
                elif self.cb_msg:
                    self.cb_msg(numero, msg)
            except Exception:
                log.exception("processando pacote")

    def parar(self):
        self._rodando = False
        time.sleep(0.3)
        with self._trava:
            if self.tox:
                try:
                    self._salvar_sem_trava()
                except Exception:
                    pass
                self.lib.tox_kill(self.tox)
                self.tox = None
