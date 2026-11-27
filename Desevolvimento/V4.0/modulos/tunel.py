# -*- coding: utf-8 -*-
"""RRFS Social - vários dispositivos na mesma conta (túnel criptografado).

Por que não usar a mesma chave Tox em dois aparelhos? Duas instâncias com a
mesma identidade se derrubam mutuamente (o Tox só mantém uma conexão por
amigo) e as mensagens iriam para um aparelho ou outro ao acaso.

Solução: o aparelho PRINCIPAL é o dono da identidade e dos dados. Cada
aparelho SECUNDÁRIO tem a própria identidade Tox, só para falar com o
principal, e é autorizado por um código de uso único. Toda a interface do
secundário funciona como uma "tela remota": as requisições da API viajam pelo
enlace Tox (cifrado de ponta a ponta) e são executadas no principal. Mensagens,
rede social, vídeos, chamadas e status aparecem nos dois aparelhos ao mesmo
tempo, sem duplicar dados nem conexões. O principal precisa estar ligado."""
import os
import re
import json
import time
import queue
import struct
import hashlib
import secrets
import tempfile
import threading

from .util import log, RE_ADDR, RE_ID, agora, ErroSocial, CHUNK_BIN

PROIBIDOS = ('/api/login', '/api/logout', '/api/criar_conta', '/api/contas',
             '/api/sessao', '/api/dispositivos', '/api/conta/', '/api/vincular',
             '/api/restaurar', '/api/remoto')
HEADERS_OK = ('Content-Type', 'Content-Length', 'Content-Range', 'Accept-Ranges',
              'Content-Disposition', 'Cache-Control', 'Content-Security-Policy')
MAX_CORPO = 2200 * 1024 * 1024
RE_CODIGO = re.compile(r'^RRFSDEV:([0-9A-Fa-f]{76}):([0-9a-f]{16})$')


def _h(token):
    return hashlib.sha256(token.encode()).hexdigest()[:32]


# ═══ lado PRINCIPAL ═════════════════════════════════════════════════════
class TunelServidor:
    def __init__(self, s):
        self.s = s
        self.reqs = {}
        self.exec = None            # definido pela camada web
        self.sem = threading.Semaphore(12)

    # pareamento
    def codigo(self):
        token = secrets.token_hex(8)
        aj = self.s.t['ajustes']
        aj['vinculos'] = {k: v for k, v in aj['vinculos'].items() if v > agora()}
        aj['vinculos'][_h(token)] = agora() + 600
        self.s.banco.sujar('ajustes')
        return 'RRFSDEV:%s:%s' % (self.s.addr(), token)

    def aceitar_pedido(self, chave, extra):
        token, _, nome = extra.partition(':')
        aj = self.s.t['ajustes']
        exp = aj['vinculos'].pop(_h(token), 0)
        if exp < agora():
            return False
        if len(aj['dispositivos']) >= 8:
            return False
        if self.s._aceitar_link(chave) is None:
            return False
        aj['dispositivos'][chave] = {'nome': (nome.strip() or 'Dispositivo')[:40],
                                     'ts': agora()}
        self.s.banco.sujar('ajustes')
        self.s._evento('dispositivo')
        return True

    def lista(self):
        return [{'pub': p, 'nome': d['nome'], 'ts': d['ts'],
                 'online': self.s._online(p)}
                for p, d in self.s.t['ajustes']['dispositivos'].items()]

    def remover(self, pub):
        pub = str(pub).upper()
        aj = self.s.t['ajustes']
        if aj['dispositivos'].pop(pub, None) is None:
            raise ErroSocial('Dispositivo não encontrado.')
        self.s.banco.sujar('ajustes')
        n = self.s._numero(pub)
        if n is not None:
            self.s.no.remover_amigo(n)
        for k in [k for k in self.reqs if k[0] == pub]:
            self.reqs.pop(k, None)

    # requisições
    def _autorizado(self, pub):
        return pub in self.s.t['ajustes']['dispositivos']

    def tratar(self, pub, m):
        if not self._autorizado(pub):
            return
        t = m.get('tipo')
        if t == 't_req':
            self._req(pub, m)
        elif t == 't_cancel':
            r = self.reqs.pop((pub, str(m.get('r', ''))), None)
            if r:
                r['cancel'] = True

    def _req(self, pub, m):
        rid = str(m.get('r', ''))
        metodo, caminho = str(m.get('m', '')), str(m.get('p', ''))
        try:
            n = int(m.get('n', 0))
        except (TypeError, ValueError):
            return
        if not RE_ID.match(rid) or metodo not in ('GET', 'POST', 'DELETE', 'PUT') \
                or not caminho.startswith('/api/') or len(caminho) > 2000 \
                or re.search(r'[\x00-\x1f]', caminho) or not 0 <= n <= MAX_CORPO \
                or any(caminho.startswith(p) for p in PROIBIDOS):
            self._erro(pub, rid, 403, 'Requisição não permitida.')
            return
        r = {'m': metodo, 'p': caminho, 'ct': str(m.get('ct', ''))[:200],
             'rg': str(m.get('rg', ''))[:100], 'n': n, 'rec': 0, 'cancel': False,
             'tmp': tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024),
             't': time.time()}
        self.reqs[(pub, rid)] = r
        if n == 0:
            threading.Thread(target=self._executar, args=(pub, rid), daemon=True).start()

    def ao_bin(self, pub, payload):
        if not self._autorizado(pub):
            return
        rid = payload[:8].hex()
        r = self.reqs.get((pub, rid))
        if not r or r['rec'] >= r['n']:
            return
        dados = payload[12:]
        r['tmp'].write(dados[:r['n'] - r['rec']])
        r['rec'] += len(dados)
        if r['rec'] >= r['n']:
            threading.Thread(target=self._executar, args=(pub, rid), daemon=True).start()

    def _erro(self, pub, rid, status, msg):
        self.s._enviar_async(pub, {'tipo': 't_res', 'r': rid, 's': status,
                                   'h': {'Content-Type': 'application/json'}})
        corpo = json.dumps({'erro': msg}).encode()
        self._chunks(pub, rid, [corpo])
        self.s._enviar_async(pub, {'tipo': 't_fim', 'r': rid, 'ok': False})

    def _chunks(self, pub, rid, it):
        n = self.s._numero(pub)
        r8, seq = bytes.fromhex(rid), 0
        for bloco in it:
            if isinstance(bloco, str):
                bloco = bloco.encode()
            for i in range(0, len(bloco), CHUNK_BIN):
                self.s.no.enviar_tunel(n, r8, seq, bloco[i:i + CHUNK_BIN])
                seq += 1

    def _executar(self, pub, rid):
        r = self.reqs.get((pub, rid))
        if not r or not self.exec:
            return
        with self.sem:
            resp = None
            try:
                r['tmp'].seek(0)
                resp = self.exec(r['m'], r['p'], r['ct'], r['rg'], r['tmp'], r['n'])
                n = self.s._numero(pub)
                if n is None:
                    return
                hs = {k: v for k, v in resp.headers.items() if k in HEADERS_OK}
                self.s.no.enviar(n, {'tipo': 't_res', 'r': rid, 's': resp.status_code, 'h': hs})
                for bloco in resp.response:
                    if r['cancel'] or (pub, rid) not in self.reqs:
                        break
                    self._chunks(pub, rid, [bloco])
                self.s.no.enviar(n, {'tipo': 't_fim', 'r': rid, 'ok': True})
            except Exception as e:
                log.debug("túnel exec: %s", e)
                try:
                    self.s._enviar_async(pub, {'tipo': 't_fim', 'r': rid, 'ok': False})
                except Exception:
                    pass
            finally:
                try:
                    if resp is not None:
                        resp.close()
                except Exception:
                    pass
                try:
                    r['tmp'].close()
                except Exception:
                    pass
                self.reqs.pop((pub, rid), None)

    def limpar(self):
        t = time.time()
        for k in [k for k, r in self.reqs.items() if t - r['t'] > 3600]:
            self.reqs.pop(k, None)


# ═══ lado SECUNDÁRIO ════════════════════════════════════════════════════
class Remoto:
    """Representa uma conta vinculada: não tem dados nem contatos próprios,
    apenas encaminha a API para o principal."""
    remoto = True

    def __init__(self, pasta, cofre, raiz, addr_principal, criar_no=None, log_fn=None):
        self.pasta, self.cofre, self.raiz = pasta, cofre, raiz
        self.addr = addr_principal.upper()
        self.pub_principal = self.addr[:64]
        self.reqs = {}
        self.rodando = True
        arq = os.path.join(pasta, 'identidade.dat')
        if criar_no:
            self.no = criar_no(self)
        else:
            from .tox_no import NoTox
            self.no = NoTox(lambda: cofre.ler_bytes(arq), lambda b: cofre.gravar_bytes(arq, b),
                            log_fn, 33900, 33949, 0)
        self.no.cb_msg = self._msg
        self.no.cb_tunel = self._bin
        self.no.cb_amigo = lambda n, st: None
        self.no.cb_pedido = lambda c, t: None
        self.no.iniciar_loop()
        threading.Thread(target=self._boot, daemon=True).start()

    def _boot(self):
        try:
            from .util import carregar_nos, ler_json
            from .rede import Rede
            nos = carregar_nos(os.path.join(self.raiz, 'tox', 'nos_bootstrap.json'))
            r = ler_json(os.path.join(self.raiz, 'rede', 'pares.json'), {}) or {}
            from .util import validar_dica
            for v in list(r.values())[:80]:
                d = validar_dica(v, permitir_lan=True)
                if d:
                    self.no.aplicar_dica(d)
            if nos:
                self.no.bootstrap_simples(nos)
        except Exception:
            log.exception("boot remoto")

    # ── pareamento ──
    def parear(self, token, nome, espera=60):
        n, _ = self.no.adicionar_amigo(self.addr, 'RRFS-SOCIAL:1:dispositivo:%s:%s' % (token, nome))
        fim = time.time() + espera
        while time.time() < fim:
            if self.no.status_amigo(n):
                return True
            time.sleep(0.3)
        return False

    def garantir_vinculo(self):
        if self.no.buscar_amigo_por_chave(self.pub_principal) is None:
            try:
                self.no.adicionar_amigo(self.addr, 'RRFS-SOCIAL:1:dispositivo:retorno')
            except Exception:
                pass

    def online(self):
        n = self.no.buscar_amigo_por_chave(self.pub_principal)
        return n is not None and bool(self.no.status_amigo(n))

    def parar(self):
        self.rodando = False
        for q in list(self.reqs.values()):
            q.put(('fim', False))
        self.no.parar()

    # ── recepção ──
    def _msg(self, numero, m):
        if self.no._amigos.get(numero, {}).get('chave_publica', '').upper() != self.pub_principal:
            return
        q = self.reqs.get(str(m.get('r', '')))
        if q is None:
            return
        if m.get('tipo') == 't_res':
            q.put(('res', int(m.get('s', 500)), m.get('h') or {}))
        elif m.get('tipo') == 't_fim':
            q.put(('fim', bool(m.get('ok'))))

    def _bin(self, numero, payload):
        q = self.reqs.get(payload[:8].hex())
        if q is not None:
            q.put(('dados', payload[12:]))

    # ── proxy ──
    def proxy(self, metodo, caminho, ct, rg, stream, n, espera=70):
        """Retorna (status, headers, gerador). Lança ErroSocial se offline."""
        if not self.online():
            self.garantir_vinculo()
            raise ErroSocial('O dispositivo principal está offline.')
        rid8 = secrets.token_bytes(8)
        rid = rid8.hex()
        q = self.reqs[rid] = queue.Queue()
        numero = self.no.buscar_amigo_por_chave(self.pub_principal)
        try:
            self.no.enviar(numero, {'tipo': 't_req', 'r': rid, 'm': metodo, 'p': caminho,
                                    'ct': ct or '', 'rg': rg or '', 'n': n})
            seq = 0
            while n and seq * CHUNK_BIN < n:
                ch = stream.read(min(CHUNK_BIN * 64, n - seq * CHUNK_BIN))
                if not ch:
                    break
                for i in range(0, len(ch), CHUNK_BIN):
                    self.no.enviar_tunel(numero, rid8, seq, ch[i:i + CHUNK_BIN])
                    seq += 1
            item = q.get(timeout=espera)
        except Exception as e:
            self.reqs.pop(rid, None)
            raise ErroSocial('Sem resposta do dispositivo principal.' if isinstance(e, queue.Empty)
                             else 'O dispositivo principal está offline.')
        if item[0] != 'res':
            self.reqs.pop(rid, None)
            raise ErroSocial('O dispositivo principal não respondeu.')

        def gerar():
            try:
                while True:
                    try:
                        it = q.get(timeout=120)
                    except queue.Empty:
                        break
                    if it[0] == 'dados':
                        yield it[1]
                    elif it[0] == 'fim':
                        break
            finally:
                self.reqs.pop(rid, None)
                try:
                    self.no.enviar(numero, {'tipo': 't_cancel', 'r': rid})
                except Exception:
                    pass
        return item[1], item[2], gerar()
