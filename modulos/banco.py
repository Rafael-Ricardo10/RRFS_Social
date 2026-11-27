# -*- coding: utf-8 -*-
"""RRFS Social - armazenamento cifrado por usuário (dados/contas/<login>/).
Tabelas e conversas ficam em arquivos cifrados; mídia em blocos cifrados."""
import os
import copy
import hashlib
import threading
import time

from .util import log, agora

TABELAS = {
    'perfil': {}, 'contatos': {}, 'pedidos': {}, 'pessoas': {},
    'grupos': {}, 'convites': {}, 'status': {}, 'midia': {},
    'outbox': [], 'baixas': {}, 'ajustes': {}, 'convs': {},
    # entretenimento
    'canal_meu': {}, 'mvid': {}, 'vlocal': {}, 'vsocial': {}, 'vinscr': {},
    'vhist': {}, 'vcc': {},
    # rede social
    'posts': {}, 'pubprof': {},
}
MAX_MSGS = 20000


class Banco:
    def __init__(self, pasta, cofre):
        self.pasta, self.cofre = pasta, cofre
        for sub in ('', 'conv', 'midia'):
            os.makedirs(os.path.join(pasta, sub), mode=0o700, exist_ok=True)
        self.lock = threading.RLock()
        self.t, self.sujo = {}, set()
        self.conv, self._ids, self.conv_sujo = {}, {}, set()
        for nome, padrao in TABELAS.items():
            self.t[nome] = cofre.ler_json(self._tab(nome),
                                          copy.deepcopy(padrao))
        self._rodando = True
        threading.Thread(target=self._flusher, name='Banco-Flush',
                         daemon=True).start()

    def _tab(self, nome):
        return os.path.join(self.pasta, nome + '.dat')

    def sujar(self, nome):
        self.sujo.add(nome)

    def salvar_tudo(self):
        with self.lock:
            nomes, self.sujo = list(self.sujo), set()
            cids, self.conv_sujo = list(self.conv_sujo), set()
            for n in nomes:
                self.cofre.salvar_json(self._tab(n), self.t[n])
            for c in cids:
                self.cofre.salvar_json(self._arq_conv(c), self.conv[c])

    def _flusher(self):
        while self._rodando:
            time.sleep(2)
            try:
                self.salvar_tudo()
            except Exception:
                log.exception("flush do banco")

    def fechar(self):
        self._rodando = False
        try:
            self.salvar_tudo()
        except Exception:
            log.exception("fechar banco")

    # ── conversas ───────────────────────────────────────────
    def _arq_conv(self, cid):
        h = hashlib.sha256(cid.encode()).hexdigest()[:32]
        return os.path.join(self.pasta, 'conv', h + '.dat')

    def _conv(self, cid):
        if cid not in self.conv:
            l = self.cofre.ler_json(self._arq_conv(cid), [])
            self.conv[cid] = l
            self._ids[cid] = {m['id'] for m in l}
        return self.conv[cid]

    def add_msg(self, cid, msg, recebida=False, previa=''):
        with self.lock:
            l = self._conv(cid)
            if msg['id'] in self._ids[cid]:
                return False
            l.append(msg)
            self._ids[cid].add(msg['id'])
            if len(l) > MAX_MSGS:
                for m in l[:len(l) - MAX_MSGS]:
                    self._ids[cid].discard(m['id'])
                del l[:len(l) - MAX_MSGS]
            self.conv_sujo.add(cid)
            c = self.t['convs'].setdefault(
                cid, {'ts': 0, 'nao_lidas': 0, 'previa': ''})
            c.update(ts=msg['ts'], previa=previa[:80])
            if recebida and msg.get('tipo') != 'sistema':
                c['nao_lidas'] += 1
            self.sujo.add('convs')
            return True

    def tem_msg(self, cid, mid):
        with self.lock:
            self._conv(cid)
            return mid in self._ids[cid]

    def achar(self, cid, mid):
        """Referência mutável (chame tocar(cid) depois de alterar)."""
        with self.lock:
            for m in reversed(self._conv(cid)):
                if m['id'] == mid:
                    return m
        return None

    def tocar(self, cid):
        self.conv_sujo.add(cid)

    def msgs(self, cid, antes=None, limite=60):
        with self.lock:
            l = self._conv(cid)
            if antes:
                idx = next((i for i, m in enumerate(l) if m['id'] == antes),
                           len(l))
                l = l[:idx]
            return [dict(m) for m in l[-limite:]]

    def marcar_lido(self, cid):
        with self.lock:
            c = self.t['convs'].get(cid)
            if c and c['nao_lidas']:
                c['nao_lidas'] = 0
                self.sujo.add('convs')

    # ── mídia ───────────────────────────────────────────────
    def caminho_midia(self, mid):
        return os.path.join(self.pasta, 'midia', mid)

    def escritor_midia(self, mid):
        return self.cofre.escritor(self.caminho_midia(mid))

    def apagar_midia(self, mid):
        with self.lock:
            self.t['midia'].pop(mid, None)
            self.sujo.add('midia')
        try:
            os.remove(self.caminho_midia(mid))
        except OSError:
            pass
