# -*- coding: utf-8 -*-
"""RRFS Social - diretório de usuários (só nome, sobrenome e miniatura da
foto), dicas de como alcançar nós e cursores de sincronização. Contém apenas
informação pública; fica em dados/rede/ e é compartilhado entre contas."""
import os
import threading
import secrets

from .util import (log, agora, ler_json, salvar_json, preparar, pontuar,
                   limpar, validar_mini, validar_dica, RE_ADDR, RE_HEX64)

MAX_USUARIOS = 20000
DIR_PAGINA = 40


def validar_usuario(d):
    try:
        addr = str(d.get('addr', '')).upper()
        nome = limpar(d.get('nome'), 40)
        if not RE_ADDR.match(addr) or not nome:
            return None
        ts = int(d.get('ts', 0))
        if ts < 0 or ts > agora() + 86400:
            return None
        return {'addr': addr, 'nome': nome,
                'sobrenome': limpar(d.get('sobrenome'), 60),
                'foto_mini': validar_mini(d.get('foto_mini')),
                'ts': ts, 'removido': bool(d.get('removido', False))}
    except Exception:
        return None


class Rede:
    def __init__(self, dados_dir):
        self.pasta = os.path.join(dados_dir, 'rede')
        os.makedirs(self.pasta, mode=0o700, exist_ok=True)
        self.lock = threading.RLock()
        self.usuarios = {}
        self.hints = {}
        self.sync = {}
        self.epoca = secrets.token_hex(6)
        self._mod_ult = 0.0
        self._cache = {}
        self._sujo = False
        self._carregar()

    def _p(self, n):
        return os.path.join(self.pasta, n)

    def _carregar(self):
        d = ler_json(self._p('diretorio.json'), {}) or {}
        self.epoca = d.get('epoca') or self.epoca
        for e in d.get('usuarios', []):
            v = validar_usuario(e)
            if v:
                v['verificado'] = bool(e.get('verificado'))
                v['mod'] = float(e.get('mod', 0))
                v['visto'] = int(e.get('visto', 0))
                self.usuarios[v['addr']] = v
                self._mod_ult = max(self._mod_ult, v['mod'])
                self._indexar(v)
        h = ler_json(self._p('pares.json'), {}) or {}
        for pub, v in (h if isinstance(h, dict) else {}).items():
            dica = validar_dica(v, permitir_lan=True)
            if dica and RE_HEX64.match(pub):
                dica['ts'] = int(v.get('ts', 0))
                self.hints[pub.upper()] = dica
        y = ler_json(self._p('sync.json'), {}) or {}
        if isinstance(y, dict):
            self.sync = y

    def salvar(self):
        with self.lock:
            corte = agora() - 60 * 86400
            us = [e for e in self.usuarios.values()
                  if not (e['removido'] and e['mod'] < corte)]
            doc = {'epoca': self.epoca, 'usuarios': us}
            hints, sync = dict(self.hints), dict(self.sync)
            self._sujo = False
        salvar_json(self._p('diretorio.json'), doc)
        salvar_json(self._p('pares.json'), hints)
        salvar_json(self._p('sync.json'), sync)

    def salvar_se_sujo(self):
        if self._sujo:
            try:
                self.salvar()
            except Exception:
                log.exception("salvar rede")

    # ── diretório ───────────────────────────────────────────
    def _prox_mod(self):
        import time
        self._mod_ult = max(time.time(), self._mod_ult + 1e-6)
        return self._mod_ult

    def _indexar(self, e):
        self._cache[e['addr']] = preparar(e['nome'] + ' ' + e['sobrenome'])

    def _gravar(self, e, verificado):
        e = dict(e)
        e.update(verificado=bool(verificado), mod=self._prox_mod(),
                 visto=agora())
        self.usuarios[e['addr']] = e
        self._indexar(e)
        self._sujo = True

    def mesclar_usuario(self, d, fonte_pub=None):
        """'novo' | 'atualizado' | None. Só o próprio dono (identificado pela
        chave do enlace Tox autenticado) sobrescreve entrada verificada."""
        e = validar_usuario(d)
        if not e:
            return None
        do_dono = bool(fonte_pub) and fonte_pub.upper() == e['addr'][:64]
        with self.lock:
            at = self.usuarios.get(e['addr'])
            if at is None:
                if len(self.usuarios) >= MAX_USUARIOS and not do_dono:
                    return None
                self._gravar(e, do_dono)
                return 'novo'
            campos = ('nome', 'sobrenome', 'foto_mini', 'ts', 'removido')
            if do_dono:
                if at['verificado'] and e['ts'] < at['ts']:
                    return None
                if at['verificado'] and all(at[k] == e[k] for k in campos):
                    at['visto'] = agora()
                    return None
                self._gravar(e, True)
                return 'atualizado'
            if at['verificado'] or e['ts'] <= at['ts']:
                return None
            self._gravar(e, False)
            return 'atualizado'

    def get(self, addr):
        with self.lock:
            e = self.usuarios.get(addr.upper())
            return dict(e) if e else None

    def delta(self, apos, limite=DIR_PAGINA):
        try:
            am, ag = float(apos[0]), str(apos[1])
        except Exception:
            am, ag = 0.0, ''
        with self.lock:
            itens = [dict(e) for e in self.usuarios.values()
                     if (e['mod'], e['addr']) > (am, ag)]
        itens.sort(key=lambda e: (e['mod'], e['addr']))
        pag = itens[:limite]
        prox = [pag[-1]['mod'], pag[-1]['addr']] if pag else [am, ag]
        return pag, prox, len(itens) > limite

    def buscar(self, consulta, limite=20):
        q = preparar(consulta)
        if not q['n']:
            return []
        with self.lock:
            itens = [(e, self._cache.get(e['addr']))
                     for e in self.usuarios.values() if not e['removido']]
        pont = []
        for e, c in itens:
            if c:
                s = pontuar(q, c)
                if s >= 0.4:
                    pont.append((s, e))
        pont.sort(key=lambda x: (-x[0], not x[1]['verificado'], -x[1]['ts']))
        return [dict(e, pontos=round(s, 3)) for s, e in pont[:limite]]

    def recentes(self, n=40):
        with self.lock:
            itens = sorted((e for e in self.usuarios.values()
                            if not e['removido']),
                           key=lambda e: (-e['verificado'], -e['visto']))
            return [e['addr'] for e in itens[:n]]

    def contagem(self):
        with self.lock:
            return sum(1 for e in self.usuarios.values() if not e['removido'])

    # ── dicas / sincronização ───────────────────────────────
    def guardar_dica(self, pub, dica):
        with self.lock:
            dica = dict(dica)
            dica['ts'] = agora()
            self.hints[pub.upper()] = dica
            self._sujo = True

    def hints_recentes(self, n=80):
        with self.lock:
            itens = sorted(self.hints.items(),
                           key=lambda kv: -kv[1].get('ts', 0))[:n]
            return [dict(v) for _, v in itens]

    def get_sync(self, pub):
        return self.sync.get(pub.upper(), {})

    def set_sync(self, pub, cursor, epoca):
        with self.lock:
            self.sync[pub.upper()] = {'cursor': cursor, 'epoca': epoca,
                                      'ts': agora()}
            self._sujo = True

    # ── exportar / importar (tudo entra como boato não verificado) ──
    def exportar(self):
        with self.lock:
            return {'usuarios': [{k: e[k] for k in ('addr', 'nome',
                                                    'sobrenome', 'foto_mini',
                                                    'ts', 'removido')}
                                 for e in self.usuarios.values()],
                    'dicas': dict(self.hints)}

    def importar(self, bloco):
        n_u = 0
        for e in (bloco.get('usuarios') or [])[:MAX_USUARIOS]:
            if isinstance(e, dict) and self.mesclar_usuario(e, None):
                n_u += 1
        n_d = 0
        for pub, v in (bloco.get('dicas') or {}).items():
            dica = validar_dica(v, permitir_lan=True)
            if dica and RE_HEX64.match(str(pub)) \
                    and pub.upper() not in self.hints:
                self.guardar_dica(pub, dica)
                n_d += 1
        self.salvar()
        return {'usuarios': n_u, 'dicas': n_d}
