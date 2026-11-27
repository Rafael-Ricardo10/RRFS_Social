# -*- coding: utf-8 -*-
"""RRFS Social - catálogo de canais e vídeos.

Cada canal tem uma chave Ed25519; o id do canal é o hash dela. Toda entrada
(canal ou vídeo) é ASSINADA pelo dono, então qualquer nó pode repassá-la sem
que ninguém consiga forjar ou alterar. Fica em dados/rede/ (informação
pública, compartilhada entre as contas deste computador)."""
import os
import json
import time
import hashlib
import secrets
import threading

from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

from .util import (log, agora, ler_json, salvar_json, preparar, pontuar,
                   RE_ADDR, RE_HEX64, RE_ID, _RE_CTRL)

CATEGORIAS = ['Tecnologia', 'Finanças', 'Educação', 'Ciência', 'Notícias',
              'Entretenimento', 'Humor', 'Música', 'Jogos', 'Esportes',
              'Culinária', 'Viagem', 'Saúde', 'Arte', 'Outros']
MAX_CANAIS = 5000
MAX_VIDEOS = 20000
CAT_PAGINA = 20
LOCAIS = ('sig', 'verificado', 'mod', 'visto', 'pontos')
MIMES_VIDEO = ('video/mp4', 'video/webm')


# ── assinatura ──────────────────────────────────────────────────────────
def canonico(o):
    return json.dumps({k: v for k, v in o.items() if k not in LOCAIS},
                      sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode('utf-8')


def nova_chave():
    p = Ed25519PrivateKey.generate()
    priv = p.private_bytes(_ser.Encoding.Raw, _ser.PrivateFormat.Raw,
                           _ser.NoEncryption()).hex()
    pub = p.public_key().public_bytes(_ser.Encoding.Raw,
                                      _ser.PublicFormat.Raw).hex()
    return priv, pub


def assinar(priv_hex, obj):
    return Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(priv_hex)).sign(canonico(obj)).hex()


def verificar(ed_hex, obj, sig_hex):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(ed_hex)).verify(
            bytes.fromhex(sig_hex), canonico(obj))
        return True
    except Exception:
        return False


def cid_de(ed_hex):
    return hashlib.sha256(bytes.fromhex(ed_hex)).hexdigest()[:16]


def hash_bloq(cid, pub):
    return hashlib.sha256((cid + pub.upper()).encode()).hexdigest()[:16]


# ── validação ESTRITA (não altera: a assinatura cobre os campos exatos) ──
def _s(d, k, n, obrig=False):
    v = d.get(k, '')
    if not isinstance(v, str) or len(v) > n or _RE_CTRL.search(v) \
            or (obrig and not v.strip()):
        raise ValueError(k)
    return v


def _i(d, k, lo, hi):
    v = d.get(k, 0)
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise ValueError(k)
    return v


def _thumb(d, k, n):
    v = _s(d, k, n)
    if v and not v.startswith(('data:image/jpeg;base64,',
                               'data:image/webp;base64,',
                               'data:image/png;base64,')):
        raise ValueError(k)
    return v


def _cats(d):
    c = d.get('cats', [])
    if not isinstance(c, list) or len(c) > 5 or \
            any(x not in CATEGORIAS for x in c):
        raise ValueError('cats')
    return c


def validar_canal(d):
    try:
        ed, addr, cid = str(d.get('ed', '')), str(d.get('addr', '')).upper(), \
            str(d.get('cid', ''))
        if not RE_HEX64.match(ed) or not RE_ADDR.match(addr) \
                or cid != cid_de(ed) or not isinstance(d.get('sig'), str):
            return None
        bl = d.get('bloq', [])
        if not isinstance(bl, list) or len(bl) > 3000 or \
                any(not isinstance(x, str) or not RE_ID.match(x) for x in bl):
            return None
        e = {'k': 'canal', 'cid': cid, 'ed': ed, 'addr': addr,
             'nome': _s(d, 'nome', 60, True), 'desc': _s(d, 'desc', 600),
             'cats': _cats(d), 'foto_mini': _thumb(d, 'foto_mini', 9000),
             'bloq': bl, 'v': _i(d, 'v', 0, 10 ** 9),
             'ts': _i(d, 'ts', 0, agora() + 86400),
             'removido': bool(d.get('removido', False)), 'sig': d['sig']}
        return e if verificar(ed, e, e['sig']) else None
    except (ValueError, TypeError):
        return None


def validar_video(d):
    try:
        ed, addr, cid, vid = str(d.get('ed', '')), \
            str(d.get('addr', '')).upper(), str(d.get('cid', '')), \
            str(d.get('vid', ''))
        if not RE_HEX64.match(ed) or not RE_ADDR.match(addr) \
                or cid != cid_de(ed) or not RE_ID.match(vid) \
                or not isinstance(d.get('sig'), str):
            return None
        mh = _s(d, 'mh', 32)
        if mh and not RE_HEX64.match(mh + '0' * 32):
            return None
        mime = _s(d, 'mime', 80)
        e = {'k': 'video', 'vid': vid, 'cid': cid, 'ed': ed, 'addr': addr,
             'titulo': _s(d, 'titulo', 100, True), 'desc': _s(d, 'desc', 1000),
             'cats': _cats(d), 'ts': _i(d, 'ts', 0, agora() + 86400),
             'v': _i(d, 'v', 0, 10 ** 9), 'dur': _i(d, 'dur', 0, 10 ** 6),
             'tam': _i(d, 'tam', 0, 10 ** 13), 'mh': mh,
             'thumb': _thumb(d, 'thumb', 14000), 'live': bool(d.get('live')),
             'mime': mime, 'seg': bool(d.get('seg')),
             'removido': bool(d.get('removido', False)), 'sig': d['sig']}
        return e if verificar(ed, e, e['sig']) else None
    except (ValueError, TypeError):
        return None


class Catalogo:
    def __init__(self, dados_dir):
        self.pasta = os.path.join(dados_dir, 'rede')
        os.makedirs(self.pasta, mode=0o700, exist_ok=True)
        self.lock = threading.RLock()
        self.canais, self.videos, self.sync, self.stats = {}, {}, {}, {}
        self.epoca = secrets.token_hex(6)
        self._mod = 0.0
        self._c = {}
        self._sujo = False
        self._carregar()

    def _p(self, n):
        return os.path.join(self.pasta, n)

    def _carregar(self):
        d = ler_json(self._p('catalogo.json'), {}) or {}
        self.epoca = d.get('epoca') or self.epoca
        for raw in d.get('canais', []):
            e = validar_canal(raw)
            if e:
                self._pos(e, raw)
                self.canais[e['cid']] = e
        for raw in d.get('videos', []):
            e = validar_video(raw)
            if e:
                self._pos(e, raw)
                self.videos[e['vid']] = e
                self._indexar(e)
        self.sync = ler_json(self._p('sync_cat.json'), {}) or {}
        self.stats = ler_json(self._p('stats_cat.json'), {}) or {}

    def _pos(self, e, raw):
        e['mod'] = float(raw.get('mod', 0))
        e['visto'] = int(raw.get('visto', 0))
        self._mod = max(self._mod, e['mod'])

    def salvar(self):
        with self.lock:
            corte = agora() - 60 * 86400
            doc = {'epoca': self.epoca,
                   'canais': [e for e in self.canais.values()
                              if not (e['removido'] and e['mod'] < corte)],
                   'videos': [e for e in self.videos.values()
                              if not (e['removido'] and e['mod'] < corte)]}
            sync, stats = dict(self.sync), dict(self.stats)
            self._sujo = False
        salvar_json(self._p('catalogo.json'), doc)
        salvar_json(self._p('sync_cat.json'), sync)
        salvar_json(self._p('stats_cat.json'), stats)

    def salvar_se_sujo(self):
        if self._sujo:
            try:
                self.salvar()
            except Exception:
                log.exception("salvar catálogo")

    def _prox(self):
        self._mod = max(time.time(), self._mod + 1e-6)
        return self._mod

    def _indexar(self, e):
        c = self.canais.get(e['cid'], {})
        self._c[e['vid']] = preparar(e['titulo'] + ' ' + e['desc'] + ' '
                                     + c.get('nome', ''))

    # ── mesclagem (a assinatura garante autenticidade) ──────────────
    def mesclar(self, raw):
        """'novo' | 'atualizado' | None."""
        if not isinstance(raw, dict):
            return None
        e = validar_canal(raw) if raw.get('k') == 'canal' else \
            validar_video(raw) if raw.get('k') == 'video' else None
        if not e:
            return None
        with self.lock:
            tab, chave = (self.canais, e['cid']) if e['k'] == 'canal' \
                else (self.videos, e['vid'])
            at = tab.get(chave)
            if at is not None:
                if at['ed'] != e['ed'] or e['v'] <= at['v']:
                    return None
            else:
                lim = MAX_CANAIS if e['k'] == 'canal' else MAX_VIDEOS
                if len(tab) >= lim:
                    velho = min(tab.values(), key=lambda x: x['ts'])
                    if e['ts'] <= velho['ts']:
                        return None
                    tab.pop(velho.get('cid') if e['k'] == 'canal'
                            else velho['vid'], None)
            e['mod'], e['visto'] = self._prox(), agora()
            tab[chave] = e
            if e['k'] == 'video':
                self._indexar(e)
            else:
                for v in self.videos.values():
                    if v['cid'] == e['cid']:
                        self._indexar(v)
            self._sujo = True
            return 'novo' if at is None else 'atualizado'

    def delta(self, apos, limite=CAT_PAGINA):
        try:
            am, ag = float(apos[0]), str(apos[1])
        except Exception:
            am, ag = 0.0, ''
        with self.lock:
            itens = [(e['mod'], e.get('vid') or e['cid'], e)
                     for t in (self.canais, self.videos) for e in t.values()
                     if (e['mod'], e.get('vid') or e['cid']) > (am, ag)]
        itens.sort(key=lambda x: (x[0], x[1]))
        pag = itens[:limite]
        prox = [pag[-1][0], pag[-1][1]] if pag else [am, ag]
        return [dict(x[2]) for x in pag], prox, len(itens) > limite

    @staticmethod
    def fio(e):
        return {k: v for k, v in e.items() if k not in
                ('verificado', 'mod', 'visto', 'pontos')}

    # ── consultas ───────────────────────────────────────────────────
    def buscar(self, consulta, limite=20):
        q = preparar(consulta)
        if not q['n']:
            return [], []
        with self.lock:
            canais = [(e, preparar(e['nome'] + ' ' + e['desc'] + ' '
                                   + ' '.join(e['cats'])))
                      for e in self.canais.values() if not e['removido']]
            vids = [(e, self._c.get(e['vid'])) for e in self.videos.values()
                    if not e['removido']]
        rc = sorted(((pontuar(q, c), e) for e, c in canais), key=lambda x: -x[0])
        rv = sorted(((pontuar(q, c), e) for e, c in vids if c),
                    key=lambda x: (-x[0], -x[1]['ts']))
        return ([e for s, e in rc if s >= 0.4][:limite],
                [e for s, e in rv if s >= 0.4][:limite * 2])

    def videos_do_canal(self, cid):
        with self.lock:
            v = [e for e in self.videos.values()
                 if e['cid'] == cid and not e['removido']]
        return sorted(v, key=lambda e: -e['ts'])

    def todos_videos(self):
        with self.lock:
            return [e for e in self.videos.values() if not e['removido']]

    def set_stats(self, vid, vis, gos, nao):
        with self.lock:
            self.stats[vid] = {'vis': int(vis), 'gos': int(gos),
                               'nao': int(nao), 'ts': agora()}
            self._sujo = True

    def get_sync(self, pub):
        return self.sync.get(pub.upper(), {})

    def set_sync(self, pub, cursor, epoca):
        with self.lock:
            self.sync[pub.upper()] = {'cursor': cursor, 'epoca': epoca,
                                      'ts': agora()}
            self._sujo = True

    def contagem(self):
        with self.lock:
            return {'canais': sum(1 for e in self.canais.values()
                                  if not e['removido']),
                    'videos': sum(1 for e in self.videos.values()
                                  if not e['removido'])}

    def exportar(self):
        with self.lock:
            return {'canais': [self.fio(e) for e in self.canais.values()],
                    'videos': [self.fio(e) for e in self.videos.values()]}

    def importar(self, bloco):
        n = 0
        for e in (bloco.get('canais') or [])[:MAX_CANAIS] + \
                (bloco.get('videos') or [])[:MAX_VIDEOS]:
            if self.mesclar(e):
                n += 1
        self.salvar()
        return {'entradas': n}
