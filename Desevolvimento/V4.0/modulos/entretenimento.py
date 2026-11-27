# -*- coding: utf-8 -*-
"""RRFS Social - Entretenimento (vídeos, canais e lives sem servidor).

* O dono do canal é o "servidor" dos seus vídeos (sem limite de espaço).
* Cada vídeo é dividido em pedaços de 512 KB com hash. Quem assiste baixa os
  pedaços enquanto reproduz, guarda em cache (5% do disco, LRU) e passa a
  servir esses pedaços a outros espectadores (enxame).
* Lives: o navegador (ou OBS via ffmpeg) gera segmentos de ~4 s; cada segmento
  é um pedaço. Espectadores trocam segmentos entre si: quanto mais gente
  assiste, mais fontes existem.
* Votos, comentários e inscritos de um vídeo ficam com o dono (autoritativo).
* Bloqueio: o dono publica (assinado) hashes dos bloqueados; clientes
  honestos recusam servir/mostrar o canal a eles."""
import os
import re
import time
import json
import base64
import shutil
import struct
import random
import hashlib
import secrets
import threading
import subprocess
import itertools

from .util import (log, ErroSocial, RE_ID, RE_ADDR, agora, novo_id, limpar,
                   limpar_multilinha, decodificar_imagem)
from .catalogo import (CATEGORIAS, MIMES_VIDEO, Catalogo, nova_chave, assinar,
                       cid_de, hash_bloq, canonico)
from .cofre import ErroCofre

PECA = 512 * 1024
SUBPEDACO = 1100
MAX_FLIGHT = 6
JANELA = 12
MAX_CLIENTES_VIDEO = 400
MAX_SEG_LIVE = 16 * 1024 * 1024
LIVE_MIME_PADRAO = 'video/webm; codecs="vp8,opus"'


def bit_get(b, i):
    return i >= 0 and (i >> 3) < len(b) and bool(b[i >> 3] & (1 << (i & 7)))


def bit_set(b, i):
    while (i >> 3) >= len(b):
        b.append(0)
    b[i >> 3] |= 1 << (i & 7)


def hash_peca(d):
    return hashlib.sha256(d).hexdigest()[:32]


def hash_man(man):
    return hashlib.sha256(canonico(man)).hexdigest()[:32]


def n_pecas(man):
    return len(man['h']) // 32


def tam_peca(man, i):
    if 'tams' in man:
        return int(man['tams'][i])
    return min(man['pc'], man['tam'] - i * man['pc'])


def man_valido(m):
    try:
        if not isinstance(m, dict) or not isinstance(m.get('h'), str) \
                or len(m['h']) % 32 or not re.match(r'^[0-9a-f]*$', m['h']):
            return False
        n = len(m['h']) // 32
        if n < 1 or n > 400000 or m.get('mime') not in MIMES_VIDEO + \
                ('video/webm; codecs="vp8,opus"',) and not \
                str(m.get('mime', '')).startswith('video/webm'):
            return False
        if 'tams' in m:
            return isinstance(m['tams'], list) and len(m['tams']) == n and \
                all(isinstance(x, int) and 0 < x <= MAX_SEG_LIVE
                    for x in m['tams'])
        return isinstance(m.get('pc'), int) and m['pc'] == PECA and \
            isinstance(m.get('tam'), int) and (n - 1) * PECA < m['tam'] <= n * PECA
    except Exception:
        return False


class Ent:
    def __init__(self, s):
        self.s, self.t, self.cat, self.cofre = s, s.t, s.cat, s.cofre
        self._bitsd = {}
        self.rx, self.voo, self.carga, self.tx = {}, {}, {}, {}
        self.enx, self.dl = {}, {}
        self.live, self.live_v = {}, {}
        self._cond = threading.Condition()
        self._meta_t, self._tem_pend, self._tem_t = {}, set(), {}
        self._canal_t = {}
        self._buscas = {}
        self._rtmp = {}
        self.enx_dono = {}
        self._clientes_video = set()

    # ═══ ciclo de vida ═══════════════════════════════════════════════
    def iniciar(self):
        self._recuperar_lives()
        for vid, vl in self.t['vlocal'].items():
            if not vl.get('meu') and not vl.get('completo') and vl.get('man') \
                    and agora() - vl.get('ult', 0) < 2 * 86400:
                self._ativar(vid, tudo=True)
        threading.Thread(target=self._loop, name='Ent', daemon=True).start()

    def _loop(self):
        t_lento = 0
        while self.s.rodando:
            try:
                self._tick()
                if time.time() - t_lento > 30:
                    t_lento = time.time()
                    self._lento()
            except Exception:
                log.exception("ent loop")
            time.sleep(0.4)

    # ═══ armazenamento de pedaços ════════════════════════════════════
    def _dir(self, vid):
        return os.path.join(self.s.pasta, 'video', vid)

    def _pf(self, vid, idx):
        return os.path.join(self._dir(vid), str(idx))

    def _bits(self, vid):
        b = self._bitsd.get(vid)
        if b is None:
            b = bytearray.fromhex((self.t['vlocal'].get(vid) or {}).get('bits', ''))
            self._bitsd[vid] = b
        return b

    def _vl(self, vid, v=None):
        vl = self.t['vlocal'].get(vid)
        if vl is None and v is not None:
            vl = self.t['vlocal'][vid] = {
                'cid': v['cid'], 'addr': v['addr'], 'bits': '', 'bytes': 0,
                'meu': False, 'ult': agora(), 'man': None, 'completo': False,
                'titulo': v['titulo'], 'pares': []}
            self.s.banco.sujar('vlocal')
        return vl

    def _guardar_peca(self, vid, idx, dados):
        os.makedirs(self._dir(vid), mode=0o700, exist_ok=True)
        self.cofre.gravar_bytes(self._pf(vid, idx), dados)
        with self.s.L:
            vl = self.t['vlocal'].get(vid)
            if not vl:
                return
            b = self._bits(vid)
            if not bit_get(b, idx):
                bit_set(b, idx)
                vl['bytes'] = vl.get('bytes', 0) + len(dados)
            vl['bits'], vl['ult'] = b.hex(), agora()
            self.s.banco.sujar('vlocal')
        self._tem_pend.add(vid)
        with self._cond:
            self._cond.notify_all()
        if not vl.get('meu'):
            self._aplicar_cache(vid)

    def _ler_se_tem(self, vid, idx):
        if not bit_get(self._bits(vid), idx):
            return None
        try:
            d = self.cofre.ler_bytes(self._pf(vid, idx))
            if d is not None:
                return d
        except ErroCofre:
            pass
        with self.s.L:
            b = self._bits(vid)
            b[idx >> 3] &= ~(1 << (idx & 7))
            self.t['vlocal'][vid]['bits'] = b.hex()
        return None

    # ═══ cache (5% do disco, substitui os mais antigos) ══════════════
    def _cache_limite(self):
        try:
            tot = shutil.disk_usage(self.s.pasta).total
        except OSError:
            return 0
        return int(tot * float(self.t['ajustes'].get('cache_pct', 5)) / 100)

    def _limpar_cache(self, vid):
        shutil.rmtree(self._dir(vid), ignore_errors=True)
        with self.s.L:
            vl = self.t['vlocal'].get(vid)
            if vl:
                vl.update(bits='', bytes=0, completo=False)
            self._bitsd.pop(vid, None)
            self.s.banco.sujar('vlocal')

    def _aplicar_cache(self, protegido=None):
        lim = self._cache_limite()
        itens = [(v, vl) for v, vl in self.t['vlocal'].items() if not vl.get('meu')]
        total = sum(vl.get('bytes', 0) for _, vl in itens)
        if total <= lim:
            return
        ordem = sorted((x for x in itens if x[0] != protegido
                        and x[0] not in self.dl and x[0] not in self.live_v),
                       key=lambda x: x[1].get('ult', 0))
        for vid, vl in ordem:
            total -= vl.get('bytes', 0)
            self._limpar_cache(vid)
            if total <= lim:
                return
        # ainda estourou: libera os pedaços já assistidos do próprio vídeo
        st = self.dl.get(protegido)
        vl = self.t['vlocal'].get(protegido)
        if st and vl:
            for i in range(0, max(0, st['pos'] - 2)):
                if total <= lim:
                    break
                if bit_get(self._bits(protegido), i):
                    try:
                        os.remove(self._pf(protegido, i))
                    except OSError:
                        pass
                    b = self._bits(protegido)
                    b[i >> 3] &= ~(1 << (i & 7))
                    inf = self._pec_info(protegido, i)
                    total -= inf[0] if inf else 0
                    vl['bytes'] = max(0, vl['bytes'] - (inf[0] if inf else 0))
            vl['bits'] = self._bits(protegido).hex()
            vl['completo'] = False
            st['tudo'] = False

    def cache_info(self):
        usados = sum(vl.get('bytes', 0) for vl in self.t['vlocal'].values()
                     if not vl.get('meu'))
        return {'usado': usados, 'limite': self._cache_limite(),
                'pct': self.t['ajustes'].get('cache_pct', 5)}

    # ═══ informação de pedaços ═══════════════════════════════════════
    def _pec_info(self, vid, idx):
        vl = self.t['vlocal'].get(vid)
        man = vl.get('man') if vl else None
        if man and 0 <= idx < n_pecas(man):
            return tam_peca(man, idx), man['h'][idx * 32:(idx + 1) * 32]
        lv = self.live_v.get(vid)
        if lv and idx in lv['segs']:
            return lv['segs'][idx]['tam'], lv['segs'][idx]['h']
        lo = self.live.get(vid)
        if lo and 0 <= idx < len(lo['segs']):
            return lo['segs'][idx]['tam'], lo['segs'][idx]['h']
        return None

    def _n_pecas(self, vid):
        vl = self.t['vlocal'].get(vid)
        if vl and vl.get('man'):
            return n_pecas(vl['man'])
        lv = self.live_v.get(vid)
        if lv and lv['segs']:
            return max(lv['segs']) + 1
        return None

    # ═══ canal (dono) ════════════════════════════════════════════════
    def _canal(self):
        return self.t['canal_meu'] or None

    def meu_canal(self):
        c = self._canal()
        if not c:
            return None
        return {'cid': c['cid'], 'nome': c['nome'], 'desc': c['desc'],
                'cats': c['cats'], 'foto_mini': c['foto_mini'],
                'foto': c.get('foto_mid', ''), 'capa': c.get('capa_mid', ''),
                'inscritos': len(c['inscritos']), 'bloqueados': len(c['bloq']),
                'videos': len([1 for v in self.cat.videos_do_canal(c['cid'])])}

    def _salvar_img(self, data_url, limite, antigo):
        raw, mime = decodificar_imagem(data_url, limite)
        if not raw:
            raise ErroSocial('Imagem inválida (JPEG, PNG ou WebP).')
        mid = novo_id()
        esc = self.s.banco.escritor_midia(mid)
        esc.escrever(raw)
        tam, sha = esc.fechar()
        self.t['midia'][mid] = {'nome': 'canal', 'mime': mime, 'tam': tam,
                                'sha': sha, 'dono': 'eu', 'acl': {'tipo': 'publico'}}
        if antigo:
            self.s.banco.apagar_midia(antigo)
        return mid, sha[:8]

    def salvar_canal(self, d):
        nome = limpar(d.get('nome'), 60)
        if not nome:
            raise ErroSocial('Dê um nome ao canal.')
        cats = [c for c in (d.get('cats') or []) if c in CATEGORIAS][:5]
        with self.s.L:
            c = self._canal()
            if not c:
                priv, ed = nova_chave()
                c = self.t['canal_meu'] = {
                    'cid': cid_de(ed), 'priv': priv, 'ed': ed, 'nome': '',
                    'desc': '', 'cats': [], 'foto_mini': '', 'foto_mid': '',
                    'capa_mid': '', 'ia': '', 'ic': '', 'bloq': [],
                    'inscritos': [], 'nomes': {}, 'v': 0, 'ts': agora(),
                    'rtmp': secrets.token_hex(8)}
            c['nome'], c['cats'] = nome, cats
            c['desc'] = limpar_multilinha(d.get('desc'), 600)
            if d.get('foto'):
                c['foto_mid'], c['ia'] = self._salvar_img(
                    d['foto'], 2 * 1024 ** 2, c['foto_mid'])
                from .util import validar_mini
                c['foto_mini'] = validar_mini(d.get('foto_mini')) or c['foto_mini']
            if d.get('capa'):
                c['capa_mid'], c['ic'] = self._salvar_img(
                    d['capa'], 4 * 1024 ** 2, c['capa_mid'])
            self.s.banco.sujar('canal_meu')
            self.s.banco.sujar('midia')
        self._publicar_canal()

    def _publicar_canal(self, removido=False):
        c = self._canal()
        with self.s.L:
            c['v'] += 1
            e = {'k': 'canal', 'cid': c['cid'], 'ed': c['ed'],
                 'addr': self.s.addr(), 'nome': c['nome'], 'desc': c['desc'],
                 'cats': c['cats'], 'foto_mini': c['foto_mini'],
                 'bloq': [hash_bloq(c['cid'], p) for p in c['bloq']],
                 'v': c['v'], 'ts': agora(), 'removido': removido}
            e['sig'] = assinar(c['priv'], e)
            self.s.banco.sujar('canal_meu')
        self.cat.mesclar(e)
        self._difundir([e])

    def _difundir(self, entradas):
        msg = {'tipo': 'v_cat_dados', 'itens': [Catalogo.fio(e) for e in entradas],
               'push': True, 'epoca': self.cat.epoca}
        for a in self.s.no.listar_amigos():
            if a['status'] and self.s._pode_dir(a['chave_publica']):
                self.s._enviar_async(a['chave_publica'], msg)

    def bloquear(self, pub):
        c = self._canal()
        pub = str(pub).upper()
        if not c or not re.match(r'^[0-9A-F]{64}$', pub) or pub == self.s.pub():
            raise ErroSocial('Usuário inválido.')
        with self.s.L:
            if pub not in c['bloq']:
                c['bloq'].append(pub)
            if pub in c['inscritos']:
                c['inscritos'].remove(pub)
            for m in self.t['mvid'].values():
                m['coms'] = [x for x in m['coms'] if x['pub'] != pub]
            for lo in self.live.values():
                lo['viewers'].pop(pub, None)
        self._publicar_canal()

    def desbloquear(self, pub):
        c = self._canal()
        if c and str(pub).upper() in c['bloq']:
            c['bloq'].remove(str(pub).upper())
            self._publicar_canal()

    def bloqueados(self):
        c = self._canal()
        return [{'pub': p, 'nome': c['nomes'].get(p, 'Usuário ' + p[:8])}
                for p in (c['bloq'] if c else [])]

    def _bloqueado(self, pub):
        c = self._canal()
        return bool(c and pub in c['bloq'])

    def _me_bloqueou(self, cid):
        e = self.cat.canais.get(cid)
        return bool(e and hash_bloq(cid, self.s.pub()) in e['bloq'])

    # ═══ vídeos (dono) ═══════════════════════════════════════════════
    def _entrada_video(self, vid, base, **mud):
        c = self._canal()
        e = dict(base)
        e.update(mud)
        e.pop('sig', None)
        for k in ('mod', 'visto', 'pontos', 'verificado'):
            e.pop(k, None)
        e['v'] = int(e.get('v', 0)) + 1
        e['sig'] = assinar(c['priv'], e)
        self.cat.mesclar(e)
        self._difundir([e])
        return e

    def receber_video(self, leitor, titulo, desc, cats, dur, thumb):
        c = self._canal()
        if not c:
            raise ErroSocial('Crie o seu canal antes de enviar vídeos.')
        titulo = limpar(titulo, 100)
        if not titulo:
            raise ErroSocial('Dê um título ao vídeo.')
        vid = novo_id()
        os.makedirs(self._dir(vid), mode=0o700, exist_ok=True)
        hs, tam, idx, mime = [], 0, 0, None
        try:
            while True:
                bloco = b''
                while len(bloco) < PECA:
                    ch = leitor(PECA - len(bloco))
                    if not ch:
                        break
                    bloco += ch
                if not bloco:
                    break
                if idx == 0:
                    if bloco[4:8] == b'ftyp':
                        mime = 'video/mp4'
                    elif bloco[:4] == b'\x1a\x45\xdf\xa3':
                        mime = 'video/webm'
                    else:
                        raise ErroSocial('Formato não suportado. Use MP4 ou WebM.')
                self.cofre.gravar_bytes(self._pf(vid, idx), bloco)
                hs.append(hash_peca(bloco))
                tam += len(bloco)
                idx += 1
            if not tam:
                raise ErroSocial('Arquivo vazio.')
        except Exception:
            shutil.rmtree(self._dir(vid), ignore_errors=True)
            raise
        man = {'vid': vid, 'tam': tam, 'pc': PECA, 'h': ''.join(hs), 'mime': mime}
        b = bytearray()
        for i in range(idx):
            bit_set(b, i)
        cats = [x for x in (cats or []) if x in CATEGORIAS][:5] or c['cats']
        th = thumb if isinstance(thumb, str) and len(thumb) <= 14000 and \
            thumb.startswith('data:image/jpeg;base64,') else ''
        with self.s.L:
            self.t['vlocal'][vid] = {
                'cid': c['cid'], 'addr': self.s.addr(), 'bits': b.hex(),
                'bytes': tam, 'meu': True, 'ult': agora(), 'man': man,
                'completo': True, 'titulo': titulo, 'pares': []}
            self._bitsd[vid] = b
            self.t['mvid'][vid] = {'votos': {}, 'vis': {}, 'coms': []}
            self.s.banco.sujar('vlocal')
            self.s.banco.sujar('mvid')
        base = {'k': 'video', 'vid': vid, 'cid': c['cid'], 'ed': c['ed'],
                'addr': self.s.addr(), 'titulo': titulo,
                'desc': limpar_multilinha(desc, 1000), 'cats': cats,
                'ts': agora(), 'v': 0, 'dur': max(0, min(int(dur or 0), 10 ** 6)),
                'tam': tam, 'mh': hash_man(man), 'thumb': th, 'live': False,
                'mime': mime, 'seg': False, 'removido': False}
        self._entrada_video(vid, base)
        self.s._evento('ent')
        return vid

    def apagar_video(self, vid):
        e = self.cat.videos.get(vid)
        c = self._canal()
        if not e or not c or e['cid'] != c['cid']:
            raise ErroSocial('Vídeo não encontrado.')
        if vid in self.live:
            self.live_encerrar(vid)
            e = self.cat.videos.get(vid)
        self._entrada_video(vid, e, removido=True, thumb='', desc='')
        shutil.rmtree(self._dir(vid), ignore_errors=True)
        with self.s.L:
            self.t['vlocal'].pop(vid, None)
            self.t['mvid'].pop(vid, None)
            self._bitsd.pop(vid, None)
            self.s.banco.sujar('vlocal')
            self.s.banco.sujar('mvid')
        self.s._evento('ent')

    def meus_videos(self):
        c = self._canal()
        return [self._card(v) for v in self.cat.videos_do_canal(c['cid'])] if c else []

    # ═══ lives (dono) ════════════════════════════════════════════════
    def live_iniciar(self, titulo, desc, cats, mime, thumb):
        c = self._canal()
        if not c:
            raise ErroSocial('Crie o seu canal antes.')
        titulo = limpar(titulo, 100)
        if not titulo:
            raise ErroSocial('Dê um título à live.')
        if any(self.live):
            raise ErroSocial('Você já tem uma live em andamento.')
        mime = str(mime or LIVE_MIME_PADRAO)[:80]
        if not mime.startswith('video/webm') or re.search(r'[\x00-\x1f]', mime):
            raise ErroSocial('Formato de live inválido.')
        vid = novo_id()
        cats = [x for x in (cats or []) if x in CATEGORIAS][:5] or c['cats']
        th = thumb if isinstance(thumb, str) and len(thumb) <= 14000 and \
            thumb.startswith('data:image/jpeg;base64,') else ''
        with self.s.L:
            self.t['vlocal'][vid] = {
                'cid': c['cid'], 'addr': self.s.addr(), 'bits': '', 'bytes': 0,
                'meu': True, 'ult': agora(), 'man': None, 'completo': False,
                'titulo': titulo, 'pares': []}
            self.t['mvid'][vid] = {'votos': {}, 'vis': {}, 'coms': []}
            self.live[vid] = {'segs': [], 'viewers': {}, 'mime': mime}
            self.s.banco.sujar('vlocal')
        base = {'k': 'video', 'vid': vid, 'cid': c['cid'], 'ed': c['ed'],
                'addr': self.s.addr(), 'titulo': titulo,
                'desc': limpar_multilinha(desc, 1000), 'cats': cats,
                'ts': agora(), 'v': 0, 'dur': 0, 'tam': 0, 'mh': '',
                'thumb': th, 'live': True, 'mime': mime, 'seg': True,
                'removido': False}
        self._entrada_video(vid, base)
        self.s._evento('ent')
        return vid

    def live_segmento(self, vid, dados, dur):
        lo = self.live.get(vid)
        if not lo or not dados or len(dados) > MAX_SEG_LIVE:
            raise ErroSocial('Live não está ativa ou segmento inválido.')
        idx = len(lo['segs'])
        seg = {'tam': len(dados), 'h': hash_peca(dados),
               'dur': max(0.0, min(float(dur or 4), 30.0))}
        lo['segs'].append(seg)
        self._guardar_peca(vid, idx, dados)
        msg = {'tipo': 'v_live_seg', 'vid': vid, 'i': idx, **seg}
        for p in list(lo['viewers']):
            self.s._enviar_async(p, msg)
        return idx

    def live_encerrar(self, vid):
        lo = self.live.pop(vid, None)
        proc = self._rtmp.pop(vid, None)
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        e = self.cat.videos.get(vid)
        if not lo or not e:
            raise ErroSocial('Live não encontrada.')
        for p in list(lo['viewers']):
            self.s._enviar_async(p, {'tipo': 'v_live_fim', 'vid': vid})
        if not lo['segs']:
            self.live[vid] = lo
            self.live.pop(vid)
            self._entrada_video(vid, e, removido=True, live=False, thumb='')
            self.t['vlocal'].pop(vid, None)
            return
        man = {'vid': vid, 'tam': sum(x['tam'] for x in lo['segs']), 'pc': 0,
               'h': ''.join(x['h'] for x in lo['segs']),
               'tams': [x['tam'] for x in lo['segs']], 'seg': True,
               'mime': lo['mime']}
        with self.s.L:
            vl = self.t['vlocal'][vid]
            vl['man'], vl['completo'] = man, True
            self.s.banco.sujar('vlocal')
        self._entrada_video(vid, e, live=False, tam=man['tam'], mh=hash_man(man),
                            dur=int(sum(x['dur'] for x in lo['segs'])))
        self.s._evento('ent')

    def _recuperar_lives(self):
        c = self._canal()
        if not c:
            return
        for v in self.cat.videos_do_canal(c['cid']):
            if v['live'] and v['vid'] not in self.live:
                vl = self.t['vlocal'].get(v['vid'])
                n = len([f for f in os.listdir(self._dir(v['vid']))]) \
                    if os.path.isdir(self._dir(v['vid'])) else 0
                if not vl or not n:
                    self._entrada_video(v['vid'], v, live=False, removido=True)
                    continue
                segs = []
                ok = True
                for i in range(n):
                    try:
                        d = self.cofre.ler_bytes(self._pf(v['vid'], i))
                    except ErroCofre:
                        d = None
                    if d is None:
                        ok = False
                        break
                    segs.append({'tam': len(d), 'h': hash_peca(d), 'dur': 4.0})
                if not ok:
                    continue
                self.live[v['vid']] = {'segs': segs, 'viewers': {},
                                       'mime': v['mime']}
                self.live_encerrar(v['vid'])

    def live_rtmp(self, vid, host='127.0.0.1', porta=1935):
        """Recebe OBS/Studio por RTMP via ffmpeg e converte em segmentos."""
        lo, c = self.live.get(vid), self._canal()
        if not lo or not c:
            raise ErroSocial('Inicie a live primeiro.')
        if not shutil.which('ffmpeg'):
            raise ErroSocial('ffmpeg não instalado (sudo apt install ffmpeg).')
        if vid in self._rtmp:
            return self._rtmp_info(c, host, porta)
        tmp = os.path.join(self.s.pasta, 'tmp_live', vid)
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp, mode=0o700)
        cmd = ['ffmpeg', '-hide_banner', '-loglevel', 'error', '-listen', '1',
               '-i', f"rtmp://{host}:{porta}/live/{c['rtmp']}",
               '-c:v', 'libvpx', '-deadline', 'realtime', '-cpu-used', '8',
               '-b:v', '2500k', '-g', '60', '-force_key_frames',
               'expr:gte(t,n_forced*4)', '-c:a', 'libopus', '-b:a', '96k',
               '-f', 'segment', '-segment_time', '4', '-segment_format', 'webm',
               '-reset_timestamps', '1', os.path.join(tmp, 'seg%06d.webm')]
        proc = subprocess.Popen(cmd, stderr=subprocess.DEVNULL)
        self._rtmp[vid] = proc
        lo['mime'] = LIVE_MIME_PADRAO

        def vigia():
            k = 0
            while vid in self.live and (proc.poll() is None or
                                        os.path.exists(os.path.join(tmp, 'seg%06d.webm' % k))):
                atual = os.path.join(tmp, 'seg%06d.webm' % k)
                prox = os.path.join(tmp, 'seg%06d.webm' % (k + 1))
                if os.path.exists(atual) and (os.path.exists(prox) or proc.poll() is not None):
                    try:
                        with open(atual, 'rb') as f:
                            dados = f.read()
                        if dados:
                            self.live_segmento(vid, dados, 4)
                        os.remove(atual)
                    except Exception:
                        log.exception("rtmp segmento")
                    k += 1
                else:
                    time.sleep(0.4)
            shutil.rmtree(tmp, ignore_errors=True)
        threading.Thread(target=vigia, name='RTMP', daemon=True).start()
        return self._rtmp_info(c, host, porta)

    @staticmethod
    def _rtmp_info(c, host, porta):
        return {'servidor': f'rtmp://{host}:{porta}/live', 'chave': c['rtmp']}

    # ═══ cartões / listas ════════════════════════════════════════════
    def _card(self, v):
        c = self.cat.canais.get(v['cid'], {})
        st = self.cat.stats.get(v['vid'], {})
        return {'vid': v['vid'], 'titulo': v['titulo'], 'thumb': v['thumb'],
                'dur': v['dur'], 'ts': v['ts'], 'live': v['live'] and
                agora() - v['ts'] < 12 * 3600, 'cid': v['cid'],
                'canal': c.get('nome') or 'Canal ' + v['cid'][:6],
                'canal_mini': c.get('foto_mini', ''), 'cats': v['cats'],
                'vis': st.get('vis'), 'gos': st.get('gos'), 'nao': st.get('nao'),
                'meu': v['cid'] == (self._canal() or {}).get('cid')}

    def _visivel(self, v):
        return not v['removido'] and not self._me_bloqueou(v['cid']) and \
            (not v['live'] or agora() - v['ts'] < 12 * 3600)

    def _score(self, v):
        st = self.cat.stats.get(v['vid'], {})
        base = st.get('vis', 0) + 3 * st.get('gos', 0) - 2 * st.get('nao', 0) + 1
        idade = max(1.0, (agora() - v['ts']) / 3600.0)
        return base / (idade + 2) ** 1.3

    def _interesses(self):
        pesos = {}
        for cid in self.t['vinscr']:
            for ct in (self.cat.canais.get(cid) or {}).get('cats', []):
                pesos[ct] = pesos.get(ct, 0) + 3
        for ct, n in (self.t['vhist'].get('cats') or {}).items():
            pesos[ct] = pesos.get(ct, 0) + n
        return pesos

    def inicio(self):
        todos = [v for v in self.cat.todos_videos() if self._visivel(v)]
        vistos = self.t['vhist'].get('vistos') or {}
        recentes = sorted(todos, key=lambda v: -v['ts'])[:24]
        alta = sorted((v for v in todos if agora() - v['ts'] < 30 * 86400
                       and not v['live']), key=lambda v: -self._score(v))[:16]
        ao_vivo = sorted((v for v in todos if v['live']), key=lambda v: -v['ts'])[:12]
        pesos = self._interesses()
        rec = []
        if pesos:
            def pont(v):
                return sum(pesos.get(c, 0) for c in v['cats']) + \
                    min(5.0, self._score(v) * 50)
            rec = sorted((v for v in todos if v['vid'] not in vistos
                          and not v['live'] and any(c in pesos for c in v['cats'])),
                         key=lambda v: -pont(v))[:16]
        insc = sorted((v for v in todos if v['cid'] in self.t['vinscr']),
                      key=lambda v: -v['ts'])[:24]
        f = self._card
        return {'ao_vivo': [f(v) for v in ao_vivo], 'em_alta': [f(v) for v in alta],
                'recentes': [f(v) for v in recentes],
                'recomendados': [f(v) for v in rec],
                'inscricoes': [f(v) for v in insc],
                'meu_canal': bool(self._canal()),
                'catalogo': self.cat.contagem()}

    def buscar(self, texto):
        import queue
        texto = limpar(texto, 80)
        if len(texto) < 2:
            raise ErroSocial('Digite pelo menos 2 letras.')
        bid = secrets.token_hex(6)
        q = queue.Queue()
        self._buscas[bid] = q
        alvos = [a['chave_publica'] for a in self.s.no.listar_amigos()
                 if a['status'] and self.s._pode_dir(a['chave_publica'])]
        random.shuffle(alvos)
        alvos = alvos[:8]
        try:
            for p in alvos:
                self.s._enviar_async(p, {'tipo': 'v_cat_busca', 'id': bid, 'q': texto})
            fim, esp = time.time() + 3.5, len(alvos)
            while esp > 0 and time.time() < fim:
                try:
                    _, itens = q.get(timeout=max(0.05, fim - time.time()))
                except queue.Empty:
                    break
                esp -= 1
                for e in itens[:40]:
                    self.cat.mesclar(e)
        finally:
            self._buscas.pop(bid, None)
        canais, videos = self.cat.buscar(texto)
        return {'consultados': len(alvos),
                'canais': [self._card_canal(c) for c in canais
                           if not self._me_bloqueou(c['cid'])],
                'videos': [self._card(v) for v in videos if self._visivel(v)]}

    def _card_canal(self, c):
        cc = self.t['vcc'].get(c['cid'], {})
        return {'cid': c['cid'], 'nome': c['nome'], 'desc': c['desc'][:140],
                'cats': c['cats'], 'foto_mini': c['foto_mini'],
                'inscritos': cc.get('inscritos'), 'inscrito': c['cid'] in self.t['vinscr']}

    # ═══ canais (espectador) ═════════════════════════════════════════
    def canal_info(self, cid):
        e = self.cat.canais.get(cid)
        if not e or e['removido']:
            raise ErroSocial('Canal não encontrado.')
        if self._me_bloqueou(cid):
            raise ErroSocial('Este canal bloqueou você.')
        meu = self._canal() and self._canal()['cid'] == cid
        cc = self.t['vcc'].get(cid, {})
        if meu:
            c = self._canal()
            cc = {'inscritos': len(c['inscritos'])}
        else:
            self._pedir_canal(cid)
        return {'canal': Catalogo.fio(e), 'avatar': cc.get('avatar') or e['foto_mini'],
                'capa': cc.get('capa', ''), 'inscritos': cc.get('inscritos'),
                'inscrito': cid in self.t['vinscr'], 'sou_dono': bool(meu),
                'videos': [self._card(v) for v in self.cat.videos_do_canal(cid)
                           if self._visivel(v)],
                'foto_local': (self._canal() or {}).get('foto_mid') if meu else '',
                'capa_local': (self._canal() or {}).get('capa_mid') if meu else ''}

    def _pedir_canal(self, cid, n=40):
        e = self.cat.canais.get(cid)
        if not e or time.time() - self._canal_t.get(cid, 0) < 20:
            return
        self._canal_t[cid] = time.time()
        pub = e['addr'][:64]
        cc = self.t['vcc'].get(cid, {})
        msg = {'tipo': 'v_canal_pedir', 'cid': cid, 'n': n,
               'ia': cc.get('ia', ''), 'ic': cc.get('ic', '')}
        if self.s._online(pub):
            self.s._enviar_async(pub, msg)
        else:
            self.s._link(e['addr'], 'video:' + cid)

    def inscrever(self, cid, on):
        e = self.cat.canais.get(cid)
        if not e:
            raise ErroSocial('Canal não encontrado.')
        if self._canal() and self._canal()['cid'] == cid:
            raise ErroSocial('Este é o seu canal.')
        with self.s.L:
            if on:
                if len(self.t['vinscr']) >= 200:
                    raise ErroSocial('Limite de inscrições atingido.')
                self.t['vinscr'][cid] = {'ts': agora(), 'addr': e['addr'],
                                         'nome': e['nome']}
            else:
                self.t['vinscr'].pop(cid, None)
            self.s.banco.sujar('vinscr')
        self.s._link(e['addr'], 'video:' + cid)
        self.s._entregar(e['addr'][:64], {'tipo': 'v_inscrever', 'cid': cid,
                                          'on': bool(on)})
        cc = self.t['vcc'].setdefault(cid, {})
        if cc.get('inscritos') is not None:
            cc['inscritos'] = max(0, cc['inscritos'] + (1 if on else -1))
        self._pedir_canal(cid)

    def inscricoes(self):
        return [self._card_canal(self.cat.canais[c]) for c in self.t['vinscr']
                if c in self.cat.canais]

    # ═══ assistir (espectador) ═══════════════════════════════════════
    def _hist(self, v):
        h = self.t['vhist']
        h.setdefault('vistos', {})[v['vid']] = agora()
        cats = h.setdefault('cats', {})
        for c in v['cats']:
            cats[c] = cats.get(c, 0) + 1
        if len(h['vistos']) > 2000:
            for k in sorted(h['vistos'], key=h['vistos'].get)[:500]:
                h['vistos'].pop(k)
        self.s.banco.sujar('vhist')

    def _ativar(self, vid, tudo=True, live=False, pos=0):
        st = self.dl.get(vid)
        if st is None:
            st = self.dl[vid] = {'prio': set(), 'pos': pos, 'acesso': time.time(),
                                 'tudo': tudo, 'live': live}
        st['acesso'] = time.time()
        return st

    def abrir(self, vid):
        v = self.cat.videos.get(vid)
        if not v or v['removido']:
            raise ErroSocial('Vídeo não encontrado.')
        if self._me_bloqueou(v['cid']):
            raise ErroSocial('Este canal bloqueou você.')
        meu = v['cid'] == (self._canal() or {}).get('cid')
        vl = self._vl(vid, v)
        vl['ult'] = agora()
        self._hist(v)
        if not meu:
            self._ativar(vid, tudo=not v['live'], live=v['live'])
            self._garantir_dono(v)
            self._pedir_meta(vid, forcar=True)
        return self.estado_video(vid)

    def _garantir_dono(self, v):
        pub = v['addr'][:64]
        if self.s.no.buscar_amigo_por_chave(pub) is None:
            self.s._link(v['addr'], 'video:' + v['vid'])

    def estado_video(self, vid):
        v = self.cat.videos.get(vid)
        vl = self.t['vlocal'].get(vid) or {}
        man = vl.get('man')
        n = n_pecas(man) if man else None
        tem = sum(1 for i in range(n or 0) if bit_get(self._bits(vid), i))
        dono = (v or {}).get('addr', vl.get('addr', ''))[:64]
        fontes = self.s._online(dono) or any(
            self.s._online(p) for p in self.enx.get(vid, {}).get('pares', {}))
        return {'vid': vid, 'pronto': bool(man), 'live': bool(v and v['live']),
                'seg': bool(man and man.get('seg')), 'mime': (man or {}).get('mime')
                or (v or {}).get('mime', ''), 'tam': (man or {}).get('tam', 0),
                'pecas': n, 'tem': tem, 'completo': bool(n and tem == n),
                'fonte_online': bool(fontes or vl.get('meu')),
                'dono_online': self.s._online(dono) or bool(vl.get('meu'))}

    def obter_peca(self, vid, idx, timeout=60):
        st = self._ativar(vid, tudo=not self.cat.videos.get(vid, {}).get('live'),
                          live=bool(self.cat.videos.get(vid, {}).get('live')))
        st['prio'].add(idx)
        st['acesso'] = time.time()
        if not st['live']:
            st['pos'] = idx
        fim = time.time() + timeout
        while True:
            d = self._ler_se_tem(vid, idx)
            if d is not None:
                vl = self.t['vlocal'].get(vid)
                if vl:
                    vl['ult'] = agora()
                return d
            if time.time() > fim:
                raise TimeoutError('Sem fontes disponíveis agora')
            with self._cond:
                self._cond.wait(0.5)

    def ler_intervalo(self, vid, ini, fim):
        vl = self.t['vlocal'].get(vid)
        man = vl and vl.get('man')
        if not man or man.get('seg'):
            raise ErroSocial('Vídeo indisponível.')
        i = ini // PECA
        while i * PECA <= fim and i < n_pecas(man):
            d = self.obter_peca(vid, i)
            a = max(0, ini - i * PECA)
            z = min(len(d), fim - i * PECA + 1)
            yield d[a:z]
            i += 1

    def mime_video(self, vid):
        man = (self.t['vlocal'].get(vid) or {}).get('man')
        return (man or {}).get('mime', 'video/mp4'), (man or {}).get('tam', 0)

    # ── metadados / enxame ──
    def _pedir_meta(self, vid, forcar=False):
        vl = self.t['vlocal'].get(vid)
        if not vl or (not forcar and time.time() - self._meta_t.get(vid, 0) < 15):
            return
        self._meta_t[vid] = time.time()
        owner = vl['addr'][:64]
        if self.s._online(owner):
            if not vl.get('man') and not (self.cat.videos.get(vid) or {}).get('live'):
                self.s._enviar_async(owner, {'tipo': 'v_manifesto_pedir', 'vid': vid,
                                             'addr': self.s.addr()})
            self.s._enviar_async(owner, {'tipo': 'v_enxame_pedir', 'vid': vid})
            self.s._enviar_async(owner, {'tipo': 'v_social_pedir', 'vid': vid})
        else:
            self.s._link(vl['addr'], 'video:' + vid)
            for addr in (vl.get('pares') or [])[:4]:
                self._link_par(vid, addr)
            alvos = [a['chave_publica'] for a in self.s.no.listar_amigos()
                     if a['status'] and self.s._pode_dir(a['chave_publica'])]
            random.shuffle(alvos)
            for p in alvos[:6]:
                if not vl.get('man'):
                    self.s._enviar_async(p, {'tipo': 'v_manifesto_pedir', 'vid': vid,
                                             'addr': self.s.addr()})
                self.s._enviar_async(p, {'tipo': 'v_enxame_pedir', 'vid': vid})

    def _link_par(self, vid, addr):
        pub = addr[:64]
        pares = self.enx.setdefault(vid, {'pares': {}})['pares']
        pares.setdefault(pub, {'bits': bytearray(), 't': time.time(),
                               'ruins': 0, 'addr': addr})
        if self.s.no.buscar_amigo_por_chave(pub) is None:
            if sum(1 for p in pares if self.s._online(p)) < 8:
                self.s._link(addr, 'enxame:' + vid)
        elif self.s._online(pub):
            self._enviar_tem(vid, pub)

    def par_online(self, pub):
        for vid, st in list(self.dl.items()):
            vl = self.t['vlocal'].get(vid) or {}
            if vl.get('addr', '')[:64] == pub:
                self._pedir_meta(vid, forcar=True)
                if st.get('live'):
                    self.s._enviar_async(pub, {'tipo': 'v_live_entrar', 'vid': vid,
                                               'addr': self.s.addr()})
            elif pub in self.enx.get(vid, {}).get('pares', {}):
                self._enviar_tem(vid, pub)
        for cid, i in self.t['vinscr'].items():
            if i['addr'][:64] == pub:
                self._pedir_canal(cid)

    def par_offline(self, pub):
        for lo in self.live.values():
            lo['viewers'].pop(pub, None)
        for k in [k for k, f in self.voo.items() if f['pub'] == pub]:
            self.voo.pop(k, None)
            self.rx.pop(k, None)
        self.carga[pub] = 0

    def precisa_link(self, pub):
        t = time.time()
        for vid, st in self.dl.items():
            if t - st['acesso'] < 1800:
                vl = self.t['vlocal'].get(vid) or {}
                if vl.get('addr', '')[:64] == pub or \
                        pub in self.enx.get(vid, {}).get('pares', {}):
                    return True
        if any(i['addr'][:64] == pub for i in self.t['vinscr'].values()):
            return True
        c = self._canal()
        return bool(c and (pub in c['inscritos'] or any(
            pub in lo['viewers'] for lo in self.live.values())
            or pub in self._clientes_video))

    def aceitar_link(self, pub, tipo, extra):
        """Chamado quando chega pedido de amizade 'video:' ou 'enxame:'."""
        if tipo == 'video':
            c = self._canal()
            if not c or self._bloqueado(pub):
                return False
            if extra != c['cid'] and extra not in self.t['mvid']:
                return False
            if len(self._clientes_video) >= MAX_CLIENTES_VIDEO:
                return False
            self._clientes_video.add(pub)
            return self.s._aceitar_link(pub) is not None
        if tipo == 'enxame':
            if extra in self.dl or extra in self.live_v or extra in self.t['vlocal']:
                v = self.cat.videos.get(extra)
                if v and hash_bloq(v['cid'], pub) in (
                        self.cat.canais.get(v['cid']) or {}).get('bloq', []):
                    return False
                return self.s._aceitar_link(pub) is not None
        return False

    # ═══ escalonador de download ═════════════════════════════════════
    def _fonte(self, vid, idx):
        vl = self.t['vlocal'].get(vid) or {}
        owner = vl.get('addr', '')[:64]
        cand = []
        for pub, p in self.enx.get(vid, {}).get('pares', {}).items():
            if bit_get(p['bits'], idx) and p['ruins'] < 3 and self.s._online(pub) \
                    and self.carga.get(pub, 0) < 3:
                cand.append(pub)
        if cand:
            return min(cand, key=lambda p: (self.carga.get(p, 0), random.random()))
        if owner and self.s._online(owner) and self.carga.get(owner, 0) < 4:
            return owner
        return None

    def _tick(self):
        agora_ = time.time()
        for k, f in list(self.voo.items()):
            if agora_ - f['t'] > 25:
                self.voo.pop(k, None)
                self.rx.pop(k, None)
                self.carga[f['pub']] = max(0, self.carga.get(f['pub'], 1) - 1)
                p = self.enx.get(k[0], {}).get('pares', {}).get(f['pub'])
                if p:
                    p['ruins'] += 1
        for vid, st in list(self.dl.items()):
            vl = self.t['vlocal'].get(vid)
            if not vl or (agora_ - st['acesso'] > 6 * 3600) or \
                    (not st['tudo'] and not st['live'] and agora_ - st['acesso'] > 900):
                self.dl.pop(vid, None)
                continue
            n = self._n_pecas(vid)
            if n is None:
                self._pedir_meta(vid)
                continue
            have = self._bits(vid)
            if st['live']:
                cand = [i for i in range(st['pos'], n) if not bit_get(have, i)][:JANELA]
            else:
                pos = min(st['pos'], n - 1)
                cand = sorted(st['prio']) + [i for i in range(pos, min(n, pos + JANELA))
                                             if not bit_get(have, i)]
                if st['tudo']:
                    resto = itertools.chain(range(pos, n), range(0, pos))
                    cand += list(itertools.islice(
                        (i for i in resto if not bit_get(have, i)), 40))
                if all(bit_get(have, i) for i in range(n)):
                    vl['completo'] = True
                    self.dl.pop(vid, None)
                    continue
            voando = sum(1 for k in self.voo if k[0] == vid)
            for idx in cand:
                if voando >= MAX_FLIGHT:
                    break
                if bit_get(have, idx) or (vid, idx) in self.voo \
                        or self._pec_info(vid, idx) is None:
                    continue
                src = self._fonte(vid, idx)
                if not src:
                    continue
                self.voo[(vid, idx)] = {'pub': src, 't': agora_}
                self.carga[src] = self.carga.get(src, 0) + 1
                voando += 1
                self.s._enviar_async(src, {'tipo': 'v_peca_pedir', 'vid': vid,
                                           'idx': idx})
            if not voando and cand and agora_ - self._meta_t.get(vid, 0) > 15:
                self._pedir_meta(vid)
        for vid in list(self._tem_pend):
            if agora_ - self._tem_t.get(vid, 0) > 2:
                self._tem_t[vid] = agora_
                self._tem_pend.discard(vid)
                for pub in list(self.enx.get(vid, {}).get('pares', {})):
                    if self.s._online(pub):
                        self._enviar_tem(vid, pub)

    def _enviar_tem(self, vid, pub, resp=False):
        b = self._bits(vid)
        self.s._enviar_async(pub, {'tipo': 'v_tem', 'vid': vid, 'resp': resp,
                                   'bits': base64.b64encode(bytes(b)).decode()})

    def _lento(self):
        t = time.time()
        for k in [k for k, v in self.rx.items() if t - v['t'] > 60]:
            self.rx.pop(k, None)
        for vid in [v for v, lv in self.live_v.items() if t - lv['t'] > 3600]:
            self.live_v.pop(vid, None)
        for cid in list(self.t['vinscr']):
            if t - self._canal_t.get(cid, 0) > 600:
                self._pedir_canal(cid, n=20)
        for vid in list(self.dl):
            if self.dl[vid]['live'] or True:
                self._pedir_meta(vid)
        self.cat.salvar_se_sujo()

    # ═══ rede: despacho ══════════════════════════════════════════════
    def tratar(self, pub, m):
        h = {'v_cat_pedir': self._h_cat_pedir, 'v_cat_dados': self._h_cat_dados,
             'v_cat_busca': self._h_cat_busca, 'v_cat_busca_res': self._h_cat_busca_res,
             'v_canal_pedir': self._h_canal_pedir, 'v_canal': self._h_canal,
             'v_inscrever': self._h_inscrever,
             'v_manifesto_pedir': self._h_man_pedir, 'v_manifesto': self._h_man,
             'v_enxame_pedir': self._h_enx_pedir, 'v_enxame': self._h_enx,
             'v_tem': self._h_tem, 'v_peca_pedir': self._h_peca_pedir,
             'v_peca_fim': self._h_peca_fim, 'v_peca_erro': self._h_peca_erro,
             'v_social_pedir': self._h_soc_pedir, 'v_social': self._h_soc,
             'v_voto': self._h_voto, 'v_comentar': self._h_comentar,
             'v_cvoto': self._h_cvoto, 'v_capagar': self._h_capagar,
             'v_live_entrar': self._h_live_entrar, 'v_live_estado': self._h_live_estado,
             'v_live_seg': self._h_live_seg, 'v_live_fim': self._h_live_fim,
             'v_live_com': self._h_live_com}.get(m.get('tipo'))
        if h:
            h(pub, m)

    # ── catálogo (gossip assinado) ──
    def _h_cat_pedir(self, pub, m):
        if not self.s._pode_dir(pub) or not self.s._limite(pub, 'vcat', 40):
            return
        apos = m.get('apos') or [0, '']
        if str(m.get('epoca', '')) != self.cat.epoca:
            apos = [0, '']
        pag, prox, mais = self.cat.delta(apos)
        self.s._enviar_async(pub, {'tipo': 'v_cat_dados', 'resp': True,
                                   'itens': [Catalogo.fio(e) for e in pag],
                                   'prox': prox, 'mais': mais,
                                   'epoca': self.cat.epoca})

    def _h_cat_dados(self, pub, m):
        if not self.s._pode_dir(pub):
            return
        k = self.s._rumores.get('v' + pub, [0, 0])
        if time.time() - k[0] > 3600:
            k = [time.time(), 0]
        novos = 0
        for e in (m.get('itens') or [])[:25]:
            if k[1] > 3000:
                break
            k[1] += 1
            if self.cat.mesclar(e):
                novos += 1
                if e.get('k') == 'video' and e.get('cid') in self.t['vinscr']:
                    self.s._evento('ent', novo=e.get('vid'))
                if e.get('k') == 'video' and e.get('removido'):
                    self._esquecer_video(e.get('vid'))
        self.s._rumores['v' + pub] = k
        if novos:
            self.s._evento('ent')
        if m.get('resp'):
            if m.get('mais') and m.get('prox'):
                self.s._enviar_async(pub, {'tipo': 'v_cat_pedir', 'apos': m['prox'],
                                           'epoca': m.get('epoca', '')})
            else:
                self.cat.set_sync(pub, m.get('prox') or [0, ''], str(m.get('epoca', '')))

    def pedir_catalogo(self, pub):
        s = self.cat.get_sync(pub)
        self.s._enviar_async(pub, {'tipo': 'v_cat_pedir', 'apos': s.get('cursor') or [0, ''],
                                   'epoca': s.get('epoca', '')})

    def _esquecer_video(self, vid):
        vl = self.t['vlocal'].get(vid)
        if vl and not vl.get('meu'):
            self.dl.pop(vid, None)
            self._limpar_cache(vid)
            self.t['vlocal'].pop(vid, None)

    def _h_cat_busca(self, pub, m):
        if not self.s._pode_dir(pub) or not self.s._limite(pub, 'vbusca', 30):
            return
        canais, videos = self.cat.buscar(limpar(m.get('q'), 80), 10)
        self.s._enviar_async(pub, {'tipo': 'v_cat_busca_res', 'id': str(m.get('id', ''))[:40],
                                   'itens': [Catalogo.fio(e) for e in canais + videos[:20]]})

    def _h_cat_busca_res(self, pub, m):
        q = self._buscas.get(str(m.get('id', '')))
        if q is not None:
            q.put((pub, m.get('itens') or []))

    # ── canal ──
    def _h_canal_pedir(self, pub, m):
        c = self._canal()
        if not c or str(m.get('cid')) != c['cid'] or self._bloqueado(pub) \
                or not self.s._limite(pub, 'vcanal', 20):
            return
        e = self.cat.canais.get(c['cid'])
        try:
            n = max(1, min(int(m.get('n', 20)), 60))
        except (TypeError, ValueError):
            n = 20
        vids = sorted((v for v in self.cat.videos.values() if v['cid'] == c['cid']),
                      key=lambda v: -v['ts'])[:n]
        stats = {}
        for v in vids:
            mv = self.t['mvid'].get(v['vid'])
            if mv:
                stats[v['vid']] = {'vis': len(mv['vis']),
                                   'gos': sum(1 for x in mv['votos'].values() if x > 0),
                                   'nao': sum(1 for x in mv['votos'].values() if x < 0)}
        msg = {'tipo': 'v_canal', 'cid': c['cid'], 'entrada': Catalogo.fio(e) if e else None,
               'videos': [Catalogo.fio(v) for v in vids], 'stats': stats,
               'inscritos': len(c['inscritos']), 'ia': c['ia'], 'ic': c['ic']}
        for campo, mid, h in (('avatar', c['foto_mid'], 'ia'), ('capa', c['capa_mid'], 'ic')):
            if mid and str(m.get(h, '')) != c[h]:
                meta, cam = self.s.midia_meta(mid)
                if meta:
                    raw = b''.join(self.cofre.ler_arquivo(cam))
                    msg[campo] = 'data:%s;base64,%s' % (meta['mime'],
                                                         base64.b64encode(raw).decode())
        self.s._enviar_async(pub, msg)

    def _h_canal(self, pub, m):
        cid = str(m.get('cid', ''))
        e = self.cat.mesclar(m.get('entrada')) if m.get('entrada') else None
        ce = self.cat.canais.get(cid)
        if not ce or ce['addr'][:64] != pub:
            return
        for v in (m.get('videos') or [])[:60]:
            if self.cat.mesclar(v) and v.get('removido'):
                self._esquecer_video(v.get('vid'))
        for vid, st in (m.get('stats') or {}).items():
            if RE_ID.match(str(vid)) and vid in self.cat.videos \
                    and self.cat.videos[vid]['cid'] == cid:
                try:
                    self.cat.set_stats(vid, st['vis'], st['gos'], st['nao'])
                except (KeyError, TypeError, ValueError):
                    pass
        cc = self.t['vcc'].setdefault(cid, {})
        try:
            cc['inscritos'] = int(m.get('inscritos', 0))
        except (TypeError, ValueError):
            pass
        for campo, h, lim in (('avatar', 'ia', 300000), ('capa', 'ic', 700000)):
            d = m.get(campo)
            if isinstance(d, str) and len(d) < lim and d.startswith('data:image/'):
                cc[campo], cc[h] = d, str(m.get(h, ''))[:8]
        self.s.banco.sujar('vcc')
        self.s._evento('ent')

    def _h_inscrever(self, pub, m):
        c = self._canal()
        if not c or str(m.get('cid')) != c['cid'] or self._bloqueado(pub):
            return
        with self.s.L:
            if m.get('on') and pub not in c['inscritos'] and len(c['inscritos']) < 100000:
                c['inscritos'].append(pub)
            elif not m.get('on') and pub in c['inscritos']:
                c['inscritos'].remove(pub)
            self.s.banco.sujar('canal_meu')

    # ── manifesto / enxame ──
    def _h_man_pedir(self, pub, m):
        vid = str(m.get('vid', ''))
        vl = self.t['vlocal'].get(vid)
        if not vl or not vl.get('man') or not self._pode_servir(pub, vid) \
                or not self.s._limite(pub, 'vman', 60):
            return
        mv = self.t['mvid'].get(vid)
        if mv is not None:
            if pub not in mv['vis'] and len(mv['vis']) < 500000:
                mv['vis'][pub] = agora()
                self.s.banco.sujar('mvid')
            addr = str(m.get('addr', '')).upper()
            if RE_ADDR.match(addr) and addr[:64] == pub:
                q = self.enx_dono.setdefault(vid, {})
                q[pub] = (addr, time.time())
                if len(q) > 60:
                    q.pop(min(q, key=lambda k: q[k][1]))
        self.s._enviar_async(pub, {'tipo': 'v_manifesto', 'vid': vid,
                                   'man': vl['man']})

    def _h_man(self, pub, m):
        vid = str(m.get('vid', ''))
        v, vl, man = self.cat.videos.get(vid), self.t['vlocal'].get(vid), m.get('man')
        if not v or not vl or vl.get('man') or not man_valido(man):
            return
        if man.get('vid') != vid or hash_man(man) != v['mh']:
            return
        with self.s.L:
            vl['man'] = man
            self.s.banco.sujar('vlocal')
        with self._cond:
            self._cond.notify_all()
        self.s._evento('video', vid=vid)

    def _h_enx_pedir(self, pub, m):
        vid = str(m.get('vid', ''))
        if not self._pode_servir(pub, vid) or not self.s._limite(pub, 'venx', 60):
            return
        lista = []
        vl = self.t['vlocal'].get(vid) or {}
        if vl.get('bytes') and not vl.get('meu'):
            lista.append(self.s.addr())
        for p, (addr, t) in sorted(self.enx_dono.get(vid, {}).items(),
                                   key=lambda x: -x[1][1]):
            if p != pub and time.time() - t < 3600 and self.s._online(p) is not None:
                lista.append(addr)
        for p, i in self.enx.get(vid, {}).get('pares', {}).items():
            if p != pub and i.get('addr') and bit_get(i['bits'], 0):
                lista.append(i['addr'])
        self.s._enviar_async(pub, {'tipo': 'v_enxame', 'vid': vid,
                                   'pares': list(dict.fromkeys(lista))[:20]})

    def _h_enx(self, pub, m):
        vid = str(m.get('vid', ''))
        vl = self.t['vlocal'].get(vid)
        if not vl:
            return
        novos = []
        for a in (m.get('pares') or [])[:20]:
            a = str(a).upper()
            if RE_ADDR.match(a) and a[:64] not in (self.s.pub(), vl['addr'][:64]):
                self._link_par(vid, a)
                novos.append(a)
        if novos:
            vl['pares'] = list(dict.fromkeys(novos + vl.get('pares', [])))[:20]
            self.s.banco.sujar('vlocal')

    def _h_tem(self, pub, m):
        vid = str(m.get('vid', ''))
        if vid not in self.dl and vid not in self.live_v and vid not in self.t['vlocal']:
            return
        try:
            b = bytearray(base64.b64decode(m.get('bits', ''), validate=True))[:60000]
        except Exception:
            return
        pares = self.enx.setdefault(vid, {'pares': {}})['pares']
        novo = pub not in pares
        p = pares.setdefault(pub, {'bits': bytearray(), 't': time.time(), 'ruins': 0,
                                   'addr': ''})
        p['bits'], p['t'] = b, time.time()
        if not p.get('addr'):
            p['addr'] = (self.s.t['pessoas'].get(pub) or {}).get('addr', '')
        if novo and not m.get('resp'):
            self._enviar_tem(vid, pub, resp=True)

    # ── servir pedaços ──
    def _pode_servir(self, pub, vid):
        v = self.cat.videos.get(vid)
        if not v or v['removido']:
            return False
        c = self._canal()
        if c and v['cid'] == c['cid']:
            return pub not in c['bloq']
        e = self.cat.canais.get(v['cid'])
        return not (e and hash_bloq(v['cid'], pub) in e['bloq'])

    def _h_peca_pedir(self, pub, m):
        vid = str(m.get('vid', ''))
        try:
            idx = int(m.get('idx', -1))
        except (TypeError, ValueError):
            return
        if not self._pode_servir(pub, vid) or not bit_get(self._bits(vid), idx) \
                or self.tx.get(pub, 0) >= 4:
            self.s._enviar_async(pub, {'tipo': 'v_peca_erro', 'vid': vid, 'idx': idx})
            return
        self.tx[pub] = self.tx.get(pub, 0) + 1
        threading.Thread(target=self._servir, args=(pub, vid, idx), daemon=True).start()

    def _servir(self, pub, vid, idx):
        try:
            d = self._ler_se_tem(vid, idx)
            n = self.s._numero(pub)
            if d is None or n is None:
                self.s._enviar_async(pub, {'tipo': 'v_peca_erro', 'vid': vid, 'idx': idx})
                return
            v8 = bytes.fromhex(vid)
            for off in range(0, len(d), SUBPEDACO):
                self.s.no.enviar_pedaco(n, v8, idx, off, d[off:off + SUBPEDACO])
            self.s.no.enviar(n, {'tipo': 'v_peca_fim', 'vid': vid, 'idx': idx, 'tam': len(d)})
        except Exception as e:
            log.debug("servir peça: %s", e)
        finally:
            self.tx[pub] = max(0, self.tx.get(pub, 1) - 1)

    def ao_pedaco(self, pub, payload):
        vid = payload[:8].hex()
        idx, off = struct.unpack('>II', payload[8:16])
        dados = payload[16:]
        f = self.voo.get((vid, idx))
        info = self._pec_info(vid, idx)
        if not f or f['pub'] != pub or not info:
            return
        r = self.rx.setdefault((vid, idx), {'buf': bytearray(), 't': time.time()})
        if off != len(r['buf']) or off + len(dados) > info[0]:
            self.rx.pop((vid, idx), None)
            return
        r['buf'] += dados
        r['t'] = time.time()

    def _fim_voo(self, pub, vid, idx, ok):
        f = self.voo.pop((vid, idx), None)
        self.rx.pop((vid, idx), None)
        if f:
            self.carga[f['pub']] = max(0, self.carga.get(f['pub'], 1) - 1)
        p = self.enx.get(vid, {}).get('pares', {}).get(pub)
        if p and not ok:
            p['ruins'] += 1

    def _h_peca_fim(self, pub, m):
        vid = str(m.get('vid', ''))
        try:
            idx = int(m.get('idx', -1))
        except (TypeError, ValueError):
            return
        f, r, info = self.voo.get((vid, idx)), self.rx.get((vid, idx)), self._pec_info(vid, idx)
        if not f or f['pub'] != pub or not r or not info:
            return
        buf = bytes(r['buf'])
        if len(buf) != info[0] or hash_peca(buf) != info[1]:
            self._fim_voo(pub, vid, idx, False)
            return
        self._guardar_peca(vid, idx, buf)
        self._fim_voo(pub, vid, idx, True)
        st = self.dl.get(vid)
        if st:
            st['prio'].discard(idx)

    def _h_peca_erro(self, pub, m):
        try:
            self._fim_voo(pub, str(m.get('vid', '')), int(m.get('idx', -1)), False)
        except (TypeError, ValueError):
            pass

    # ═══ social: votos, comentários ══════════════════════════════════
    def _dono_de(self, vid):
        return vid in self.t['mvid']

    def _social_fio(self, vid, pub=None, completo=False):
        m = self.t['mvid'].get(vid)
        if m is None:
            return None
        coms = []
        for c in m['coms'][-100:]:
            d = {'id': c['id'], 'nome': c['nome'], 'pub8': c['pub'][:8],
                 'texto': c['texto'], 'ts': c['ts'], 'resp': c.get('resp', ''),
                 'gos': len(c['likes']), 'meu': bool(pub and pub in c['likes']),
                 'meu_com': bool(pub and c['pub'] == pub),
                 'dono': c['pub'] == self.s.pub()}
            if completo:
                d['pub'] = c['pub']
            coms.append(d)
        return {'vid': vid, 'gos': sum(1 for x in m['votos'].values() if x > 0),
                'nao': sum(1 for x in m['votos'].values() if x < 0),
                'vis': len(m['vis']), 'meu': m['votos'].get(pub, 0) if pub else 0,
                'coms': coms, 'total': len(m['coms']),
                'ids': [c['id'] for c in m['coms'][-500:]]}

    def _h_soc_pedir(self, pub, m):
        vid = str(m.get('vid', ''))
        if not self._dono_de(vid) or self._bloqueado(pub) \
                or not self.s._limite(pub, 'vsoc', 40):
            return
        f = self._social_fio(vid, pub)
        f['tipo'] = 'v_social'
        self.s._enviar_async(pub, f)

    def _h_soc(self, pub, m):
        vid = str(m.get('vid', ''))
        v = self.cat.videos.get(vid)
        if not v or v['addr'][:64] != pub:
            return
        try:
            gos, nao, vis = int(m['gos']), int(m['nao']), int(m['vis'])
        except (KeyError, TypeError, ValueError):
            return
        self.cat.set_stats(vid, vis, gos, nao)
        coms = []
        for c in (m.get('coms') or [])[:100]:
            if isinstance(c, dict) and RE_ID.match(str(c.get('id', ''))):
                coms.append({'id': c['id'], 'nome': limpar(c.get('nome'), 40),
                             'pub8': str(c.get('pub8', ''))[:8],
                             'texto': limpar_multilinha(c.get('texto'), 1000),
                             'ts': int(c.get('ts', 0) or 0),
                             'resp': str(c.get('resp', ''))[:16],
                             'gos': int(c.get('gos', 0) or 0), 'meu': bool(c.get('meu')),
                             'meu_com': bool(c.get('meu_com')), 'dono': bool(c.get('dono'))})
        with self.s.L:
            self.t['vsocial'][vid] = {'gos': gos, 'nao': nao, 'vis': vis,
                                      'meu': int(m.get('meu', 0) or 0), 'coms': coms,
                                      'total': int(m.get('total', len(coms)) or 0),
                                      'ts': agora()}
            self.s.banco.sujar('vsocial')
        self.s._evento('social', vid=vid)

    def social(self, vid):
        if self._dono_de(vid):
            f = self._social_fio(vid, self.s.pub(), completo=True)
            f['sou_dono'] = True
            return f
        self._pedir_meta_social(vid)
        d = dict(self.t['vsocial'].get(vid) or {'gos': 0, 'nao': 0, 'vis': 0,
                                                 'meu': 0, 'coms': [], 'total': 0})
        d['vid'], d['sou_dono'] = vid, False
        return d

    def _pedir_meta_social(self, vid):
        v = self.cat.videos.get(vid)
        if v and time.time() - self._meta_t.get('s' + vid, 0) > 4:
            self._meta_t['s' + vid] = time.time()
            self.s._enviar_async(v['addr'][:64], {'tipo': 'v_social_pedir', 'vid': vid})

    def votar(self, vid, val):
        val = 1 if val > 0 else -1 if val < 0 else 0
        v = self.cat.videos.get(vid)
        if not v or v['removido']:
            raise ErroSocial('Vídeo não encontrado.')
        h = self.t['vhist']
        for c in v['cats']:
            h.setdefault('cats', {})[c] = h.get('cats', {}).get(c, 0) + (2 * val if val else 0)
        self.s.banco.sujar('vhist')
        with self.s.L:
            sc = self.t['vsocial'].setdefault(vid, {'gos': 0, 'nao': 0, 'vis': 0,
                                                    'meu': 0, 'coms': [], 'total': 0})
            ant = sc.get('meu', 0)
            sc['gos'] = max(0, sc['gos'] - (ant > 0) + (val > 0))
            sc['nao'] = max(0, sc['nao'] - (ant < 0) + (val < 0))
            sc['meu'] = val
            self.s.banco.sujar('vsocial')
        if self._dono_de(vid):
            self._aplicar_voto(vid, self.s.pub(), val)
        else:
            self._garantir_dono(v)
            self.s._entregar(v['addr'][:64], {'tipo': 'v_voto', 'vid': vid, 'v': val})

    def _aplicar_voto(self, vid, pub, val):
        m = self.t['mvid'].get(vid)
        if m is None:
            return
        with self.s.L:
            if val:
                m['votos'][pub] = val
            else:
                m['votos'].pop(pub, None)
            self.s.banco.sujar('mvid')

    def _h_voto(self, pub, m):
        vid = str(m.get('vid', ''))
        if not self._dono_de(vid) or self._bloqueado(pub) or not self.s._limite(pub, 'vvoto', 60):
            return
        try:
            val = int(m.get('v', 0))
        except (TypeError, ValueError):
            return
        self._aplicar_voto(vid, pub, 1 if val > 0 else -1 if val < 0 else 0)

    def comentar(self, vid, texto, resp=''):
        texto = limpar_multilinha(texto, 1000).strip()
        if not texto:
            raise ErroSocial('Comentário vazio.')
        v = self.cat.videos.get(vid)
        if not v or v['removido']:
            raise ErroSocial('Vídeo não encontrado.')
        if self._dono_de(vid):
            self._registrar_comentario(vid, self.s.pub(), self.s._nome_completo(), texto, resp)
        else:
            self._garantir_dono(v)
            self.s._entregar(v['addr'][:64], {'tipo': 'v_comentar', 'vid': vid, 'texto': texto,
                                              'resp': str(resp or '')[:16],
                                              'nome': self.s._nome_completo()})
            self._meta_t['s' + vid] = 0
            self._pedir_meta_social(vid)

    def _registrar_comentario(self, vid, pub, nome, texto, resp=''):
        m = self.t['mvid'].get(vid)
        if m is None or len(m['coms']) >= 3000:
            return None
        c = {'id': novo_id(), 'pub': pub, 'nome': limpar(nome, 40) or 'Usuário ' + pub[:8],
             'texto': texto, 'ts': agora(),
             'resp': resp if RE_ID.match(str(resp or '')) else '', 'likes': []}
        with self.s.L:
            m['coms'].append(c)
            cm = self._canal()
            if cm and pub != self.s.pub():
                cm['nomes'][pub] = c['nome']
                if len(cm['nomes']) > 5000:
                    cm['nomes'].pop(next(iter(cm['nomes'])))
            self.s.banco.sujar('mvid')
            self.s.banco.sujar('canal_meu')
        lo = self.live.get(vid)
        if lo:
            msg = {'tipo': 'v_live_com', 'vid': vid, 'c': {
                'id': c['id'], 'nome': c['nome'], 'pub8': pub[:8], 'texto': texto,
                'ts': c['ts'], 'resp': c['resp'], 'gos': 0, 'dono': pub == self.s.pub()}}
            for p in list(lo['viewers']):
                self.s._enviar_async(p, msg)
        self.s._evento('social', vid=vid)
        return c

    def _h_comentar(self, pub, m):
        vid = str(m.get('vid', ''))
        if not self._dono_de(vid) or self._bloqueado(pub) or not self.s._limite(pub, 'vcom', 6):
            return
        t = limpar_multilinha(m.get('texto'), 1000).strip()
        if t:
            self._registrar_comentario(vid, pub, m.get('nome'), t, m.get('resp'))

    def voto_comentario(self, vid, cid_c, on):
        v = self.cat.videos.get(vid)
        if not v:
            raise ErroSocial('Vídeo não encontrado.')
        if self._dono_de(vid):
            self._aplicar_cvoto(vid, self.s.pub(), cid_c, on)
        else:
            self.s._entregar(v['addr'][:64], {'tipo': 'v_cvoto', 'vid': vid,
                                              'c': cid_c, 'on': bool(on)})
            sc = self.t['vsocial'].get(vid)
            for c in (sc or {}).get('coms', []):
                if c['id'] == cid_c and c['meu'] != bool(on):
                    c['meu'] = bool(on)
                    c['gos'] = max(0, c['gos'] + (1 if on else -1))

    def _aplicar_cvoto(self, vid, pub, cid_c, on):
        m = self.t['mvid'].get(vid)
        for c in (m or {}).get('coms', []):
            if c['id'] == cid_c:
                with self.s.L:
                    if on and pub not in c['likes']:
                        c['likes'].append(pub)
                    elif not on and pub in c['likes']:
                        c['likes'].remove(pub)
                    self.s.banco.sujar('mvid')
                return

    def _h_cvoto(self, pub, m):
        vid = str(m.get('vid', ''))
        if self._dono_de(vid) and not self._bloqueado(pub) and self.s._limite(pub, 'vcv', 60):
            self._aplicar_cvoto(vid, pub, str(m.get('c', '')), bool(m.get('on')))

    def apagar_comentario(self, vid, cid_c):
        v = self.cat.videos.get(vid)
        if not v:
            raise ErroSocial('Vídeo não encontrado.')
        if self._dono_de(vid):
            self._apagar_com(vid, self.s.pub(), cid_c, dono=True)
        else:
            self.s._entregar(v['addr'][:64], {'tipo': 'v_capagar', 'vid': vid, 'c': cid_c})
            sc = self.t['vsocial'].get(vid)
            if sc:
                sc['coms'] = [c for c in sc['coms'] if c['id'] != cid_c]

    def _apagar_com(self, vid, pub, cid_c, dono=False):
        m = self.t['mvid'].get(vid)
        if m is None:
            return
        with self.s.L:
            m['coms'] = [c for c in m['coms']
                         if not (c['id'] == cid_c and (dono or c['pub'] == pub))]
            self.s.banco.sujar('mvid')
        self.s._evento('social', vid=vid)

    def _h_capagar(self, pub, m):
        vid = str(m.get('vid', ''))
        if self._dono_de(vid):
            self._apagar_com(vid, pub, str(m.get('c', '')))

    # ═══ lives (espectador) ══════════════════════════════════════════
    def live_entrar(self, vid):
        v = self.cat.videos.get(vid)
        if not v or v['removido'] or not v['live']:
            raise ErroSocial('Esta live não está no ar.')
        if self._me_bloqueou(v['cid']):
            raise ErroSocial('Este canal bloqueou você.')
        self._vl(vid, v)
        self._hist(v)
        self.live_v.setdefault(vid, {'segs': {}, 'fim': False, 'mime': v['mime'],
                                     'owner': v['addr'][:64], 'pos': None, 't': time.time()})
        self._ativar(vid, tudo=False, live=True)
        self._garantir_dono(v)
        pub = v['addr'][:64]
        if self.s._online(pub):
            self.s._enviar_async(pub, {'tipo': 'v_live_entrar', 'vid': vid,
                                       'addr': self.s.addr()})
            self.s._enviar_async(pub, {'tipo': 'v_enxame_pedir', 'vid': vid})
        return self.live_estado(vid)

    def live_estado(self, vid):
        lv = self.live_v.get(vid)
        if not lv:
            raise ErroSocial('Entre na live primeiro.')
        lv['t'] = time.time()
        have = self._bits(vid)
        ult = max(lv['segs']) if lv['segs'] else -1
        st = self.dl.get(vid)
        if st:
            st['acesso'] = time.time()
        return {'ultimo': ult, 'pos': lv['pos'], 'fim': lv['fim'], 'mime': lv['mime'],
                'prontos': [i for i in sorted(lv['segs']) if lv['pos'] is not None
                            and i >= lv['pos'] and bit_get(have, i)][:30],
                'dono_online': self.s._online(lv['owner']),
                'espectadores': len(self.enx.get(vid, {}).get('pares', {})) + 1}

    def _seg_ok(self, s):
        try:
            return {'tam': int(s['tam']), 'h': str(s['h']), 'dur': float(s.get('dur', 4))} \
                if 0 < int(s['tam']) <= MAX_SEG_LIVE and re.match(r'^[0-9a-f]{32}$', str(s['h'])) \
                else None
        except (KeyError, TypeError, ValueError):
            return None

    def _h_live_entrar(self, pub, m):
        vid = str(m.get('vid', ''))
        lo = self.live.get(vid)
        if not lo or self._bloqueado(pub) or not self.s._limite(pub, 'vlive', 20):
            return
        lo['viewers'][pub] = time.time()
        addr = str(m.get('addr', '')).upper()
        if RE_ADDR.match(addr) and addr[:64] == pub:
            self.enx_dono.setdefault(vid, {})[pub] = (addr, time.time())
        segs = [{'i': i, **s} for i, s in enumerate(lo['segs'])][-8:]
        self.s._enviar_async(pub, {'tipo': 'v_live_estado', 'vid': vid, 'segs': segs,
                                   'total': len(lo['segs']), 'mime': lo['mime']})
        mv = self.t['mvid'].get(vid)
        if mv:
            f = self._social_fio(vid, pub)
            f['tipo'] = 'v_social'
            self.s._enviar_async(pub, f)

    def _h_live_estado(self, pub, m):
        vid = str(m.get('vid', ''))
        lv = self.live_v.get(vid)
        if not lv or lv['owner'] != pub:
            return
        for s in (m.get('segs') or [])[:10]:
            ok = self._seg_ok(s)
            if ok and isinstance(s.get('i'), int) and 0 <= s['i'] < 10 ** 6:
                lv['segs'][s['i']] = ok
        if lv['pos'] is None and lv['segs']:
            lv['pos'] = max(0, max(lv['segs']) - 2)
            self._ativar(vid, tudo=False, live=True)['pos'] = lv['pos']
        if m.get('mime'):
            lv['mime'] = str(m['mime'])[:80]

    def _h_live_seg(self, pub, m):
        vid = str(m.get('vid', ''))
        lv = self.live_v.get(vid)
        ok = self._seg_ok(m)
        if not lv or lv['owner'] != pub or not ok or not isinstance(m.get('i'), int):
            return
        lv['segs'][m['i']] = ok
        if lv['pos'] is None:
            lv['pos'] = m['i']
            self._ativar(vid, tudo=False, live=True)['pos'] = m['i']
        self._tem_pend.add(vid)

    def _h_live_fim(self, pub, m):
        lv = self.live_v.get(str(m.get('vid', '')))
        if lv and lv['owner'] == pub:
            lv['fim'] = True

    def _h_live_com(self, pub, m):
        vid = str(m.get('vid', ''))
        lv, c = self.live_v.get(vid), m.get('c')
        if not lv or lv['owner'] != pub or not isinstance(c, dict) or not RE_ID.match(str(c.get('id', ''))):
            return
        with self.s.L:
            sc = self.t['vsocial'].setdefault(vid, {'gos': 0, 'nao': 0, 'vis': 0, 'meu': 0,
                                                    'coms': [], 'total': 0})
            if not any(x['id'] == c['id'] for x in sc['coms']):
                sc['coms'].append({'id': c['id'], 'nome': limpar(c.get('nome'), 40),
                                   'pub8': str(c.get('pub8', ''))[:8],
                                   'texto': limpar_multilinha(c.get('texto'), 1000),
                                   'ts': int(c.get('ts', agora()) or agora()),
                                   'resp': '', 'gos': 0, 'meu': False,
                                   'meu_com': False, 'dono': bool(c.get('dono'))})
                del sc['coms'][:-200]
                self.s.banco.sujar('vsocial')
        self.s._evento('social', vid=vid)
