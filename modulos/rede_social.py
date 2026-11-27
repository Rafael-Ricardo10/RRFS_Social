# -*- coding: utf-8 -*-
"""RRFS Social - rede social (publicações estilo Facebook/X).

* Só amigos (contatos do mensageiro) recebem e veem publicações, fotos e
  vídeos. Quem não é amigo vê apenas nome, foto e capa do perfil e pode pedir
  amizade.
* O autor é a fonte da verdade: cada amigo mantém uma cópia local (texto e
  mídias) e curtidas/comentários passam pelo autor, que os redistribui.
* Tudo trafega pelos enlaces Tox (cifrados) e fica cifrado em disco."""
import time
import base64
import hashlib

from .util import (log, ErroSocial, RE_ID, RE_ADDR, RE_HEX64, agora, novo_id,
                   limpar, limpar_multilinha, mime_seguro, nome_arquivo,
                   tipo_por_mime, validar_mini)
from .catalogo import Catalogo

MAX_TEXTO = 3000
MAX_FOTOS = 10
MAX_POSTS_AMIGOS = 3000
MAX_COMS = 500
RETENCAO_DIAS = 3650


def _chave(autor, rid):
    return autor[:16].upper() + rid


class Posts:
    def __init__(self, s):
        self.s = s
        self.t = s.t
        self.L = s.L
        self._perfil_pend = set()
        self._lista_t = {}

    # ═══ utilidades ═══════════════════════════════════════════
    def _meta(self, mid):
        m = self.t['midia'][mid]
        return {'fid': mid, 'nome': m['nome'], 'mime': m['mime'],
                'tam': m['tam'], 'sha': m['sha']}

    def _midias_proprias(self, mids):
        saida, fotos, videos = [], 0, 0
        for mid in mids:
            m = self.t['midia'].get(str(mid))
            if not m or m.get('dono') != 'eu':
                raise ErroSocial('Arquivo não encontrado.')
            tp = tipo_por_mime(m['mime'])
            if tp == 'imagem':
                fotos += 1
            elif tp == 'video':
                videos += 1
            else:
                raise ErroSocial('Use fotos (JPEG, PNG, WebP, GIF) ou vídeo (MP4, WebM).')
            m['acl'] = {'tipo': 'contatos'}
            saida.append({**self._meta(mid), 'local': mid, 'estado': 'ok'})
        if fotos > MAX_FOTOS or videos > 1 or (videos and fotos):
            raise ErroSocial('Até %d fotos, ou 1 vídeo por publicação.' % MAX_FOTOS)
        self.s.banco.sujar('midia')
        return saida

    def _amigos_online(self):
        return [a['chave_publica'] for a in self.s.no.listar_amigos()
                if a['status'] and self.s._eh_contato(a['chave_publica'])]

    def _proprio(self, key):
        p = self.t['posts'].get(key)
        if not p or p['autor'] != self.s.pub():
            raise ErroSocial('Publicação não encontrada.')
        return p

    # ═══ criar / editar / apagar ══════════════════════════════
    def criar(self, texto, mids=(), vid=None, orig_key=None):
        texto = limpar_multilinha(texto, MAX_TEXTO).strip()
        midias = self._midias_proprias(list(mids)[:MAX_FOTOS + 1])
        video, orig = None, None
        if vid:
            v = self.s.cat.videos.get(str(vid))
            if not v or v['removido']:
                raise ErroSocial('Vídeo não encontrado.')
            video = {'vid': v['vid'], 'titulo': v['titulo']}
        if orig_key:
            o = self.t['posts'].get(orig_key)
            if not o:
                raise ErroSocial('Publicação original não encontrada.')
            orig = {'nome': self.s._nome_completo() if o['autor'] == self.s.pub()
                    else self.s.nome_de(o['autor']),
                    'texto': o['texto'][:600], 'ts': o['ts']}
            for m in o['midias'][:4]:                      # copia as fotos para ser dono
                if m['estado'] == 'ok' and tipo_por_mime(m['mime']) == 'imagem':
                    midias.append(self._copiar_midia(m))
        if not (texto or midias or video or orig):
            raise ErroSocial('Escreva algo ou escolha fotos/vídeo.')
        rid, ts = novo_id(), agora()
        k = _chave(self.s.pub(), rid)
        p = {'k': k, 'rid': rid, 'autor': self.s.pub(), 'ts': ts, 'ed': 0,
             'texto': texto, 'midias': midias, 'video': video, 'orig': orig,
             'curt': [], 'coms': [], 'sv': 0}
        with self.L:
            self.t['posts'][k] = p
            self.s.banco.sujar('posts')
        self._difundir(p)
        self.s._evento('post')
        return k

    def _copiar_midia(self, m):
        mid = novo_id()
        esc = self.s.banco.escritor_midia(mid)
        for bloco in self.s.cofre.ler_arquivo(self.s.banco.caminho_midia(m['local'])):
            esc.escrever(bloco)
        tam, sha = esc.fechar()
        self.t['midia'][mid] = {'nome': m['nome'], 'mime': m['mime'], 'tam': tam,
                                'sha': sha, 'dono': 'eu', 'acl': {'tipo': 'contatos'}}
        self.s.banco.sujar('midia')
        return {**self._meta(mid), 'local': mid, 'estado': 'ok'}

    def editar(self, key, texto, manter=None, mids_novos=()):
        p = self._proprio(key)
        texto = limpar_multilinha(texto, MAX_TEXTO).strip()
        novos = self._midias_proprias(list(mids_novos)) if mids_novos else []
        with self.L:
            atuais = p['midias']
            manter = list(range(len(atuais))) if manter is None else \
                [i for i in manter if isinstance(i, int) and 0 <= i < len(atuais)]
            ficam = [atuais[i] for i in manter] + novos
            if sum(1 for m in ficam if tipo_por_mime(m['mime']) == 'video') > 1 or \
                    len(ficam) > MAX_FOTOS:
                raise ErroSocial('Até %d fotos, ou 1 vídeo por publicação.' % MAX_FOTOS)
            if not (texto or ficam or p['video'] or p['orig']):
                raise ErroSocial('A publicação não pode ficar vazia.')
            for i, m in enumerate(atuais):
                if i not in manter:
                    self.s.banco.apagar_midia(m['local'])
            p['texto'], p['midias'] = texto, ficam
            p['ed'] = max(agora(), p['ed'] + 1)
            p['sv'] += 1
            self.s.banco.sujar('posts')
        self._difundir(p)
        self.s._evento('post')

    def apagar(self, key):
        p = self._proprio(key)
        with self.L:
            for m in p['midias']:
                self.s.banco.apagar_midia(m['local'])
            self.t['posts'].pop(key, None)
            ap = self.t['ajustes'].setdefault('posts_apagados', [])
            ap.append([p['rid'], agora()])
            del ap[:-300]
            self.s.banco.sujar('posts')
            self.s.banco.sujar('ajustes')
        for pub in self._amigos_online():
            self.s._enviar_async(pub, {'tipo': 'p_apagar', 'id': p['rid']})
        self.s._evento('post')

    def _esquecer(self, key):
        p = self.t['posts'].pop(key, None)
        if p:
            for m in p['midias']:
                if m.get('local') and p['autor'] != self.s.pub():
                    self.s.banco.apagar_midia(m['local'])
            self.s.banco.sujar('posts')

    def esquecer_autor(self, pub):
        with self.L:
            for k in [k for k, p in self.t['posts'].items() if p['autor'] == pub]:
                self._esquecer(k)
        self.s._evento('post')

    # ═══ rede: enviar ═════════════════════════════════════════
    def _fio(self, p):
        d = {'tipo': 'p_post', 'id': p['rid'], 'ts': p['ts'], 'ed': p['ed'],
             'texto': p['texto'], 'sv': p['sv'], 'orig': p['orig'],
             'midias': [{k: m[k] for k in ('fid', 'nome', 'mime', 'tam', 'sha')}
                        for m in p['midias']]}
        if p['video']:
            e = self.s.cat.videos.get(p['video']['vid'])
            d['video'] = {'vid': p['video']['vid'],
                          'entrada': Catalogo.fio(e) if e else None}
        return d

    def _difundir(self, p):
        fio = self._fio(p)
        for pub in self._amigos_online():
            self.s._enviar_async(pub, fio)
            self._push_social(p, pub)

    def _push_social(self, p, so_para=None):
        alvos = [so_para] if so_para else self._amigos_online()
        for pub in alvos:
            self.s._enviar_async(pub, {
                'tipo': 'p_social', 'id': p['rid'], 'sv': p['sv'],
                'n': len(p['curt']), 'meu': pub in p['curt'], 'nc': len(p['coms']),
                'coms': [{'id': c['id'], 'nome': c['nome'], 'pub8': c['pub'][:8],
                          'texto': c['texto'], 'ts': c['ts'],
                          'meu_com': c['pub'] == pub, 'dono': c['pub'] == p['autor']}
                         for c in p['coms'][-50:]]})

    def enviar_lista(self, pub):
        me = self.s.pub()
        corte = agora() - 90 * 86400
        itens = [[p['rid'], p['ts'], p['ed'], p['sv']] for p in
                 sorted((p for p in self.t['posts'].values() if p['autor'] == me),
                        key=lambda p: -p['ts'])[:200]]
        apag = [r for r, t in self.t['ajustes'].get('posts_apagados', []) if t > corte]
        self.s._enviar_async(pub, {'tipo': 'p_lista', 'itens': itens, 'apagados': apag})

    def ao_conectar(self, pub):
        if self.s._eh_contato(pub):
            self.enviar_lista(pub)
        if pub in self._perfil_pend:
            self._perfil_pend.discard(pub)
            self.s._enviar_async(pub, {'tipo': 'p_perfil_pedir'})

    # ═══ rede: receber ════════════════════════════════════════
    def tratar(self, pub, m):
        h = {'p_post': self._h_post, 'p_lista': self._h_lista, 'p_pedir': self._h_pedir,
             'p_apagar': self._h_apagar, 'p_curtir': self._h_curtir,
             'p_comentar': self._h_comentar, 'p_capagar': self._h_capagar,
             'p_social': self._h_social, 'p_amigos_pedir': self._h_amigos_pedir,
             'p_amigos': self._h_amigos, 'p_perfil_pedir': self._h_perfil_pedir,
             'p_perfil_pub': self._h_perfil_pub}.get(m.get('tipo'))
        if h:
            h(pub, m)

    def _midias_validas(self, lista):
        saida = []
        for a in (lista or [])[:MAX_FOTOS]:
            try:
                fid, tam, sha = str(a['fid']), int(a['tam']), str(a['sha']).lower()
            except (KeyError, TypeError, ValueError):
                continue
            mime = mime_seguro(a.get('mime'))
            if not RE_ID.match(fid) or not RE_HEX64.match(sha) or \
                    tipo_por_mime(mime) not in ('imagem', 'video') or \
                    not 0 < tam <= 500 * 1048576:
                continue
            saida.append({'fid': fid, 'nome': nome_arquivo(a.get('nome')),
                          'mime': mime, 'tam': tam, 'sha': sha})
        return saida

    def _h_post(self, pub, m):
        if not self.s._eh_contato(pub) or not self.s._limite(pub, 'ppost', 120, 60):
            return
        rid = str(m.get('id', ''))
        if not RE_ID.match(rid):
            return
        try:
            ts = min(int(m.get('ts', 0)), agora() + 60)
            ed = max(0, int(m.get('ed', 0)))
            sv = max(0, int(m.get('sv', 0)))
        except (TypeError, ValueError):
            return
        k = _chave(pub, rid)
        at = self.t['posts'].get(k)
        if at and at['ed'] >= ed and at['ts'] == ts and \
                [x['fid'] for x in at['midias']] == [x['fid'] for x in self._midias_validas(m.get('midias'))]:
            return
        metas = self._midias_validas(m.get('midias'))
        video = None
        v = m.get('video')
        if isinstance(v, dict) and RE_ID.match(str(v.get('vid', ''))):
            if v.get('entrada'):
                self.s.cat.mesclar(v['entrada'])
            e = self.s.cat.videos.get(v['vid'])
            video = {'vid': v['vid'], 'titulo': e['titulo'] if e else 'Vídeo'}
        orig = None
        o = m.get('orig')
        if isinstance(o, dict):
            orig = {'nome': limpar(o.get('nome'), 80), 'texto': limpar_multilinha(o.get('texto'), 600),
                    'ts': int(o.get('ts', 0) or 0)}
        texto = limpar_multilinha(m.get('texto'), MAX_TEXTO)
        with self.L:
            antigos = {x['fid']: x for x in (at['midias'] if at else [])}
            midias = []
            for meta in metas:
                loc = hashlib.sha256((pub + meta['fid']).encode()).hexdigest()[:16]
                old = antigos.pop(meta['fid'], None)
                midias.append({**meta, 'local': loc,
                               'estado': old['estado'] if old else (
                                   'ok' if loc in self.t['midia'] else 'pendente')})
            for old in antigos.values():                    # mídia removida na edição
                self.s.banco.apagar_midia(old['local'])
            novo = at is None
            p = {'k': k, 'rid': rid, 'autor': pub, 'ts': ts, 'ed': ed, 'texto': texto,
                 'midias': midias, 'video': video, 'orig': orig, 'sv': sv,
                 'ncurt': (at or {}).get('ncurt', 0), 'meu_curtir': (at or {}).get('meu_curtir', False),
                 'ncoms': (at or {}).get('ncoms', 0), 'coms': (at or {}).get('coms', [])}
            self.t['posts'][k] = p
            self._podar()
            self.s.banco.sujar('posts')
        for i, mm in enumerate(midias):
            if mm['estado'] == 'pendente':
                lim = 500 * 1048576
                self.s._pedir_arq(pub, mm['fid'], {'tipo': 'post', 'key': k, 'fid': mm['fid']},
                                  esperado=mm, limite=lim)
        self.s._evento('post', nova=novo, autor=pub)

    def _podar(self):
        alheios = [p for p in self.t['posts'].values() if p['autor'] != self.s.pub()]
        if len(alheios) > MAX_POSTS_AMIGOS:
            for p in sorted(alheios, key=lambda p: p['ts'])[:len(alheios) - MAX_POSTS_AMIGOS]:
                self._esquecer(p['k'])

    def _h_lista(self, pub, m):
        if not self.s._eh_contato(pub) or not self.s._limite(pub, 'plista', 20, 60):
            return
        for rid in (m.get('apagados') or [])[:300]:
            if RE_ID.match(str(rid)):
                self._esquecer(_chave(pub, str(rid)))
        pedir = []
        for it in (m.get('itens') or [])[:200]:
            try:
                rid, ts, ed, sv = str(it[0]), int(it[1]), int(it[2]), int(it[3])
            except (TypeError, ValueError, IndexError):
                continue
            at = self.t['posts'].get(_chave(pub, rid))
            if RE_ID.match(rid) and (not at or at['ed'] < ed or at.get('sv', 0) != sv):
                pedir.append(rid)
        if pedir:
            self.s._enviar_async(pub, {'tipo': 'p_pedir', 'ids': pedir[:60]})
        self.s._evento('post')

    def _h_pedir(self, pub, m):
        if not self.s._eh_contato(pub) or not self.s._limite(pub, 'ppedir', 30, 60):
            return
        for rid in (m.get('ids') or [])[:60]:
            p = self.t['posts'].get(_chave(self.s.pub(), str(rid)))
            if p and p['autor'] == self.s.pub():
                self.s._enviar_async(pub, self._fio(p))
                self._push_social(p, pub)

    def _h_apagar(self, pub, m):
        if self.s._eh_contato(pub) and RE_ID.match(str(m.get('id', ''))):
            self._esquecer(_chave(pub, str(m['id'])))
            self.s._evento('post')

    # ═══ curtir / comentar ════════════════════════════════════
    def curtir(self, key, on):
        p = self.t['posts'].get(key)
        if not p:
            raise ErroSocial('Publicação não encontrada.')
        if p['autor'] == self.s.pub():
            self._aplicar_curtir(p, self.s.pub(), on)
            return
        with self.L:
            if bool(p.get('meu_curtir')) != bool(on):
                p['meu_curtir'] = bool(on)
                p['ncurt'] = max(0, p.get('ncurt', 0) + (1 if on else -1))
                self.s.banco.sujar('posts')
        self.s._entregar(p['autor'], {'tipo': 'p_curtir', 'id': p['rid'], 'on': bool(on)})

    def _aplicar_curtir(self, p, pub, on):
        with self.L:
            if on and pub not in p['curt']:
                p['curt'].append(pub)
            elif not on and pub in p['curt']:
                p['curt'].remove(pub)
            else:
                return
            p['sv'] += 1
            self.s.banco.sujar('posts')
        self._push_social(p)
        self.s._evento('post')

    def _h_curtir(self, pub, m):
        p = self.t['posts'].get(_chave(self.s.pub(), str(m.get('id', ''))))
        if p and self.s._eh_contato(pub) and self.s._limite(pub, 'pcurt', 120, 60):
            self._aplicar_curtir(p, pub, bool(m.get('on')))

    def comentar(self, key, texto):
        texto = limpar_multilinha(texto, 1000).strip()
        if not texto:
            raise ErroSocial('Comentário vazio.')
        p = self.t['posts'].get(key)
        if not p:
            raise ErroSocial('Publicação não encontrada.')
        if p['autor'] == self.s.pub():
            self._add_com(p, self.s.pub(), self.s._nome_completo(), texto)
        else:
            self.s._entregar(p['autor'], {'tipo': 'p_comentar', 'id': p['rid'],
                                          'texto': texto, 'nome': self.s._nome_completo()})

    def _add_com(self, p, pub, nome, texto):
        with self.L:
            if len(p['coms']) >= MAX_COMS:
                return
            p['coms'].append({'id': novo_id(), 'pub': pub, 'ts': agora(), 'texto': texto,
                              'nome': limpar(nome, 80) or self.s.nome_de(pub)})
            p['sv'] += 1
            self.s.banco.sujar('posts')
        self._push_social(p)
        self.s._evento('post')

    def _h_comentar(self, pub, m):
        p = self.t['posts'].get(_chave(self.s.pub(), str(m.get('id', ''))))
        t = limpar_multilinha(m.get('texto'), 1000).strip()
        if p and t and self.s._eh_contato(pub) and self.s._limite(pub, 'pcom', 12, 60):
            self._add_com(p, pub, self.s.nome_de(pub), t)

    def apagar_comentario(self, key, cid):
        p = self.t['posts'].get(key)
        if not p:
            raise ErroSocial('Publicação não encontrada.')
        if p['autor'] == self.s.pub():
            self._remover_com(p, cid, None)
        else:
            self.s._entregar(p['autor'], {'tipo': 'p_capagar', 'id': p['rid'], 'c': cid})
            with self.L:
                p['coms'] = [c for c in p['coms'] if c['id'] != cid]
                p['ncoms'] = len(p['coms'])
                self.s.banco.sujar('posts')

    def _remover_com(self, p, cid, pub):
        with self.L:
            antes = len(p['coms'])
            p['coms'] = [c for c in p['coms'] if not (c['id'] == cid and (pub is None or c['pub'] == pub))]
            if len(p['coms']) == antes:
                return
            p['sv'] += 1
            self.s.banco.sujar('posts')
        self._push_social(p)
        self.s._evento('post')

    def _h_capagar(self, pub, m):
        p = self.t['posts'].get(_chave(self.s.pub(), str(m.get('id', ''))))
        if p and self.s._eh_contato(pub):
            self._remover_com(p, str(m.get('c', '')), pub)

    def _h_social(self, pub, m):
        p = self.t['posts'].get(_chave(pub, str(m.get('id', ''))))
        if not p or p['autor'] != pub or not self.s._eh_contato(pub):
            return
        coms = []
        for c in (m.get('coms') or [])[:50]:
            if isinstance(c, dict) and RE_ID.match(str(c.get('id', ''))):
                coms.append({'id': c['id'], 'nome': limpar(c.get('nome'), 80),
                             'pub8': str(c.get('pub8', ''))[:8],
                             'texto': limpar_multilinha(c.get('texto'), 1000),
                             'ts': int(c.get('ts', 0) or 0), 'meu_com': bool(c.get('meu_com')),
                             'dono': bool(c.get('dono'))})
        with self.L:
            try:
                p['ncurt'], p['ncoms'] = int(m.get('n', 0)), int(m.get('nc', len(coms)))
                p['sv'] = int(m.get('sv', p.get('sv', 0)))
            except (TypeError, ValueError):
                return
            p['meu_curtir'], p['coms'] = bool(m.get('meu')), coms
            self.s.banco.sujar('posts')
        self.s._evento('post')

    # ═══ visualização ═════════════════════════════════════════
    def _foto_de(self, pub):
        if pub == self.s.pub():
            return self.t['perfil']['foto_mini']
        return self.s._mini_de(pub)

    def ui(self, p):
        me = self.s.pub()
        meu = p['autor'] == me
        video = None
        if p.get('video'):
            e = self.s.cat.videos.get(p['video']['vid'])
            video = self.s.ent._card(e) if e and not e['removido'] else \
                {'vid': p['video']['vid'], 'titulo': p['video']['titulo'], 'indisponivel': True}
        if meu:
            ncurt, mc, coms = len(p['curt']), me in p['curt'], [
                {'id': c['id'], 'nome': c['nome'], 'pub8': c['pub'][:8], 'texto': c['texto'],
                 'ts': c['ts'], 'meu_com': c['pub'] == me, 'dono': c['pub'] == me}
                for c in p['coms'][-50:]]
            ncoms = len(p['coms'])
        else:
            ncurt, mc, coms, ncoms = p.get('ncurt', 0), p.get('meu_curtir', False), \
                p.get('coms', []), p.get('ncoms', 0)
        return {'key': p['k'], 'autor': p['autor'], 'meu': meu,
                'nome': self.s._nome_completo() if meu else self.s.nome_de(p['autor']),
                'foto_mini': self._foto_de(p['autor']), 'ts': p['ts'], 'ed': p['ed'],
                'texto': p['texto'], 'orig': p.get('orig'), 'video': video,
                'midias': [{'i': i, 'nome': m['nome'], 'mime': m['mime'],
                            'tipo': tipo_por_mime(m['mime']), 'local': m['local'],
                            'estado': m['estado'], 'tam': m['tam']}
                           for i, m in enumerate(p['midias'])],
                'ncurt': ncurt, 'meu_curtir': mc, 'ncoms': ncoms, 'coms': coms}

    def _visiveis(self):
        me = self.s.pub()
        return [p for p in self.t['posts'].values()
                if p['autor'] == me or self.s._eh_contato(p['autor'])]

    def feed(self, antes=None, limite=15):
        lst = sorted(self._visiveis(), key=lambda p: -p['ts'])
        if antes:
            lst = [p for p in lst if p['ts'] < int(antes)]
        pag = lst[:max(1, min(int(limite), 40))]
        return {'posts': [self.ui(p) for p in pag],
                'mais': len(lst) > len(pag)}

    def do_autor(self, pub, antes=None, limite=15):
        pub = pub.upper()
        if pub != self.s.pub() and not self.s._eh_contato(pub):
            raise ErroSocial('Só amigos veem as publicações.')
        lst = sorted((p for p in self.t['posts'].values() if p['autor'] == pub),
                     key=lambda p: -p['ts'])
        if antes:
            lst = [p for p in lst if p['ts'] < int(antes)]
        pag = lst[:max(1, min(int(limite), 40))]
        return {'posts': [self.ui(p) for p in pag], 'mais': len(lst) > len(pag)}

    def fotos(self, pub):
        pub = pub.upper()
        if pub != self.s.pub() and not self.s._eh_contato(pub):
            raise ErroSocial('Só amigos veem as fotos.')
        saida = []
        for p in sorted((p for p in self.t['posts'].values() if p['autor'] == pub),
                        key=lambda p: -p['ts']):
            for i, m in enumerate(p['midias']):
                if tipo_por_mime(m['mime']) in ('imagem', 'video') and m['estado'] == 'ok':
                    saida.append({'key': p['k'], 'i': i, 'local': m['local'],
                                  'tipo': tipo_por_mime(m['mime']), 'ts': p['ts']})
        return saida[:200]

    def n_posts(self, pub):
        return sum(1 for p in self.t['posts'].values() if p['autor'] == pub)

    # ═══ amigos de uma pessoa ═════════════════════════════════
    def amigos_de(self, pub):
        pub = pub.upper()
        if pub == self.s.pub():
            return [{'pub': c['pub'], 'nome': c['nome'], 'sobrenome': c['sobrenome'],
                     'foto_mini': c['foto_mini'], 'addr': c['addr'],
                     'online': c['online']} for c in self.s.listar_contatos()
                    if c['estado'] == 'ativo']
        if not self.s._eh_contato(pub):
            raise ErroSocial('Só amigos veem a lista de amigos.')
        self.s._enviar_async(pub, {'tipo': 'p_amigos_pedir'})
        return (self.t['pessoas'].get(pub) or {}).get('amigos', [])

    def _h_amigos_pedir(self, pub, m):
        if not self.s._eh_contato(pub) or not self.s._limite(pub, 'pamig', 10, 60):
            return
        if not self.t['ajustes'].get('mostrar_amigos', True):
            self.s._enviar_async(pub, {'tipo': 'p_amigos', 'lista': [], 'oculta': True})
            return
        lista = [{'addr': c['addr'], 'nome': c['nome'], 'sobrenome': c['sobrenome'],
                  'foto_mini': c['foto_mini']} for c in self.s.listar_contatos()
                 if c['estado'] == 'ativo' and c['addr']][:300]
        self.s._enviar_async(pub, {'tipo': 'p_amigos', 'lista': lista})

    def _h_amigos(self, pub, m):
        if not self.s._eh_contato(pub):
            return
        lista = []
        for a in (m.get('lista') or [])[:300]:
            addr = str(a.get('addr', '')).upper() if isinstance(a, dict) else ''
            if RE_ADDR.match(addr):
                lista.append({'pub': addr[:64], 'addr': addr,
                              'nome': limpar(a.get('nome'), 40),
                              'sobrenome': limpar(a.get('sobrenome'), 60),
                              'foto_mini': validar_mini(a.get('foto_mini'))})
        with self.L:
            self.t['pessoas'].setdefault(pub, {})['amigos'] = lista
            self.s.banco.sujar('pessoas')
        self.s._evento('perfil', pub=pub)

    # ═══ perfil visto por quem NÃO é amigo (só nome, foto e capa) ═══
    def pedir_perfil_publico(self, addr):
        addr = str(addr).upper()
        pub = addr[:64]
        self._lista_t[pub] = time.time()
        if self.s._online(pub):
            self.s._enviar_async(pub, {'tipo': 'p_perfil_pedir'})
        else:
            self._perfil_pend.add(pub)
            self.s._link(addr, 'perfil')

    def perfil_publico(self, addr):
        addr = str(addr).upper()
        pub = addr[:64]
        c = self.t['pubprof'].get(pub) or {}
        e = self.s.rede.get(addr) or {}
        if time.time() - self._lista_t.get(pub, 0) > 30 and (not c or agora() - c.get('ts', 0) > 600):
            self.pedir_perfil_publico(addr)
        ct = self.t['contatos'].get(pub)
        return {'tipo': 'publico', 'pub': pub, 'addr': addr,
                'nome': c.get('nome') or e.get('nome', ''),
                'sobrenome': c.get('sobrenome') or e.get('sobrenome', ''),
                'foto': c.get('foto') or e.get('foto_mini', ''), 'capa': c.get('capa', ''),
                'relacao': ct['estado'] if ct else 'nenhuma'}

    def _h_perfil_pedir(self, pub, m):
        if not self.s._limite(pub, 'pperfil', 10, 60) or \
                not self.t['perfil'].get('visivel', True) or \
                not self.t['ajustes'].get('perfil_publico', True):
            return
        p = self.t['perfil']
        d = {'tipo': 'p_perfil_pub', 'nome': p['nome'], 'sobrenome': p['sobrenome']}
        for campo, mid, chave in (('foto', p['foto_mid'], 'foto'), ('capa', p['capa_mid'], 'capa')):
            meta, cam = self.s.midia_meta(mid) if mid else (None, None)
            if meta:
                raw = b''.join(self.s.cofre.ler_arquivo(cam))
                d[chave] = 'data:%s;base64,%s' % (meta['mime'], base64.b64encode(raw).decode())
        self.s._enviar_async(pub, d)

    def _h_perfil_pub(self, pub, m):
        nome = limpar(m.get('nome'), 40)
        if not nome:
            return
        c = {'nome': nome, 'sobrenome': limpar(m.get('sobrenome'), 60), 'ts': agora()}
        for chave, lim in (('foto', 400000), ('capa', 900000)):
            d = m.get(chave)
            if isinstance(d, str) and len(d) < lim and d.startswith(
                    ('data:image/jpeg;base64,', 'data:image/png;base64,', 'data:image/webp;base64,')):
                c[chave] = d
        with self.L:
            self.t['pubprof'][pub] = c
            if len(self.t['pubprof']) > 200:
                velho = min(self.t['pubprof'], key=lambda k: self.t['pubprof'][k].get('ts', 0))
                self.t['pubprof'].pop(velho, None)
            self.s.banco.sujar('pubprof')
        self.s._evento('perfil', pub=pub)
