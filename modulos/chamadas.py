# -*- coding: utf-8 -*-
"""RRFS Social - chamadas de voz e vídeo (conversa e grupo).

O áudio/vídeo trafega direto entre os navegadores (WebRTC, malha: cada par de
participantes tem uma conexão). Este módulo só faz a SINALIZAÇÃO pelo Tox:
convite, entrada, saída, recusa e troca de ofertas/candidatos (SDP/ICE).
Só contatos (conversa) e membros (grupo) conseguem ligar ou sinalizar."""
import json
import time
import threading

from .util import log, ErroSocial, RE_ID, agora, novo_id

MAX_PART = 8
TOCA_SEG = 45


class Chamadas:
    def __init__(self, s):
        self.s = s
        self.cham = {}
        self.L = threading.RLock()

    # ── util ────────────────────────────────────────────────
    def _cid_de(self, pub, m):
        gid = m.get('grupo')
        if gid:
            g = self.s.t['grupos'].get(str(gid))
            if g and g['estado'] == 'ativo' and pub in g['membros']:
                return 'g:' + g['gid']
            return None
        return 'p:' + pub if self.s._eh_contato(pub) else None

    def _titulo(self, cid):
        if cid.startswith('g:'):
            g = self.s.t['grupos'].get(cid[2:])
            return g['nome'] if g else 'Grupo'
        return self.s.nome_de(cid[2:])

    def _ev(self, sub, **kw):
        self.s._evento('chamada', sub=sub, **kw)

    def _sis(self, cid, texto):
        try:
            self.s.banco.add_msg(cid, {'id': novo_id(), 'de': '', 'ts': agora(),
                                       'tipo': 'sistema', 'texto': texto},
                                 previa=texto)
            self.s._evento('msg', cid=cid)
        except Exception:
            log.exception("sistema chamada")

    def _nomes(self, pubs):
        return {p: (self.s._nome_completo() if p == self.s.pub()
                    else self.s.nome_de(p)) for p in pubs}

    def _envio(self, c, msg, excluir=None):
        """Envia a todos os destinos da conversa (online)."""
        dest, g, _ = self.s._destinos(c['cid'])
        if g:
            msg = dict(msg, grupo=g['gid'])
        for p in dest:
            if p != excluir:
                self.s._enviar_async(p, msg)

    def _ocupado(self):
        return any(c['eu'] for c in self.cham.values())

    # ── ações locais ────────────────────────────────────────
    def iniciar(self, cid, video):
        with self.L:
            if self._ocupado():
                raise ErroSocial('Você já está em uma chamada.')
            dest, g, _ = self.s._destinos(cid)
            call = novo_id()
            c = self.cham[call] = {'cid': cid, 'video': bool(video),
                                   'de': self.s.pub(), 'part': {self.s.pub()},
                                   'ts': agora(), 'eu': True, 't0': None,
                                   'toca': False}
        msg = {'tipo': 'c_convite', 'call': call, 'video': bool(video)}
        if g:
            msg['grupo'] = g['gid']
        for p in dest:
            self.s._enviar_async(p, msg)
        self._sis(cid, 'Você iniciou uma chamada de %s'
                  % ('vídeo' if video else 'voz'))
        threading.Timer(TOCA_SEG, self._sem_resposta, (call,)).start()
        return {'call': call, 'cid': cid, 'video': bool(video),
                'titulo': self._titulo(cid)}

    def _sem_resposta(self, call):
        c = self.cham.get(call)
        if c and c['eu'] and len(c['part']) <= 1 and c['de'] == self.s.pub():
            self._ev('sem_resposta', call=call)

    def entrar(self, call, video):
        with self.L:
            c = self.cham.get(call)
            if not c or c['eu']:
                raise ErroSocial('Chamada não encontrada ou já encerrada.')
            if self._ocupado():
                raise ErroSocial('Você já está em outra chamada.')
            if len(c['part']) >= MAX_PART:
                raise ErroSocial('A chamada está cheia (máx. %d pessoas).' % MAX_PART)
            c['eu'], c['toca'] = True, False
            c['part'].add(self.s.pub())
            part = [p for p in c['part'] if p != self.s.pub()]
        self._envio(c, {'tipo': 'c_entrar', 'call': call, 'video': bool(video)})
        return {'call': call, 'cid': c['cid'], 'video': c['video'],
                'titulo': self._titulo(c['cid']), 'part': self._nomes(part)}

    def recusar(self, call):
        c = self.cham.get(call)
        if not c or c['eu']:
            return
        c['toca'] = False
        self.s._enviar_async(c['de'], {'tipo': 'c_recusar', 'call': call})
        if c['cid'].startswith('p:'):
            self.cham.pop(call, None)

    def sair(self, call):
        with self.L:
            c = self.cham.get(call)
            if not c or not c['eu']:
                return
            c['eu'] = False
            c['part'].discard(self.s.pub())
            t0 = c['t0']
        self._envio(c, {'tipo': 'c_sair', 'call': call})
        if t0:
            d = agora() - t0
            self._sis(c['cid'], 'Chamada encerrada · %d:%02d' % (d // 60, d % 60))
        if not c['part'] or c['cid'].startswith('p:'):
            self.cham.pop(call, None)

    def sinal(self, call, para, dado):
        c = self.cham.get(call)
        para = str(para).upper()
        if not c or not c['eu'] or para not in c['part'] or para == self.s.pub():
            raise ErroSocial('Participante indisponível.')
        if not isinstance(dado, dict) or len(json.dumps(dado)) > 40000:
            raise ErroSocial('Sinal inválido.')
        n = self.s._numero(para)
        if n is None or not self.s.no.status_amigo(n):
            raise ErroSocial('Participante offline.')
        self.s._enviar_async(para, {'tipo': 'c_sinal', 'call': call, 'dado': dado,
                                    **({'grupo': c['cid'][2:]} if c['cid'].startswith('g:') else {})})

    def ativas(self):
        saida = []
        for call, c in self.cham.items():
            if not c['part'] or agora() - c['ts'] > 6 * 3600:
                continue
            saida.append({'call': call, 'cid': c['cid'], 'video': c['video'],
                          'eu': c['eu'], 'toca': c['toca'], 'n': len(c['part']),
                          'titulo': self._titulo(c['cid']),
                          'nomes': list(self._nomes(c['part']).values())})
        return saida

    def ice(self):
        urls = []
        for a in self.s.no.listar_amigos():
            d = self.s.rede.hints.get(a['chave_publica'])
            if a['status'] and d and d.get('stun_porta'):
                ips = (d['ips_globais'][:1] or d['ips'][:1])
                for ip in ips:
                    host = '[%s]' % ip if ':' in ip else ip
                    urls.append('stun:%s:%d' % (host, d['stun_porta']))
        urls += [u for u in self.s.t['ajustes'].get('stun_extra', [])
                 if isinstance(u, str) and u.startswith(('stun:', 'turn:'))]
        return [{'urls': u} for u in list(dict.fromkeys(urls))[:6]]

    def limpar(self):
        t = agora()
        with self.L:
            for call in [k for k, c in self.cham.items()
                         if t - c['ts'] > 6 * 3600 or (not c['eu'] and not c['part'])]:
                self.cham.pop(call, None)

    def par_offline(self, pub):
        for call, c in list(self.cham.items()):
            if pub in c['part'] and pub != self.s.pub():
                c['part'].discard(pub)
                self._ev('saiu', call=call, pub=pub, nome=self.s.nome_de(pub),
                         n=len(c['part']))

    # ── mensagens recebidas ─────────────────────────────────
    def tratar(self, pub, m):
        if not self.s._limite(pub, 'cham', 600, 60):
            return
        call = str(m.get('call', ''))
        if not RE_ID.match(call):
            return
        cid = self._cid_de(pub, m)
        if not cid:
            return
        c = self.cham.get(call)
        if c and c['cid'] != cid:
            return
        t = m.get('tipo')
        if t == 'c_convite':
            self._h_convite(pub, call, cid, m, c)
        elif t == 'c_entrar':
            self._h_entrar(pub, call, cid, m, c)
        elif c is None:
            return
        elif t == 'c_aqui':
            self._h_aqui(pub, call, c, m)
        elif t == 'c_sinal':
            if c['eu'] and pub in c['part'] and isinstance(m.get('dado'), dict) \
                    and len(json.dumps(m['dado'])) <= 40000:
                self._ev('sinal', call=call, de=pub, dado=m['dado'])
        elif t == 'c_sair':
            self._h_sair(pub, call, c)
        elif t == 'c_recusar':
            if c['eu']:
                self._ev('recusou', call=call, nome=self.s.nome_de(pub))
        elif t == 'c_ocupado':
            if c['eu']:
                self._ev('ocupado', call=call, nome=self.s.nome_de(pub))
        elif t == 'c_cheia':
            if c['eu']:
                self._ev('cheia', call=call)

    def _h_convite(self, pub, call, cid, m, c):
        if c is not None or not self.s._limite(pub, 'cconv', 6, 60):
            return
        video = bool(m.get('video'))
        mudo = cid in self.s.t['ajustes'].get('silenciados', [])
        with self.L:
            ocupado = self._ocupado()
            self.cham[call] = {'cid': cid, 'video': video, 'de': pub,
                               'part': {pub}, 'ts': agora(), 'eu': False,
                               't0': None, 'toca': not ocupado or cid.startswith('g:')}
        nome = self.s.nome_de(pub)
        tipo = 'vídeo' if video else 'voz'
        if ocupado and cid.startswith('p:'):
            self.s._enviar_async(pub, {'tipo': 'c_ocupado', 'call': call})
            self._sis(cid, 'Chamada de %s perdida (você estava em outra chamada)' % tipo)
            self.cham.pop(call, None)
            return
        self._ev('convite', call=call, cid=cid, de=pub, nome=nome, video=video,
                 titulo=self._titulo(cid), grupo=cid.startswith('g:'), mudo=mudo)
        threading.Timer(TOCA_SEG, self._perdida, (call, tipo, nome)).start()

    def _perdida(self, call, tipo, nome):
        c = self.cham.get(call)
        if c and c['toca'] and not c['eu']:
            c['toca'] = False
            self._sis(c['cid'], 'Chamada de %s perdida de %s' % (tipo, nome))
            self._ev('perdida', call=call)
            if c['cid'].startswith('p:'):
                self.cham.pop(call, None)

    def _h_entrar(self, pub, call, cid, m, c):
        with self.L:
            if c is None:
                if not cid.startswith('g:'):
                    return
                c = self.cham[call] = {'cid': cid, 'video': bool(m.get('video')),
                                       'de': pub, 'part': set(), 'ts': agora(),
                                       'eu': False, 't0': None, 'toca': False}
            if pub not in c['part'] and len(c['part']) >= MAX_PART:
                cheia = True
            else:
                cheia = False
                c['part'].add(pub)
        if cheia:
            self.s._enviar_async(pub, {'tipo': 'c_cheia', 'call': call})
            return
        if c['eu']:
            if not c['t0']:
                c['t0'] = agora()
            self.s._enviar_async(pub, {'tipo': 'c_aqui', 'call': call,
                                       'video': c['video'],
                                       **({'grupo': cid[2:]} if cid.startswith('g:') else {})})
            self._ev('entrou', call=call, pub=pub, nome=self.s.nome_de(pub),
                     video=bool(m.get('video')), n=len(c['part']))
        else:
            c['toca'] = False if c['de'] != pub else c['toca']
            self._ev('part', call=call, cid=cid, n=len(c['part']))

    def _h_aqui(self, pub, call, c, m):
        if not c['eu']:
            return
        with self.L:
            c['part'].add(pub)
            if not c['t0']:
                c['t0'] = agora()
        self._ev('aqui', call=call, pub=pub, nome=self.s.nome_de(pub),
                 video=bool(m.get('video')), n=len(c['part']))

    def _h_sair(self, pub, call, c):
        with self.L:
            c['part'].discard(pub)
            vazio = not c['part']
        if not c['eu'] and c['toca'] and vazio:
            c['toca'] = False
            self._sis(c['cid'], 'Chamada de %s perdida de %s'
                      % ('vídeo' if c['video'] else 'voz', self.s.nome_de(pub)))
        self._ev('saiu', call=call, pub=pub, nome=self.s.nome_de(pub),
                 n=len(c['part']))
        if vazio and not c['eu']:
            self.cham.pop(call, None)
            self._ev('fim', call=call, cid=c['cid'])
