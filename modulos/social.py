# -*- coding: utf-8 -*-
"""RRFS Social - núcleo: contatos, grupos, mensagens, arquivos, status, busca.

Modelo de segurança: cada par de usuários conversa por um enlace Tox
(Curve25519 + XSalsa20-Poly1305, autenticado pela chave pública). Não há
servidor: mensagens de grupo são enviadas individualmente a cada membro, e o
que não pôde ser entregue espera numa fila (outbox) cifrada em disco."""
import os
import copy
import time
import struct
import hashlib
import secrets
import threading
from collections import deque

from .util import (log, PROTO, CHUNK_BIN, RE_ADDR, RE_HEX64, RE_ID, agora,
                   novo_id, limpar, limpar_multilinha, mime_seguro,
                   tipo_por_mime, nome_arquivo, decodificar_imagem,
                   validar_mini, validar_dica, ips_lan_locais,
                   ips_globais_locais, carregar_nos, mesclar_nos,
                   atualizar_nos_online, ErroSocial)
from .banco import Banco
from .catalogo import Catalogo
from .entretenimento import Ent
from .chamadas import Chamadas
from .rede_social import Posts
from .tunel import TunelServidor
from .stun import StunServer
from .rede import DIR_PAGINA
from .tox_no import NoTox

MAX_ARQ = 2 * 1024 ** 3
MAX_MEMBROS = 100
MAX_NOS = 30
MAX_NOS_SAIDA = 12
TTL_OUTBOX = 30 * 86400
STATUS_TTL = 86400
TIPOS_MSG = ('texto', 'imagem', 'video', 'audio', 'arquivo', 'video_ref')

AJ_PADRAO = {'relay_tcp_ativo': True, 'relay_tcp_porta': 33620,
             'aceitar_nos': True, 'auto_baixar_mb': 100, 'cache_pct': 5, 'stun_ativo': True, 'stun_porta': 33478,
             'stun_extra': [], 'silenciados': [], 'invisivel': False,
             'mostrar_amigos': True, 'perfil_publico': True, 'posts_apagados': [],
             'dispositivos': {}, 'vinculos': {}, 'nos': [],
             'links_ts': {}, 'convites_env': {}, 'bloqueados': []}
PERFIL_PADRAO = {'nome': '', 'sobrenome': '', 'bio': '', 'foto_mid': '',
                 'capa_mid': '', 'foto_mini': '', 'foto_ts': 0, 'capa_ts': 0,
                 'visivel': True, 'ts': 0}


class Social:
    def __init__(self, raiz, login, cofre, rede, criar_no=None, catalogo=None):
        self.raiz, self.login, self.cofre, self.rede = raiz, login, cofre, rede
        self.pasta = os.path.join(raiz, 'contas', login)
        self.cat = catalogo or Catalogo(raiz)
        self.banco = Banco(self.pasta, cofre)
        self.t = self.banco.t
        self.criar_no = criar_no
        self.no = None
        self.L = threading.RLock()
        for k, v in AJ_PADRAO.items():
            self.t['ajustes'].setdefault(k, copy.deepcopy(v))
        for k, v in PERFIL_PADRAO.items():
            self.t['perfil'].setdefault(k, v)
        self._rx = {}            # (pub, fid) -> download em curso
        self._rx_local = {}      # id local -> (pub, fid)
        self._tx = {}            # pub -> uploads simultâneos
        self._lim = {}
        self._rumores = {}
        self._buscas = {}
        self._visto = {}
        self._flush_locks = {}
        self._flush_again = set()
        self._eventos = deque(maxlen=500)
        self._ev_n = 0
        self._ev_cond = threading.Condition()
        self._ult_boot = 0
        self.rodando = False
        self.arq_nos = os.path.join(raiz, 'tox', 'nos_bootstrap.json')
        self.ent = Ent(self)
        self.cham = Chamadas(self)
        self.posts = Posts(self)
        self.tunel = TunelServidor(self)
        self.stun = None

    def _log(self, m):
        log.info(m)

    # ═══ ciclo de vida ═══════════════════════════════════════════════
    def iniciar(self):
        aj = self.t['ajustes']
        tcp = int(aj['relay_tcp_porta']) if aj['relay_tcp_ativo'] else 0
        if self.criar_no:
            self.no = self.criar_no(self)
        else:
            arq = os.path.join(self.pasta, 'identidade.dat')
            self.no = NoTox(lambda: self.cofre.ler_bytes(arq),
                            lambda b: self.cofre.gravar_bytes(arq, b),
                            self._log, 33800, 33899, tcp)
        self.no.cb_msg = self._ao_mensagem
        self.no.cb_bin = self._ao_bin
        self.no.cb_pedaco = lambda n, p: self.ent.ao_pedaco(self._pub_de(n), p)
        self.no.cb_tunel = lambda n, p: self.tunel.ao_bin(self._pub_de(n), p)
        self.no.cb_amigo = self._ao_amigo
        self.no.cb_pedido = self._ao_pedido
        self.rodando = True
        self.no.iniciar_loop()
        self._publicar_entrada()
        self.ent.iniciar()
        if aj['stun_ativo']:
            self.stun = StunServer(aj['stun_porta'])
            if not self.stun.iniciar():
                self.stun = None
        for alvo, nome in ((self._bootstrap_inicial, 'Boot'),
                           (self._loop_manter, 'Manter'),
                           (self._loop_rota, 'Rota'),
                           (self._loop_nos_online, 'NosOnline')):
            threading.Thread(target=alvo, name=nome, daemon=True).start()
        self._log(f"Endereço do usuário {self.login}: {self.addr()}")

    def parar(self):
        self.rodando = False
        self.rede.salvar_se_sujo()
        self.cat.salvar_se_sujo()
        for vid in list(self.ent.live):
            try:
                self.ent.live_encerrar(vid)
            except Exception:
                pass
        if self.stun:
            self.stun.parar()
        if self.no:
            self.no.parar()
        self.banco.fechar()

    def _bootstrap_inicial(self):
        try:
            for d in self.rede.hints_recentes(80):
                self.no.aplicar_dica(d)
            nos = carregar_nos(self.arq_nos)
            if not nos:
                atualizar_nos_online(self.arq_nos)
                nos = carregar_nos(self.arq_nos)
            if nos:
                self.no.bootstrap_simples(nos)
                self.no.bootstrap_otimizado(nos)
            self._ult_boot = agora()
        except Exception:
            log.exception("bootstrap inicial")

    def _loop_nos_online(self):
        while self.rodando:
            for _ in range(6 * 3600):
                if not self.rodando:
                    return
                time.sleep(1)
            atualizar_nos_online(self.arq_nos)

    def addr(self):
        return self.no.endereco_hex()

    def pub(self):
        return self.no.pubkey_hex()

    # ═══ eventos (a interface consulta por /api/eventos) ═════════════
    def _evento(self, tipo, **kw):
        with self._ev_cond:
            self._ev_n += 1
            self._eventos.append(dict(kw, n=self._ev_n, tipo=tipo))
            self._ev_cond.notify_all()

    def esperar_eventos(self, desde, timeout=20):
        if desde < 0:                      # só quer saber o contador atual
            return [], self._ev_n
        with self._ev_cond:
            if self._ev_n <= desde:
                self._ev_cond.wait(timeout)
            return [e for e in self._eventos if e['n'] > desde], self._ev_n

    # ═══ envio com fila persistente ══════════════════════════════════
    def _pub_de(self, numero):
        return self.no._amigos.get(numero, {}).get('chave_publica', '')

    def _numero(self, pub):
        return self.no.buscar_amigo_por_chave(pub)

    def _online(self, pub):
        n = self._numero(pub)
        return n is not None and self.no.status_amigo(n) != 0

    def _enviar_async(self, pub, msg):
        def run():
            try:
                n = self._numero(pub)
                if n is not None:
                    self.no.enviar(n, msg)
            except Exception as e:
                log.debug("envio async: %s", e)
        threading.Thread(target=run, daemon=True).start()

    def _entregar(self, pub, msg):
        """Guarda na fila cifrada e tenta enviar agora."""
        with self.L:
            ob = self.t['outbox']
            if len(ob) >= 5000:
                ob.pop(0)
            ob.append({'id': novo_id(), 'para': pub, 'msg': msg,
                       'ts': agora()})
            self.banco.sujar('outbox')
        if self._online(pub):
            threading.Thread(target=self._flush, args=(pub,),
                             daemon=True).start()

    def _flush(self, pub):
        lk = self._flush_locks.setdefault(pub, threading.Lock())
        if not lk.acquire(blocking=False):
            self._flush_again.add(pub)   # quem está enviando vai reprocessar
            return
        try:
            while True:
                self._flush_again.discard(pub)
                n = self._numero(pub)
                if n is None or self.no.status_amigo(n) == 0:
                    return
                with self.L:
                    itens = [i for i in self.t['outbox'] if i['para'] == pub]
                for it in itens:
                    try:
                        self.no.enviar(n, it['msg'])
                    except Exception as e:
                        log.debug("flush %s: %s", pub[:8], e)
                        return
                    with self.L:
                        if it in self.t['outbox']:
                            self.t['outbox'].remove(it)
                        self.banco.sujar('outbox')
                    self._ao_enviado(pub, it['msg'])
                if pub not in self._flush_again:
                    return
        finally:
            lk.release()

    def _ao_enviado(self, pub, msg):
        if msg.get('tipo') != 'msg':
            return
        cid = ('g:' + msg['grupo']) if msg.get('grupo') else 'p:' + pub
        with self.L:
            m = self.banco.achar(cid, msg['id'])
            if m is not None and pub not in m.setdefault('env', []):
                m['env'].append(pub)
                self.banco.tocar(cid)
        self._evento('msg', cid=cid)

    # ═══ vínculos Tox ════════════════════════════════════════════════
    def _link(self, addr, motivo):
        addr = str(addr).upper()
        if not RE_ADDR.match(addr) or addr[:64] == self.pub():
            return None
        d = self.rede.hints.get(addr[:64])
        if d:
            self.no.aplicar_dica(d)
        try:
            n, novo = self.no.adicionar_amigo(addr,
                                              f"RRFS-SOCIAL:{PROTO}:{motivo}")
        except Exception as e:
            log.debug("link %s: %s", addr[:8], e)
            return None
        if novo:
            with self.L:
                self.t['ajustes']['links_ts'][addr[:64]] = agora()
                self.banco.sujar('ajustes')
        return n

    def _aceitar_link(self, pub):
        n = self.no.aceitar_amigo(pub)
        if n is not None:
            with self.L:
                self.t['ajustes']['links_ts'][pub] = agora()
                self.banco.sujar('ajustes')
        return n

    def _ao_pedido(self, chave, texto):
        p = texto.strip().split(':', 3)
        if len(p) < 3 or p[0] != 'RRFS-SOCIAL':
            return
        tipo, extra = p[2], (p[3] if len(p) > 3 else '')
        aj = self.t['ajustes']
        if chave in aj['bloqueados']:
            return
        if tipo == 'contato':
            self._novo_pedido(chave, extra)
        elif tipo == 'no':
            if aj['aceitar_nos'] and len(aj['nos']) < MAX_NOS * 2:
                if self._aceitar_link(chave) is not None:
                    with self.L:
                        if chave not in aj['nos']:
                            aj['nos'].append(chave)
                            self.banco.sujar('ajustes')
        elif tipo == 'grupo':
            g = self.t['grupos'].get(extra[:16])
            if g and g['estado'] == 'ativo' and chave in g['membros']:
                self._aceitar_link(chave)
        elif tipo == 'dispositivo':
            if extra.startswith('retorno'):
                if chave in aj['dispositivos']:
                    self._aceitar_link(chave)
            else:
                self.tunel.aceitar_pedido(chave, extra)
        elif tipo == 'perfil':
            if aj.get('perfil_publico', True) and self._limite(chave, 'plink', 3, 600):
                self._aceitar_link(chave)
        elif tipo in ('video', 'enxame'):
            self.ent.aceitar_link(chave, tipo, extra)
        elif tipo == 'convite':
            novos = sum(1 for c in self.t['convites'].values())
            if novos < 50:
                self._aceitar_link(chave)

    def _precisa_link(self, pub):
        aj = self.t['ajustes']
        if pub in self.t['contatos'] or pub in aj['nos']:
            return True
        if self.ent.precisa_link(pub) or pub in aj['dispositivos']:
            return True
        if any(g['estado'] == 'ativo' and pub in g['membros']
               for g in self.t['grupos'].values()):
            return True
        t = agora() - 14 * 86400
        if any(v['ts'] > t and k.startswith(pub)
               for k, v in aj['convites_env'].items()):
            return True
        return any(c['de'] == pub and c['ts'] > t
                   for c in self.t['convites'].values())

    def _limpar_links(self):
        aj = self.t['ajustes']
        t = agora()
        for k in [k for k, v in aj['convites_env'].items()
                  if v['ts'] < t - 14 * 86400]:
            aj['convites_env'].pop(k, None)
        for a in self.no.listar_amigos():
            pub = a['chave_publica']
            if a['status'] != 0:
                self._visto[pub] = t
            if pub in aj['nos'] and t - self._visto.setdefault(pub, t) \
                    > 3 * 86400:
                aj['nos'].remove(pub)
            if self._precisa_link(pub):
                continue
            if t - aj['links_ts'].get(pub, 0) > 3600:
                self.no.remover_amigo(a['numero'])
                aj['links_ts'].pop(pub, None)
        self.banco.sujar('ajustes')

    def _garantir_vinculos(self):
        """Contatos pendentes, membros de grupos e nós da rede."""
        amigos = {a['chave_publica'] for a in self.no.listar_amigos()}
        for pub, c in list(self.t['contatos'].items()):
            if pub not in amigos and c.get('addr'):
                self._link(c['addr'], 'contato:' + self._nome_completo())
        for g in list(self.t['grupos'].values()):
            if g['estado'] != 'ativo':
                continue
            for pub, m in g['membros'].items():
                if pub != self.pub() and pub not in amigos:
                    self._link(m['addr'], 'grupo:' + g['gid'])
        aj = self.t['ajustes']
        saida = [p for p in aj['nos'] if p in amigos]
        if len(saida) < MAX_NOS_SAIDA:
            novos = 0
            for addr in self.rede.recentes(40):
                if novos >= 3:
                    break
                if addr[:64] in amigos or addr[:64] == self.pub():
                    continue
                if self._link(addr, 'no') is not None:
                    novos += 1
                    amigos.add(addr[:64])
                    with self.L:
                        if addr[:64] not in aj['nos']:
                            aj['nos'].append(addr[:64])
                            self.banco.sujar('ajustes')

    # ═══ laços de manutenção ═════════════════════════════════════════
    def _loop_manter(self):
        t_dir = t_lim = 0
        while self.rodando:
            for _ in range(20):
                if not self.rodando:
                    return
                time.sleep(1)
            try:
                self._garantir_vinculos()
                if self.no.status_rede() == 0 and agora() - self._ult_boot > 120:
                    for d in self.rede.hints_recentes(40):
                        self.no.aplicar_dica(d)
                    nos = carregar_nos(self.arq_nos)
                    if nos:
                        self.no.bootstrap_otimizado(nos)
                    self._ult_boot = agora()
                for a in self.no.listar_amigos():
                    if a['status']:
                        self._flush(a['chave_publica'])
                if agora() - t_dir > 300:
                    for a in self.no.listar_amigos():
                        pub = a['chave_publica']
                        if not a['status']:
                            continue
                        if self._pode_dir(pub):
                            self._pedir_dir(pub)
                            self.ent.pedir_catalogo(pub)
                        if self._eh_contato(pub) or self._compartilha_grupo(pub):
                            self._enviar_perfil(pub)
                    t_dir = agora()
                if agora() - t_lim > 300:
                    self._limpar_links()
                    self._limpar_geral()
                    self.cham.limpar()
                    self.tunel.limpar()
                    t_lim = agora()
                self._purgar_status()
                self.rede.salvar_se_sujo()
            except Exception:
                log.exception("loop_manter")

    def _loop_rota(self):
        while self.rodando:
            for _ in range(12):
                if not self.rodando:
                    return
                time.sleep(1)
            try:
                for a in self.no.listar_amigos():
                    if a['status'] != 1:
                        continue
                    self._enviar_dica(a['chave_publica'])
                    d = self.rede.hints.get(a['chave_publica'])
                    if d:
                        self.no.aplicar_dica(d)
            except Exception as e:
                log.debug("loop_rota: %s", e)

    def _limpar_geral(self):
        t = agora()
        with self.L:
            self.t['outbox'][:] = [i for i in self.t['outbox']
                                   if t - i['ts'] < TTL_OUTBOX]
            for k in [k for k, v in self.t['baixas'].items()
                      if t - v['ts'] > 7 * 86400]:
                self.t['baixas'].pop(k)
            for k in [k for k, v in self.t['convites'].items()
                      if t - v['ts'] > 30 * 86400]:
                self.t['convites'].pop(k)
            for k in [k for k, v in self._lim.items() if time.time() - v[0] > 300]:
                self._lim.pop(k, None)
            for k in [k for k, v in self._rx.items() if time.time() - v['t'] > 180]:
                self._abortar_rx(k, 'Tempo esgotado')
            for k in ('outbox', 'baixas', 'convites'):
                self.banco.sujar(k)

    def _limite(self, pub, tipo, maximo, janela=60):
        k = (pub, tipo)
        t0, n = self._lim.get(k, (0, 0))
        if time.time() - t0 > janela:
            t0, n = time.time(), 0
        self._lim[k] = (t0, n + 1)
        return n + 1 <= maximo

    # ═══ conexão de um par ═══════════════════════════════════════════
    def _ao_amigo(self, numero, status):
        if status == 0:
            self.ent.par_offline(self._pub_de(numero))
            self.cham.par_offline(self._pub_de(numero))
            return
        pub = self._pub_de(numero)
        self._visto[pub] = agora()
        threading.Thread(target=self._ao_conectar, args=(pub,),
                         daemon=True).start()

    def _ao_conectar(self, pub):
        try:
            ct = self.t['contatos'].get(pub)
            if ct and ct['estado'] == 'pend_env':
                self._enviar_async(pub, self._pedido_fio())
            if ct and ct['estado'] == 'ativo':
                self._enviar_perfil(pub)
                self._enviar_presenca(pub)
                self._enviar_status_lista(pub)
            elif self._compartilha_grupo(pub):
                self._enviar_perfil(pub)
            self._enviar_dica(pub)
            if self._pode_dir(pub):
                self._enviar_async(pub, self._dir_push())
                self._pedir_dir(pub)
            self._retomar_baixas(pub)
            if self._pode_dir(pub):
                self.ent.pedir_catalogo(pub)
            self.ent.par_online(pub)
            self.posts.ao_conectar(pub)
            self._flush(pub)
        except Exception:
            log.exception("ao_conectar")

    def _enviar_dica(self, pub):
        dht, porta = self.no.dht_id_hex(), self.no.porta_udp()
        lan, glob = ips_lan_locais(), ips_globais_locais()
        if dht and porta and (lan or glob):
            self._enviar_async(pub, {'tipo': 'dica', 'dht_id': dht,
                                     'porta': porta, 'ips': lan,
                                     'ips_globais': glob,
                                     'tcp_porta': self.no.tcp_porta,
                                     'stun_porta': self.stun.porta if self.stun else 0})

    def _h_dica(self, pub, m):
        d = validar_dica(m, permitir_lan=True)
        if d:
            self.rede.guardar_dica(pub, d)
            self.no.aplicar_dica(d)

    # ═══ despacho de mensagens ═══════════════════════════════════════
    def _ao_mensagem(self, numero, msg):
        pub = self._pub_de(numero)
        if not pub or pub in self.t['ajustes']['bloqueados']:
            return
        h = {'contato_pedir': self._h_contato_pedir,
             'contato_aceito': self._h_contato_aceito,
             'contato_removido': self._h_contato_removido,
             'perfil': self._h_perfil, 'msg': self._h_msg, 'ack': self._h_ack,
             'arq_pedir': self._h_arq_pedir, 'arq_inicio': self._h_arq_inicio,
             'arq_fim': self._h_arq_fim, 'arq_erro': self._h_arq_erro,
             'status_lista': self._h_status_lista,
             'grupo_convite': self._h_grupo_convite,
             'grupo_aceito': self._h_grupo_aceito,
             'grupo_estado': self._h_grupo_estado,
             'grupo_sair': self._h_grupo_sair,
             'grupo_removido': self._h_grupo_removido,
             'dir_pedir': self._h_dir_pedir, 'dir_dados': self._h_dir_dados,
             'busca': self._h_busca, 'busca_res': self._h_busca_res,
             'presenca': self._h_presenca,
             'dica': self._h_dica}.get(msg.get('tipo'))
        if h:
            h(pub, msg)
        elif str(msg.get('tipo', '')).startswith('v_'):
            self.ent.tratar(pub, msg)
        elif str(msg.get('tipo', '')).startswith('c_'):
            self.cham.tratar(pub, msg)
        elif str(msg.get('tipo', '')).startswith('p_'):
            self.posts.tratar(pub, msg)
        elif str(msg.get('tipo', '')).startswith('t_'):
            self.tunel.tratar(pub, msg)

    def _eh_contato(self, pub):
        c = self.t['contatos'].get(pub)
        return bool(c and c['estado'] == 'ativo')

    def _compartilha_grupo(self, pub):
        return any(g['estado'] == 'ativo' and pub in g['membros']
                   for g in self.t['grupos'].values())

    # ═══ privacidade: modo "aparecer offline" ═══════════════════
    def _enviar_presenca(self, pub):
        self._enviar_async(pub, {'tipo': 'presenca',
                                 'oculto': bool(self.t['ajustes']['invisivel'])})

    def _h_presenca(self, pub, m):
        if self._eh_contato(pub):
            with self.L:
                self.t['pessoas'].setdefault(pub, {})['oculto'] = bool(m.get('oculto'))
                self.banco.sujar('pessoas')
            self._evento('contato', pub=pub)

    def online_visivel(self, pub):
        return self._online(pub) and not (self.t['pessoas'].get(pub) or {}).get('oculto')

    def privacidade(self, d=None):
        aj = self.t['ajustes']
        if d:
            with self.L:
                for k in ('invisivel', 'mostrar_amigos', 'perfil_publico'):
                    if k in d:
                        aj[k] = bool(d[k])
                self.banco.sujar('ajustes')
            if 'invisivel' in d:
                for a in self.no.listar_amigos():
                    if a['status'] and self._eh_contato(a['chave_publica']):
                        self._enviar_presenca(a['chave_publica'])
        return {k: aj[k] for k in ('invisivel', 'mostrar_amigos', 'perfil_publico')}

    def amigos_online(self):
        return [c for c in self.listar_contatos() if c['estado'] == 'ativo' and c['online']]

    def _pode_dir(self, pub):
        return self._eh_contato(pub) or pub in self.t['ajustes']['nos']

    # ═══ perfil ══════════════════════════════════════════════════════
    def _nome_completo(self):
        p = self.t['perfil']
        return (p['nome'] + ' ' + p['sobrenome']).strip()

    def perfil_proprio(self):
        p = dict(self.t['perfil'])
        p.update(addr=self.addr(), pub=self.pub())
        return p

    def atualizar_perfil(self, d):
        p = self.t['perfil']
        with self.L:
            if 'nome' in d:
                nome = limpar(d['nome'], 40)
                if not nome:
                    raise ErroSocial('Informe o seu nome.')
                p['nome'] = nome
            if 'sobrenome' in d:
                p['sobrenome'] = limpar(d['sobrenome'], 60)
            if 'bio' in d:
                p['bio'] = limpar_multilinha(d['bio'], 500)
            if 'visivel' in d:
                p['visivel'] = bool(d['visivel'])
            if d.get('foto'):
                self._definir_imagem('foto', d['foto'], 2 * 1024 * 1024)
                mini = validar_mini(d.get('foto_mini'))
                if mini:
                    p['foto_mini'] = mini
            if d.get('remover_foto'):
                self._remover_imagem('foto')
                p['foto_mini'] = ''
            if d.get('capa'):
                self._definir_imagem('capa', d['capa'], 4 * 1024 * 1024)
            if d.get('remover_capa'):
                self._remover_imagem('capa')
            p['ts'] = max(agora(), p['ts'] + 1)
            self.banco.sujar('perfil')
        if not self.no:
            return
        self._publicar_entrada()
        for a in self.no.listar_amigos():
            if a['status'] and (self._eh_contato(a['chave_publica'])
                                or self._compartilha_grupo(a['chave_publica'])):
                self._enviar_perfil(a['chave_publica'])

    def _definir_imagem(self, campo, data_url, limite):
        raw, mime = decodificar_imagem(data_url, limite)
        if not raw:
            raise ErroSocial('Imagem inválida (use JPEG, PNG ou WebP).')
        p, mid = self.t['perfil'], novo_id()
        esc = self.banco.escritor_midia(mid)
        esc.escrever(raw)
        tam, sha = esc.fechar()
        self.t['midia'][mid] = {'nome': campo, 'mime': mime, 'tam': tam,
                                'sha': sha, 'dono': 'eu',
                                'acl': {'tipo': 'contatos'}}
        self._remover_imagem(campo)
        p[campo + '_mid'] = mid
        p[campo + '_ts'] = max(agora(), p[campo + '_ts'] + 1)
        self.banco.sujar('midia')

    def _remover_imagem(self, campo):
        p = self.t['perfil']
        if p[campo + '_mid']:
            self.banco.apagar_midia(p[campo + '_mid'])
        p[campo + '_mid'] = ''
        p[campo + '_ts'] = max(agora(), p[campo + '_ts'] + 1)

    def _perfil_fio(self, completo):
        p = self.t['perfil']
        d = {'tipo': 'perfil', 'nome': p['nome'], 'sobrenome': p['sobrenome'],
             'foto_mini': p['foto_mini'], 'addr': self.addr(), 'ts': p['ts']}
        if completo:
            d.update(bio=p['bio'], foto_mid=p['foto_mid'],
                     capa_mid=p['capa_mid'], foto_ts=p['foto_ts'],
                     capa_ts=p['capa_ts'])
        return d

    def _enviar_perfil(self, pub):
        self._enviar_async(pub, self._perfil_fio(self._eh_contato(pub)))

    def _h_perfil(self, pub, m):
        ct = self.t['contatos'].get(pub)
        eh_ct = bool(ct and ct['estado'] == 'ativo')
        if not (eh_ct or self._compartilha_grupo(pub)):
            return
        nome = limpar(m.get('nome'), 40)
        if not nome:
            return
        sob, mini = limpar(m.get('sobrenome'), 60), validar_mini(m.get('foto_mini'))
        addr = str(m.get('addr', '')).upper()
        with self.L:
            pe = self.t['pessoas'].setdefault(pub, {})
            pe.update(nome=nome, sobrenome=sob, foto_mini=mini)
            if RE_ADDR.match(addr) and addr[:64] == pub:
                pe['addr'] = addr
            for g in self.t['grupos'].values():
                if pub in g['membros']:
                    g['membros'][pub].update(nome=nome, sobrenome=sob)
            self.banco.sujar('pessoas')
            self.banco.sujar('grupos')
            if eh_ct:
                ct.update(nome=nome, sobrenome=sob, foto_mini=mini,
                          bio=limpar_multilinha(m.get('bio'), 500))
                if pe.get('addr'):
                    ct['addr'] = pe['addr']
                self.banco.sujar('contatos')
        if eh_ct:
            for campo in ('foto', 'capa'):
                fid, ts = str(m.get(campo + '_mid', '')), 0
                try:
                    ts = int(m.get(campo + '_ts', 0))
                except (TypeError, ValueError):
                    pass
                if RE_ID.match(fid) and ts > ct.get(campo + '_ts', 0):
                    self._pedir_arq(pub, fid, {'tipo': 'perfil',
                                               'campo': campo, 'ts': ts},
                                    limite=6 * 1024 * 1024)
        self._evento('perfil', pub=pub)

    # ═══ diretório e busca ═══════════════════════════════════════════
    def _entrada_propria(self):
        p = self.t['perfil']
        return {'addr': self.addr(), 'nome': p['nome'],
                'sobrenome': p['sobrenome'], 'foto_mini': p['foto_mini'],
                'ts': p['ts'], 'removido': not p['visivel']}

    def _publicar_entrada(self):
        e = self._entrada_propria()
        if not e['nome']:
            return
        self.rede.mesclar_usuario(e, self.pub())
        msg = {'tipo': 'dir_dados', 'usuarios': [e], 'push': True,
               'epoca': self.rede.epoca}
        for a in self.no.listar_amigos():
            if a['status'] and self._pode_dir(a['chave_publica']):
                self._enviar_async(a['chave_publica'], msg)

    def _dir_push(self):
        return {'tipo': 'dir_dados', 'usuarios': [self._entrada_propria()],
                'push': True, 'epoca': self.rede.epoca}

    def _pedir_dir(self, pub):
        s = self.rede.get_sync(pub)
        self._enviar_async(pub, {'tipo': 'dir_pedir',
                                 'apos': s.get('cursor') or [0, ''],
                                 'epoca': s.get('epoca', '')})

    def _h_dir_pedir(self, pub, m):
        if not self._pode_dir(pub) or not self._limite(pub, 'dir', 40):
            return
        apos = m.get('apos') or [0, '']
        ep = str(m.get('epoca', ''))
        if not ep or ep != self.rede.epoca:
            apos = [0, '']
        pag, prox, mais = self.rede.delta(apos)
        fio = [{k: e[k] for k in ('addr', 'nome', 'sobrenome', 'foto_mini',
                                  'ts', 'removido')} for e in pag]
        self._enviar_async(pub, {'tipo': 'dir_dados', 'resp': True,
                                 'usuarios': fio, 'prox': prox, 'mais': mais,
                                 'epoca': self.rede.epoca})

    def _h_dir_dados(self, pub, m):
        if not self._pode_dir(pub):
            return
        k = self._rumores.get(pub, [0, 0])
        if time.time() - k[0] > 3600:
            k = [time.time(), 0]
        for e in (m.get('usuarios') or [])[:DIR_PAGINA]:
            if k[1] > 3000 or not isinstance(e, dict):
                break
            k[1] += 1
            self.rede.mesclar_usuario(e, pub)
        self._rumores[pub] = k
        if m.get('resp'):
            if m.get('mais') and m.get('prox'):
                self._enviar_async(pub, {'tipo': 'dir_pedir',
                                         'apos': m['prox'],
                                         'epoca': m.get('epoca', '')})
            else:
                self.rede.set_sync(pub, m.get('prox') or [0, ''],
                                   str(m.get('epoca', '')))

    def _h_busca(self, pub, m):
        if not self._pode_dir(pub) or not self._limite(pub, 'busca', 30):
            return
        res = self.rede.buscar(limpar(m.get('q'), 80), 15)
        fio = [{k: e[k] for k in ('addr', 'nome', 'sobrenome', 'foto_mini',
                                  'ts', 'removido')} for e in res]
        self._enviar_async(pub, {'tipo': 'busca_res',
                                 'id': str(m.get('id', ''))[:40],
                                 'resultados': fio})

    def _h_busca_res(self, pub, m):
        q = self._buscas.get(str(m.get('id', '')))
        if q is not None:
            q.put((pub, m.get('resultados') or []))

    def buscar(self, texto):
        import queue
        texto = limpar(texto, 80)
        if len(texto) < 2:
            raise ErroSocial('Digite pelo menos 2 letras do nome.')
        bid = secrets.token_hex(6)
        q = queue.Queue()
        self._buscas[bid] = q
        alvos = [a['chave_publica'] for a in self.no.listar_amigos()
                 if a['status'] and self._pode_dir(a['chave_publica'])]
        import random
        random.shuffle(alvos)
        alvos = alvos[:8]
        try:
            for p in alvos:
                self._enviar_async(p, {'tipo': 'busca', 'id': bid, 'q': texto})
            fim, esperando = time.time() + 3.5, len(alvos)
            while esperando > 0 and time.time() < fim:
                try:
                    pub, res = q.get(timeout=max(0.05, fim - time.time()))
                except queue.Empty:
                    break
                esperando -= 1
                for e in res[:15]:
                    if isinstance(e, dict):
                        e = dict(e, removido=False)
                        self.rede.mesclar_usuario(e, None)
        finally:
            self._buscas.pop(bid, None)
        saida = []
        for e in self.rede.buscar(texto, 25):
            pub = e['addr'][:64]
            if pub == self.pub():
                continue
            ct = self.t['contatos'].get(pub)
            saida.append({'addr': e['addr'], 'pub': pub, 'nome': e['nome'],
                          'sobrenome': e['sobrenome'],
                          'foto_mini': e['foto_mini'],
                          'verificado': e['verificado'],
                          'impressao': pub[:8],
                          'relacao': (ct['estado'] if ct else 'nenhuma')})
        return {'resultados': saida, 'consultados': len(alvos)}

    # ═══ contatos ════════════════════════════════════════════════════
    def _pedido_fio(self):
        p = self.t['perfil']
        return {'tipo': 'contato_pedir', 'nome': p['nome'],
                'sobrenome': p['sobrenome'], 'addr': self.addr()}

    def adicionar_contato(self, addr):
        addr = str(addr or '').strip().upper().replace(' ', '')
        if addr.startswith('RRFS-'):
            addr = addr[5:]
        if not RE_ADDR.match(addr):
            raise ErroSocial('Chave inválida: são 76 caracteres hexadecimais.')
        pub = addr[:64]
        if pub == self.pub():
            raise ErroSocial('Esta é a sua própria chave.')
        if pub in self.t['ajustes']['bloqueados']:
            self.t['ajustes']['bloqueados'].remove(pub)
        ct = self.t['contatos'].get(pub)
        if ct and ct['estado'] == 'ativo':
            raise ErroSocial('Esta pessoa já é seu contato.')
        e = self.rede.get(addr) or {}
        with self.L:
            self.t['contatos'][pub] = {
                'pub': pub, 'addr': addr, 'estado': 'pend_env',
                'nome': e.get('nome', ''), 'sobrenome': e.get('sobrenome', ''),
                'foto_mini': e.get('foto_mini', ''), 'bio': '', 'ts': agora()}
            self.banco.sujar('contatos')
        if self.t['pedidos'].pop(pub, None):
            self._ativar_contato(pub)
            return
        self._link(addr, 'contato:' + self._nome_completo())
        if self._online(pub):
            self._enviar_async(pub, self._pedido_fio())
        self._evento('contato', pub=pub)

    def _novo_pedido(self, pub, texto_nome, addr=''):
        ct = self.t['contatos'].get(pub)
        if ct and ct['estado'] == 'ativo':
            self._entregar(pub, {'tipo': 'contato_aceito'})
            return
        if ct and ct['estado'] == 'pend_env':
            self._ativar_contato(pub)
            return
        with self.L:
            ped = self.t['pedidos']
            if pub not in ped and len(ped) >= 200:
                return
            ped[pub] = {'pub': pub, 'ts': agora(), 'addr': addr,
                        'nome': limpar(texto_nome, 80)
                        or ped.get(pub, {}).get('nome', '')}
            self.banco.sujar('pedidos')
        self._evento('pedido', pub=pub)

    def _h_contato_pedir(self, pub, m):
        if not self._limite(pub, 'pedido', 10):
            return
        addr = str(m.get('addr', '')).upper()
        addr = addr if RE_ADDR.match(addr) and addr[:64] == pub else ''
        nome = (limpar(m.get('nome'), 40) + ' '
                + limpar(m.get('sobrenome'), 60)).strip()
        self._novo_pedido(pub, nome, addr)

    def _ativar_contato(self, pub):
        with self.L:
            ct = self.t['contatos'].get(pub)
            if not ct:
                return
            ct['estado'] = 'ativo'
            self.banco.sujar('contatos')
        self._entregar(pub, {'tipo': 'contato_aceito'})
        self._enviar_perfil(pub)
        self._enviar_status_lista(pub)
        self._evento('contato', pub=pub)

    def _h_contato_aceito(self, pub, m):
        ct = self.t['contatos'].get(pub)
        if ct and ct['estado'] == 'pend_env':
            with self.L:
                ct['estado'] = 'ativo'
                self.banco.sujar('contatos')
            self._enviar_perfil(pub)
            self._enviar_presenca(pub)
            self._enviar_status_lista(pub)
            self.posts.enviar_lista(pub)
            self._evento('contato', pub=pub)

    def aceitar_pedido(self, pub):
        pub = str(pub).upper()
        with self.L:
            ped = self.t['pedidos'].pop(pub, None)
            self.banco.sujar('pedidos')
        if not ped:
            raise ErroSocial('Pedido não encontrado.')
        if self._aceitar_link(pub) is None:
            raise ErroSocial('Não foi possível aceitar agora. Tente de novo.')
        e = self.rede.get(ped['addr']) if ped.get('addr') else {}
        nome, _, sob = (ped.get('nome') or '').partition(' ')
        with self.L:
            self.t['contatos'][pub] = {
                'pub': pub, 'addr': ped.get('addr', ''), 'estado': 'ativo',
                'nome': (e or {}).get('nome') or nome,
                'sobrenome': (e or {}).get('sobrenome') or sob,
                'foto_mini': (e or {}).get('foto_mini', ''), 'bio': '',
                'ts': agora()}
            self.banco.sujar('contatos')
        self._entregar(pub, {'tipo': 'contato_aceito'})
        self._enviar_perfil(pub)
        self._enviar_presenca(pub)
        self._enviar_status_lista(pub)
        self.posts.enviar_lista(pub)
        self._evento('contato', pub=pub)

    def recusar_pedido(self, pub, bloquear=False):
        pub = str(pub).upper()
        with self.L:
            self.t['pedidos'].pop(pub, None)
            if bloquear and pub not in self.t['ajustes']['bloqueados']:
                self.t['ajustes']['bloqueados'].append(pub)
                self.banco.sujar('ajustes')
            self.banco.sujar('pedidos')
        self._evento('pedido', pub=pub)

    def remover_contato(self, pub):
        pub = str(pub).upper()
        if pub not in self.t['contatos']:
            raise ErroSocial('Contato não encontrado.')
        n = self._numero(pub)
        if n is not None and self.no.status_amigo(n):
            try:
                self.no.enviar(n, {'tipo': 'contato_removido'})
            except Exception:
                pass
        self._apagar_contato(pub)

    def _apagar_contato(self, pub):
        self.posts.esquecer_autor(pub)
        with self.L:
            self.t['contatos'].pop(pub, None)
            for k in [k for k, s in self.t['status'].items() if s['dono'] == pub]:
                self._apagar_status_local(k)
            self.banco.sujar('contatos')
        self._evento('contato', pub=pub)

    def _h_contato_removido(self, pub, m):
        if pub in self.t['contatos']:
            self._apagar_contato(pub)

    def bloquear(self, pub):
        pub = str(pub).upper()
        with self.L:
            if pub not in self.t['ajustes']['bloqueados']:
                self.t['ajustes']['bloqueados'].append(pub)
                self.banco.sujar('ajustes')
        if pub in self.t['contatos']:
            self.remover_contato(pub)

    def nome_de(self, pub):
        c = self.t['contatos'].get(pub) or self.t['pessoas'].get(pub) or {}
        n = (c.get('nome', '') + ' ' + c.get('sobrenome', '')).strip()
        if not n:
            for g in self.t['grupos'].values():
                m = g['membros'].get(pub)
                if m:
                    n = (m.get('nome', '') + ' ' + m.get('sobrenome', '')).strip()
                    break
        return n or ('Usuário ' + pub[:8])

    def _mini_de(self, pub):
        c = self.t['contatos'].get(pub) or self.t['pessoas'].get(pub) or {}
        return c.get('foto_mini', '')

    def listar_contatos(self):
        saida = []
        for pub, c in self.t['contatos'].items():
            saida.append({'pub': pub, 'estado': c['estado'],
                          'nome': c.get('nome', ''),
                          'sobrenome': c.get('sobrenome', ''),
                          'foto_mini': c.get('foto_mini', ''),
                          'online': self.online_visivel(pub),
                          'addr': c.get('addr') or (self.t['pessoas'].get(pub)
                                                    or {}).get('addr', ''),
                          'impressao': pub[:8]})
        saida.sort(key=lambda c: (c['estado'] != 'ativo',
                                  (c['nome'] + c['sobrenome']).lower()))
        return saida

    def listar_pedidos(self):
        return sorted(self.t['pedidos'].values(), key=lambda p: -p['ts'])

    def contato_info(self, pub):
        pub = str(pub).upper()
        c = self.t['contatos'].get(pub)
        if not c:
            raise ErroSocial('Contato não encontrado.')
        return {'pub': pub, 'estado': c['estado'], 'nome': c.get('nome', ''),
                'sobrenome': c.get('sobrenome', ''), 'bio': c.get('bio', ''),
                'foto_mini': c.get('foto_mini', ''),
                'foto': c.get('foto_local', ''), 'capa': c.get('capa_local', ''),
                'online': self.online_visivel(pub), 'impressao': pub[:8],
                'addr': c.get('addr', '')}

    # ═══ mensagens ═══════════════════════════════════════════════════
    def _destinos(self, cid):
        """(lista de pubs destino, dict do grupo|None, acl)."""
        if cid.startswith('p:'):
            pub = cid[2:].upper()
            if not self._eh_contato(pub):
                raise ErroSocial('Esta pessoa não é seu contato.')
            return [pub], None, {'tipo': 'priv', 'pub': pub}
        if cid.startswith('g:'):
            g = self.t['grupos'].get(cid[2:])
            if not g or g['estado'] != 'ativo':
                raise ErroSocial('Você não está neste grupo.')
            return [p for p in g['membros'] if p != self.pub()], g, \
                {'tipo': 'grupo', 'gid': g['gid']}
        raise ErroSocial('Conversa inválida.')

    def enviar_texto(self, cid, texto):
        texto = limpar_multilinha(texto, 8000).strip()
        if not texto:
            raise ErroSocial('Mensagem vazia.')
        return self._enviar_msg(cid, 'texto', texto, None)

    def _enviar_msg(self, cid, k, texto, arq):
        destinos, g, _ = self._destinos(cid)
        mid, ts = novo_id(), agora()
        fio = {'tipo': 'msg', 'id': mid, 'ts': ts, 'k': k, 'texto': texto}
        if g:
            fio['grupo'] = g['gid']
        reg = {'id': mid, 'de': self.pub(), 'ts': ts, 'tipo': k,
               'texto': texto, 'para': destinos, 'env': [], 'ack': []}
        if arq:
            fio['arq'] = arq
            reg['arq'] = dict(arq, estado='ok', local=arq['fid'])
        with self.L:
            self.banco.add_msg(cid, reg, previa=texto or arq['nome'] if arq
                               else texto)
        for p in destinos:
            self._entregar(p, fio)
        self._evento('msg', cid=cid)
        return mid

    def enviar_video(self, cid, vid):
        v = self.cat.videos.get(vid)
        if not v or v['removido']:
            raise ErroSocial('Vídeo não encontrado.')
        destinos, g, _ = self._destinos(cid)
        mid, ts = novo_id(), agora()
        fio = {'tipo': 'msg', 'id': mid, 'ts': ts, 'k': 'video_ref',
               'texto': v['titulo'], 'vid': vid, 'entrada': Catalogo.fio(v)}
        if g:
            fio['grupo'] = g['gid']
        reg = {'id': mid, 'de': self.pub(), 'ts': ts, 'tipo': 'video_ref',
               'texto': v['titulo'], 'vid': vid, 'para': destinos, 'env': [],
               'ack': []}
        with self.L:
            self.banco.add_msg(cid, reg, previa='Vídeo: ' + v['titulo'])
        for p in destinos:
            self._entregar(p, fio)
        self._evento('msg', cid=cid)

    def enviar_arquivo(self, cid, mid, legenda=''):
        meta = self.t['midia'].get(mid)
        if not meta or meta.get('dono') != 'eu':
            raise ErroSocial('Arquivo não encontrado.')
        _, _, acl = self._destinos(cid)
        meta['acl'] = acl
        self.banco.sujar('midia')
        arq = {'fid': mid, 'nome': meta['nome'], 'mime': meta['mime'],
               'tam': meta['tam'], 'sha': meta['sha']}
        return self._enviar_msg(cid, tipo_por_mime(meta['mime']),
                                limpar_multilinha(legenda, 2000), arq)

    def _h_msg(self, pub, m):
        gid = m.get('grupo')
        if gid:
            g = self.t['grupos'].get(str(gid))
            if not g or g['estado'] != 'ativo' or pub not in g['membros']:
                return
            cid = 'g:' + g['gid']
        else:
            if not self._eh_contato(pub):
                return
            cid = 'p:' + pub
        mid = str(m.get('id', ''))
        if not RE_ID.match(mid):
            return
        if self.banco.tem_msg(cid, mid):
            self._enviar_async(pub, {'tipo': 'ack', 'ids': [mid],
                                     **({'grupo': gid} if gid else {})})
            return
        k = m.get('k') if m.get('k') in TIPOS_MSG else 'texto'
        try:
            ts = min(int(m.get('ts', agora())), agora() + 60)
        except (TypeError, ValueError):
            ts = agora()
        texto = limpar_multilinha(m.get('texto'), 8000)
        reg = {'id': mid, 'de': pub, 'ts': ts, 'tipo': k, 'texto': texto}
        if m.get('k') == 'video_ref':
            ent = m.get('entrada')
            self.cat.mesclar(ent)
            vid = str(m.get('vid', ''))
            v = self.cat.videos.get(vid)
            if not RE_ID.match(vid) or not v:
                return
            reg['tipo'], reg['vid'], reg['texto'] = 'video_ref', vid, v['titulo']
        arq = m.get('arq')
        if isinstance(arq, dict):
            try:
                fid, tam = str(arq.get('fid', '')), int(arq.get('tam', -1))
                sha = str(arq.get('sha', '')).lower()
            except (TypeError, ValueError):
                return
            if not RE_ID.match(fid) or not 0 <= tam <= MAX_ARQ \
                    or not RE_HEX64.match(sha):
                return
            local = hashlib.sha256((pub + fid).encode()).hexdigest()[:16]
            reg['arq'] = {'fid': fid, 'nome': nome_arquivo(arq.get('nome')),
                          'mime': mime_seguro(arq.get('mime')), 'tam': tam,
                          'sha': sha, 'estado': 'pendente', 'local': local}
            reg['tipo'] = tipo_por_mime(reg['arq']['mime']) \
                if k != 'texto' else k
        if not self.banco.add_msg(cid, reg, recebida=True,
                                  previa=texto or (reg.get('arq') or {}).get(
                                      'nome', '')):
            return
        self._enviar_async(pub, {'tipo': 'ack', 'ids': [mid],
                                 **({'grupo': gid} if gid else {})})
        if 'arq' in reg:
            a = reg['arq']
            if a['tam'] <= self.t['ajustes']['auto_baixar_mb'] * 1048576:
                self._pedir_arq(pub, a['fid'], {'tipo': 'msg', 'cid': cid,
                                                'mid': mid},
                                esperado=a, limite=MAX_ARQ)
            else:
                a['estado'] = 'manual'
        if g_nome := (self.t['grupos'][str(gid)]['nome'] if gid else ''):
            titulo = g_nome
        else:
            titulo = self.nome_de(pub)
        quem = self.nome_de(pub)
        prev = texto or (reg.get('arq') or {}).get('nome', '') or \
            ('Vídeo: ' + reg['texto'] if reg['tipo'] == 'video_ref' else '')
        self._evento('msg', cid=cid, nova=True, titulo=titulo, quem=quem,
                     grupo=bool(gid), previa=prev[:120],
                     mudo=cid in self.t['ajustes']['silenciados'])

    def _h_ack(self, pub, m):
        cid = ('g:' + str(m['grupo'])) if m.get('grupo') else 'p:' + pub
        for mid in (m.get('ids') or [])[:50]:
            with self.L:
                r = self.banco.achar(cid, str(mid))
                if r and pub in r.get('para', []) and pub not in r['ack']:
                    r['ack'].append(pub)
                    self.banco.tocar(cid)
        self._evento('msg', cid=cid)

    def baixar_manual(self, cid, mid):
        m = self.banco.achar(cid, mid)
        if not m or 'arq' not in m or m['de'] == self.pub():
            raise ErroSocial('Arquivo não encontrado.')
        a = m['arq']
        if a['estado'] == 'ok':
            return
        a['estado'] = 'pendente'
        self.banco.tocar(cid)
        self._pedir_arq(m['de'], a['fid'], {'tipo': 'msg', 'cid': cid,
                                            'mid': mid}, esperado=a,
                        limite=MAX_ARQ)

    def _estado_msg(self, m):
        if m.get('de') != self.pub():
            return 'recebida'
        para = m.get('para', [])
        if para and len(m.get('ack', [])) >= len(para):
            return 'entregue'
        return 'enviada' if m.get('env') else 'pendente'

    def listar_conversas(self):
        saida = []
        for cid, c in self.t['convs'].items():
            if cid.startswith('p:'):
                pub = cid[2:]
                if pub not in self.t['contatos']:
                    continue
                info = {'nome': self.nome_de(pub), 'foto_mini': self._mini_de(pub),
                        'online': self.online_visivel(pub)}
            else:
                g = self.t['grupos'].get(cid[2:])
                if not g:
                    continue
                info = {'nome': g['nome'], 'grupo': True,
                        'estado': g['estado'], 'foto_mini': ''}
            saida.append(dict(info, cid=cid, ts=c['ts'],
                              silenciada=cid in self.t['ajustes']['silenciados'],
                              nao_lidas=c['nao_lidas'], previa=c['previa']))
        saida.sort(key=lambda c: -c['ts'])
        return saida

    def mensagens(self, cid, antes=None, limite=60):
        self._destinos_leitura(cid)
        saida = []
        for m in self.banco.msgs(cid, antes, min(int(limite), 200)):
            m = dict(m)
            m['estado'] = self._estado_msg(m)
            m['nome'] = '' if m['de'] == self.pub() else self.nome_de(m['de'])
            m['meu'] = m['de'] == self.pub()
            a = m.get('arq')
            if a and a['estado'] == 'pendente':
                rx = self._rx.get(self._rx_local.get(a['local']))
                if rx:
                    a['progresso'] = round(100 * rx['rec'] / max(1, rx['tam']))
            m.pop('para', None)
            m.pop('env', None)
            m['ack'] = len(m.get('ack', []))
            saida.append(m)
        return saida

    def _destinos_leitura(self, cid):
        if cid.startswith('p:') and cid[2:].upper() in self.t['contatos']:
            return
        if cid.startswith('g:') and cid[2:] in self.t['grupos']:
            return
        raise ErroSocial('Conversa não encontrada.')

    def silenciar(self, cid, on):
        self._destinos_leitura(cid)
        with self.L:
            lst = self.t['ajustes']['silenciados']
            if on and cid not in lst:
                lst.append(cid)
            elif not on and cid in lst:
                lst.remove(cid)
            self.banco.sujar('ajustes')

    def lista_silenciados(self):
        saida = []
        for cid in self.t['ajustes']['silenciados']:
            if cid.startswith('p:'):
                saida.append({'cid': cid, 'nome': self.nome_de(cid[2:])})
            elif cid[2:] in self.t['grupos']:
                saida.append({'cid': cid, 'nome': self.t['grupos'][cid[2:]]['nome']})
        return saida

    def marcar_lido(self, cid):
        self.banco.marcar_lido(cid)

    # ═══ arquivos (modelo "pedir": o destinatário puxa do remetente) ═══
    def iniciar_upload(self):
        mid = novo_id()
        return mid, self.banco.escritor_midia(mid)

    def concluir_upload(self, mid, esc, nome, mime, acl=None):
        tam, sha = esc.fechar()
        with self.L:
            self.t['midia'][mid] = {
                'nome': nome_arquivo(nome), 'mime': mime_seguro(mime),
                'tam': tam, 'sha': sha, 'dono': 'eu',
                'acl': acl or {'tipo': 'contatos'}}
            self.banco.sujar('midia')
        return self.t['midia'][mid]

    def midia_meta(self, mid):
        meta = self.t['midia'].get(mid)
        if not meta or not os.path.exists(self.banco.caminho_midia(mid)):
            return None, None
        return meta, self.banco.caminho_midia(mid)

    def _pedir_arq(self, pub, fid, ctx, esperado=None, limite=MAX_ARQ):
        with self.L:
            if (pub, fid) in self._rx:
                return
            self.t['baixas'][f"{pub}:{fid}"] = {
                'de': pub, 'fid': fid, 'ctx': ctx, 'ts': agora(),
                'esp': {k: esperado[k] for k in ('tam', 'sha', 'mime', 'nome')
                        if esperado and k in esperado} or None,
                'limite': limite}
            self.banco.sujar('baixas')
        self._enviar_async(pub, {'tipo': 'arq_pedir', 'fid': fid})

    def _retomar_baixas(self, pub):
        for k, b in list(self.t['baixas'].items()):
            if b['de'] == pub and (pub, b['fid']) not in self._rx:
                self._enviar_async(pub, {'tipo': 'arq_pedir', 'fid': b['fid']})

    def _autorizado_midia(self, pub, meta):
        acl = meta.get('acl') or {}
        t = acl.get('tipo')
        if t == 'priv':
            return acl.get('pub') == pub and self._eh_contato(pub)
        if t == 'grupo':
            g = self.t['grupos'].get(acl.get('gid'))
            return bool(g and g['estado'] == 'ativo' and pub in g['membros'])
        if t == 'contatos':
            return self._eh_contato(pub)
        return False

    def _h_arq_pedir(self, pub, m):
        fid = str(m.get('fid', ''))
        meta = self.t['midia'].get(fid)
        if not RE_ID.match(fid) or not meta or meta.get('dono') != 'eu' \
                or not self._autorizado_midia(pub, meta):
            self._enviar_async(pub, {'tipo': 'arq_erro', 'fid': fid,
                                     'motivo': 'Indisponível'})
            return
        if self._tx.get(pub, 0) >= 3:
            return
        self._tx[pub] = self._tx.get(pub, 0) + 1
        threading.Thread(target=self._servir_arq, args=(pub, fid, meta),
                         daemon=True).start()

    def _servir_arq(self, pub, fid, meta):
        try:
            n = self._numero(pub)
            if n is None:
                return
            self.no.enviar(n, {'tipo': 'arq_inicio', 'fid': fid,
                               'tam': meta['tam'], 'sha': meta['sha'],
                               'mime': meta['mime'], 'nome': meta['nome']})
            fid8, seq = bytes.fromhex(fid), 0
            for bloco in self.cofre.ler_arquivo(self.banco.caminho_midia(fid)):
                for i in range(0, len(bloco), CHUNK_BIN):
                    self.no.enviar_bin(n, fid8, seq, bloco[i:i + CHUNK_BIN])
                    seq += 1
            self.no.enviar(n, {'tipo': 'arq_fim', 'fid': fid})
        except Exception as e:
            log.debug("servir_arq: %s", e)
        finally:
            self._tx[pub] = max(0, self._tx.get(pub, 1) - 1)

    def _h_arq_inicio(self, pub, m):
        fid = str(m.get('fid', ''))
        b = self.t['baixas'].get(f"{pub}:{fid}")
        if not b or (pub, fid) in self._rx:
            return
        try:
            tam = int(m.get('tam', -1))
        except (TypeError, ValueError):
            return
        esp = b.get('esp') or {}
        if not 0 <= tam <= b.get('limite', MAX_ARQ) or \
                ('tam' in esp and esp['tam'] != tam):
            self._falha_baixa(pub, fid, 'Tamanho inválido')
            return
        sha = str(m.get('sha', '')).lower()
        if not RE_HEX64.match(sha) or ('sha' in esp and esp['sha'] != sha):
            self._falha_baixa(pub, fid, 'Verificação inválida')
            return
        local = hashlib.sha256((pub + fid).encode()).hexdigest()[:16]
        esc = self.banco.escritor_midia(local)
        self._rx[(pub, fid)] = {'esc': esc, 'tam': tam, 'sha': sha,
                                'mime': mime_seguro(m.get('mime')),
                                'nome': nome_arquivo(m.get('nome')), 'seq': 0,
                                'rec': 0, 't': time.time(), 'local': local}
        self._rx_local[local] = (pub, fid)

    def _ao_bin(self, numero, payload):
        pub = self._pub_de(numero)
        fid = payload[:8].hex()
        rx = self._rx.get((pub, fid))
        if not rx:
            return
        seq = struct.unpack('>I', payload[8:12])[0]
        dados = payload[12:]
        if seq != rx['seq'] or rx['rec'] + len(dados) > rx['tam']:
            self._abortar_rx((pub, fid), 'Dados fora de ordem')
            return
        rx['esc'].escrever(dados)
        rx['rec'] += len(dados)
        rx['seq'] += 1
        rx['t'] = time.time()

    def _abortar_rx(self, chave, motivo):
        rx = self._rx.pop(chave, None)
        if rx:
            rx['esc'].cancelar()
            self._rx_local.pop(rx['local'], None)
            self._falha_baixa(chave[0], chave[1], motivo, manter=True)

    def _h_arq_fim(self, pub, m):
        fid = str(m.get('fid', ''))
        rx = self._rx.pop((pub, fid), None)
        if not rx:
            return
        self._rx_local.pop(rx['local'], None)
        tam, sha = rx['esc'].fechar()
        if tam != rx['tam'] or sha != rx['sha']:
            self.banco.apagar_midia(rx['local'])
            self._falha_baixa(pub, fid, 'Arquivo corrompido na transferência')
            return
        b = self.t['baixas'].pop(f"{pub}:{fid}", None)
        self.banco.sujar('baixas')
        if not b:
            self.banco.apagar_midia(rx['local'])
            return
        with self.L:
            self.t['midia'][rx['local']] = {
                'nome': rx['nome'], 'mime': rx['mime'], 'tam': tam,
                'sha': sha, 'dono': pub}
            self.banco.sujar('midia')
            ctx = b['ctx']
            if ctx['tipo'] == 'msg':
                msg = self.banco.achar(ctx['cid'], ctx['mid'])
                if msg and 'arq' in msg:
                    msg['arq']['estado'] = 'ok'
                    msg['arq']['mime'] = rx['mime']
                    self.banco.tocar(ctx['cid'])
                self._evento('msg', cid=ctx['cid'])
            elif ctx['tipo'] == 'perfil':
                ct = self.t['contatos'].get(pub)
                campo = ctx['campo']
                if ct and ctx['ts'] > ct.get(campo + '_ts', 0):
                    if ct.get(campo + '_local'):
                        self.banco.apagar_midia(ct[campo + '_local'])
                    ct[campo + '_local'], ct[campo + '_ts'] = rx['local'], ctx['ts']
                    self.banco.sujar('contatos')
                self._evento('perfil', pub=pub)
            elif ctx['tipo'] == 'post':
                p = self.t['posts'].get(ctx['key'])
                for mm in (p or {}).get('midias', []):
                    if mm['fid'] == ctx['fid']:
                        mm['estado'] = 'ok'
                        mm['mime'] = rx['mime']
                self.banco.sujar('posts')
                self._evento('post')
            elif ctx['tipo'] == 'status':
                s = self.t['status'].get(ctx['id'])
                if s:
                    s['local'] = rx['local']
                    self.banco.sujar('status')
                self._evento('status')

    def _h_arq_erro(self, pub, m):
        self._falha_baixa(pub, str(m.get('fid', '')), 'Indisponível no remetente')

    def _falha_baixa(self, pub, fid, motivo, manter=False):
        log.debug("download %s/%s falhou: %s", pub[:8], fid, motivo)
        if manter:
            return
        with self.L:
            b = self.t['baixas'].pop(f"{pub}:{fid}", None)
            self.banco.sujar('baixas')
            if b and b['ctx']['tipo'] == 'post':
                p = self.t['posts'].get(b['ctx']['key'])
                for mm in (p or {}).get('midias', []):
                    if mm['fid'] == b['ctx']['fid']:
                        mm['estado'] = 'falhou'
                self.banco.sujar('posts')
            if b and b['ctx']['tipo'] == 'msg':
                msg = self.banco.achar(b['ctx']['cid'], b['ctx']['mid'])
                if msg and 'arq' in msg:
                    msg['arq']['estado'] = 'falhou'
                    self.banco.tocar(b['ctx']['cid'])
                self._evento('msg', cid=b['ctx']['cid'])

    # ═══ status (somem em 24 h) ══════════════════════════════════════
    def postar_status(self, texto='', mid=None):
        texto = limpar_multilinha(texto, 700).strip()
        arq, tipo = None, 'texto'
        if mid:
            meta = self.t['midia'].get(mid)
            if not meta or meta.get('dono') != 'eu':
                raise ErroSocial('Arquivo não encontrado.')
            tipo = tipo_por_mime(meta['mime'])
            if tipo not in ('imagem', 'video'):
                self.banco.apagar_midia(mid)
                raise ErroSocial('O status aceita texto, foto ou vídeo.')
            meta['acl'] = {'tipo': 'contatos'}
            arq = {'fid': mid, 'nome': meta['nome'], 'mime': meta['mime'],
                   'tam': meta['tam'], 'sha': meta['sha']}
        if not texto and not arq:
            raise ErroSocial('Escreva algo ou escolha uma foto/vídeo.')
        sid, ts = novo_id(), agora()
        with self.L:
            self.t['status'][sid] = {
                'id': sid, 'rid': sid, 'dono': self.pub(), 'tipo': tipo,
                'texto': texto, 'ts': ts, 'exp': ts + STATUS_TTL,
                'arq': arq, 'local': mid or ''}
            self.banco.sujar('status')
            self.banco.sujar('midia')
        self._difundir_status()
        self._evento('status')
        return sid

    def apagar_status(self, sid):
        s = self.t['status'].get(sid)
        if not s or s['dono'] != self.pub():
            raise ErroSocial('Status não encontrado.')
        self._apagar_status_local(sid)
        self._difundir_status()
        self._evento('status')

    def _apagar_status_local(self, sid):
        s = self.t['status'].pop(sid, None)
        self.banco.sujar('status')
        if s and s.get('local'):
            self.banco.apagar_midia(s['local'])

    def _lista_status_fio(self):
        return [{'id': s['rid'], 'tipo': s['tipo'], 'texto': s['texto'],
                 'ts': s['ts'], 'arq': s['arq']}
                for s in self.t['status'].values()
                if s['dono'] == self.pub() and s['exp'] > agora()]

    def _enviar_status_lista(self, pub):
        self._enviar_async(pub, {'tipo': 'status_lista',
                                 'itens': self._lista_status_fio()})

    def _difundir_status(self):
        for a in self.no.listar_amigos():
            if a['status'] and self._eh_contato(a['chave_publica']):
                self._enviar_status_lista(a['chave_publica'])

    def _h_status_lista(self, pub, m):
        if not self._eh_contato(pub) or not self._limite(pub, 'status', 30):
            return
        vistos = set()
        for it in (m.get('itens') or [])[:50]:
            if not isinstance(it, dict):
                continue
            rid = str(it.get('id', ''))
            if not RE_ID.match(rid):
                continue
            try:
                ts = min(int(it.get('ts', 0)), agora())
            except (TypeError, ValueError):
                continue
            if ts + STATUS_TTL <= agora():
                continue
            key = f"{pub[:8]}:{rid}"
            vistos.add(key)
            if key in self.t['status']:
                continue
            arq, tipo = None, 'texto'
            a = it.get('arq')
            if isinstance(a, dict):
                try:
                    fid, tam = str(a.get('fid', '')), int(a.get('tam', -1))
                    sha = str(a.get('sha', '')).lower()
                except (TypeError, ValueError):
                    continue
                mime = mime_seguro(a.get('mime'))
                tipo = tipo_por_mime(mime)
                if not RE_ID.match(fid) or not 0 <= tam <= 200 * 1048576 \
                        or not RE_HEX64.match(sha) \
                        or tipo not in ('imagem', 'video'):
                    continue
                arq = {'fid': fid, 'nome': nome_arquivo(a.get('nome')),
                       'mime': mime, 'tam': tam, 'sha': sha}
            with self.L:
                self.t['status'][key] = {
                    'id': key, 'rid': rid, 'dono': pub, 'tipo': tipo,
                    'texto': limpar_multilinha(it.get('texto'), 700),
                    'ts': ts, 'exp': ts + STATUS_TTL, 'arq': arq,
                    'local': '', 'visto': False}
                self.banco.sujar('status')
            if arq:
                self._pedir_arq(pub, arq['fid'], {'tipo': 'status', 'id': key},
                                esperado=arq, limite=200 * 1048576)
        with self.L:
            for k in [k for k, s in self.t['status'].items()
                      if s['dono'] == pub and k not in vistos]:
                self._apagar_status_local(k)
        self._evento('status')

    def _purgar_status(self):
        t = agora()
        with self.L:
            for k in [k for k, s in self.t['status'].items() if s['exp'] <= t]:
                self._apagar_status_local(k)

    def listar_status(self):
        grupos = {}
        for s in self.t['status'].values():
            if s['exp'] <= agora():
                continue
            d = grupos.setdefault(s['dono'], [])
            d.append({'id': s['id'], 'tipo': s['tipo'], 'texto': s['texto'],
                      'ts': s['ts'], 'exp': s['exp'], 'midia': s.get('local', ''),
                      'visto': s.get('visto', s['dono'] == self.pub())})
        saida = []
        for pub, itens in grupos.items():
            itens.sort(key=lambda i: i['ts'])
            meu = pub == self.pub()
            saida.append({'pub': pub, 'meu': meu,
                          'nome': 'Meu status' if meu else self.nome_de(pub),
                          'foto_mini': self.t['perfil']['foto_mini'] if meu
                          else self._mini_de(pub), 'itens': itens,
                          'novos': sum(1 for i in itens if not i['visto'])})
        saida.sort(key=lambda g: (not g['meu'], -g['novos'],
                                  -g['itens'][-1]['ts']))
        return saida

    def marcar_status_visto(self, sid):
        s = self.t['status'].get(sid)
        if s and not s.get('visto'):
            s['visto'] = True
            self.banco.sujar('status')

    # ═══ grupos ══════════════════════════════════════════════════════
    def _eu_membro(self):
        p = self.t['perfil']
        return {'addr': self.addr(), 'nome': p['nome'], 'sobrenome': p['sobrenome']}

    def _estado_fio(self, g):
        return {'gid': g['gid'], 'nome': g['nome'], 'desc': g['desc'],
                'dono': g['dono'], 'admins': g['admins'],
                'membros': g['membros'], 'versao': g['versao']}

    def _sistema(self, gid, texto):
        cid = 'g:' + gid
        self.banco.add_msg(cid, {'id': novo_id(), 'de': '', 'ts': agora(),
                                 'tipo': 'sistema', 'texto': texto},
                           previa=texto)
        self._evento('msg', cid=cid)

    def _g_admin(self, gid):
        g = self.t['grupos'].get(gid)
        if not g or g['estado'] != 'ativo':
            raise ErroSocial('Grupo não encontrado.')
        if self.pub() not in g['admins']:
            raise ErroSocial('Só administradores podem fazer isso.')
        return g

    def criar_grupo(self, nome, desc='', addrs=()):
        nome = limpar(nome, 60)
        if not nome:
            raise ErroSocial('Dê um nome ao grupo.')
        gid = novo_id()
        with self.L:
            self.t['grupos'][gid] = {
                'gid': gid, 'nome': nome, 'desc': limpar(desc, 300),
                'dono': self.pub(), 'admins': [self.pub()],
                'membros': {self.pub(): self._eu_membro()}, 'versao': 1,
                'estado': 'ativo', 'ts': agora()}
            self.banco.sujar('grupos')
            self._sistema(gid, 'Grupo criado')
        erros = []
        for a in addrs:
            try:
                self.grupo_convidar(gid, a)
            except ErroSocial as e:
                erros.append(str(e))
        self._evento('grupo', gid=gid)
        return gid, erros

    def grupo_convidar(self, gid, addr):
        g = self._g_admin(gid)
        addr = str(addr or '').strip().upper()
        if not RE_ADDR.match(addr):
            raise ErroSocial('Chave inválida.')
        pub = addr[:64]
        if pub in g['membros']:
            raise ErroSocial('Esta pessoa já está no grupo.')
        if len(g['membros']) >= MAX_MEMBROS:
            raise ErroSocial('O grupo atingiu o limite de membros.')
        with self.L:
            self.t['ajustes']['convites_env'][f"{pub}:{gid}"] = {
                'gid': gid, 'addr': addr, 'ts': agora()}
            self.banco.sujar('ajustes')
        if pub not in self.t['contatos']:
            self._link(addr, 'convite:' + gid)
        self._entregar(pub, dict(self._estado_fio(g), tipo='grupo_convite'))

    def _estado_valido(self, m):
        try:
            gid = str(m['gid'])
            membros = m['membros']
            if not RE_ID.match(gid) or not isinstance(membros, dict) \
                    or not 1 <= len(membros) <= MAX_MEMBROS:
                return None
            lim = {}
            for pub, v in membros.items():
                pub, addr = str(pub).upper(), str(v.get('addr', '')).upper()
                if not RE_HEX64.match(pub) or not RE_ADDR.match(addr) \
                        or addr[:64] != pub:
                    return None
                lim[pub] = {'addr': addr, 'nome': limpar(v.get('nome'), 40),
                            'sobrenome': limpar(v.get('sobrenome'), 60)}
            admins = [str(a).upper() for a in m['admins'] if str(a).upper() in lim]
            dono = str(m['dono']).upper()
            if dono not in lim or dono not in admins:
                return None
            nome = limpar(m['nome'], 60)
            if not nome:
                return None
            return {'gid': gid, 'nome': nome, 'desc': limpar(m.get('desc'), 300),
                    'dono': dono, 'admins': admins, 'membros': lim,
                    'versao': int(m['versao'])}
        except Exception:
            return None

    def _h_grupo_convite(self, pub, m):
        e = self._estado_valido(m)
        if not e or pub not in e['admins'] or pub not in e['membros']:
            return
        if not self._limite(pub, 'convite', 10):
            return
        g = self.t['grupos'].get(e['gid'])
        if g and g['estado'] == 'ativo':
            return
        with self.L:
            if len(self.t['convites']) >= 50 and e['gid'] not in self.t['convites']:
                return
            self.t['convites'][e['gid']] = {'gid': e['gid'], 'de': pub,
                                            'estado': e, 'ts': agora()}
            self.banco.sujar('convites')
        self._evento('convite', gid=e['gid'])

    def listar_convites(self):
        return [{'gid': c['gid'], 'nome': c['estado']['nome'],
                 'desc': c['estado']['desc'], 'de': self.nome_de(c['de']),
                 'membros': len(c['estado']['membros']), 'ts': c['ts']}
                for c in self.t['convites'].values()]

    def aceitar_convite(self, gid):
        with self.L:
            c = self.t['convites'].pop(gid, None)
            self.banco.sujar('convites')
            if not c:
                raise ErroSocial('Convite não encontrado.')
            e = c['estado']
            e['membros'][self.pub()] = self._eu_membro()
            e.update(estado='ativo', ts=agora())
            self.t['grupos'][gid] = e
            self.banco.sujar('grupos')
            self._sistema(gid, 'Você entrou no grupo')
        p = self.t['perfil']
        self._entregar(c['de'], {'tipo': 'grupo_aceito', 'gid': gid,
                                 'addr': self.addr(), 'nome': p['nome'],
                                 'sobrenome': p['sobrenome']})
        self._garantir_vinculos()
        self._evento('grupo', gid=gid)

    def recusar_convite(self, gid):
        with self.L:
            self.t['convites'].pop(gid, None)
            self.banco.sujar('convites')
        self._evento('convite', gid=gid)

    def _h_grupo_aceito(self, pub, m):
        gid = str(m.get('gid', ''))
        g = self.t['grupos'].get(gid)
        k = f"{pub}:{gid}"
        env = self.t['ajustes']['convites_env'].get(k)
        if not g or g['estado'] != 'ativo' or self.pub() not in g['admins'] \
                or not env or pub in g['membros'] \
                or len(g['membros']) >= MAX_MEMBROS:
            return
        with self.L:
            pe = self.t['pessoas'].get(pub, {})
            g['membros'][pub] = {
                'addr': env['addr'],
                'nome': limpar(m.get('nome'), 40) or pe.get('nome', ''),
                'sobrenome': limpar(m.get('sobrenome'), 60)
                or pe.get('sobrenome', '')}
            g['versao'] += 1
            self.t['ajustes']['convites_env'].pop(k, None)
            self.banco.sujar('grupos')
            self.banco.sujar('ajustes')
            self._sistema(gid, 'Entrou: ' + self.nome_de(pub))
        self._difundir_estado(g)
        self._evento('grupo', gid=gid)

    def _difundir_estado(self, g):
        fio = dict(self._estado_fio(g), tipo='grupo_estado')
        for p in g['membros']:
            if p != self.pub():
                self._entregar(p, fio)
        self._garantir_vinculos()

    def _h_grupo_estado(self, pub, m):
        g = self.t['grupos'].get(str(m.get('gid', '')))
        if not g or g['estado'] != 'ativo' or pub not in g['admins']:
            return
        e = self._estado_valido(m)
        if not e or e['versao'] <= g['versao']:
            return
        with self.L:
            antigos = set(g['membros'])
            if self.pub() not in e['membros']:
                g['estado'] = 'removido'
                self._sistema(g['gid'], 'Você foi removido do grupo')
            else:
                for p in set(e['membros']) - antigos:
                    self._sistema(g['gid'], 'Entrou: ' + (
                        (e['membros'][p]['nome'] + ' ' + e['membros'][p]['sobrenome']).strip()
                        or 'Usuário ' + p[:8]))
                for p in antigos - set(e['membros']):
                    self._sistema(g['gid'], 'Saiu: ' + self.nome_de(p))
                for p, v in e['membros'].items():
                    if not v['nome'] and p in g['membros']:
                        v['nome'] = g['membros'][p].get('nome', '')
                        v['sobrenome'] = g['membros'][p].get('sobrenome', '')
                g.update(nome=e['nome'], desc=e['desc'], dono=e['dono'],
                         admins=e['admins'], membros=e['membros'],
                         versao=e['versao'])
            self.banco.sujar('grupos')
        self._garantir_vinculos()
        for p in e['membros']:
            if p != self.pub() and p not in antigos and self._online(p):
                self._enviar_perfil(p)
        self._evento('grupo', gid=g['gid'])

    def _h_grupo_sair(self, pub, m):
        g = self.t['grupos'].get(str(m.get('gid', '')))
        if not g or g['estado'] != 'ativo' or pub not in g['membros']:
            return
        with self.L:
            self._tirar_membro(g, pub)
            self._sistema(g['gid'], 'Saiu: ' + self.nome_de(pub))
            self.banco.sujar('grupos')
        self._evento('grupo', gid=g['gid'])

    def _tirar_membro(self, g, pub):
        g['membros'].pop(pub, None)
        if pub in g['admins']:
            g['admins'].remove(pub)
        if g['dono'] == pub and g['membros']:
            novo = sorted(g['admins'])[0] if g['admins'] \
                else sorted(g['membros'])[0]
            if novo not in g['admins']:
                g['admins'].append(novo)
            g['dono'] = novo

    def _h_grupo_removido(self, pub, m):
        g = self.t['grupos'].get(str(m.get('gid', '')))
        if g and g['estado'] == 'ativo' and pub in g['admins']:
            with self.L:
                g['estado'] = 'removido'
                self._sistema(g['gid'], 'Você foi removido do grupo')
                self.banco.sujar('grupos')
            self._evento('grupo', gid=g['gid'])

    def grupo_remover(self, gid, pub):
        g = self._g_admin(gid)
        pub = str(pub).upper()
        if pub not in g['membros'] or pub == self.pub():
            raise ErroSocial('Membro inválido.')
        if pub == g['dono'] or (pub in g['admins'] and self.pub() != g['dono']):
            raise ErroSocial('Só o dono remove administradores.')
        nome = self.nome_de(pub)
        with self.L:
            self._tirar_membro(g, pub)
            g['versao'] += 1
            self._sistema(gid, 'Removido: ' + nome)
            self.banco.sujar('grupos')
        self._entregar(pub, {'tipo': 'grupo_removido', 'gid': gid})
        self._difundir_estado(g)
        self._evento('grupo', gid=gid)

    def grupo_admin(self, gid, pub, admin):
        g = self._g_admin(gid)
        pub = str(pub).upper()
        if pub not in g['membros']:
            raise ErroSocial('Membro inválido.')
        if not admin and (self.pub() != g['dono'] or pub == g['dono']):
            raise ErroSocial('Só o dono rebaixa administradores.')
        with self.L:
            if admin and pub not in g['admins']:
                g['admins'].append(pub)
            elif not admin and pub in g['admins']:
                g['admins'].remove(pub)
            g['versao'] += 1
            self._sistema(gid, ('Novo administrador: ' if admin
                                else 'Deixou de ser administrador: ')
                          + self.nome_de(pub))
            self.banco.sujar('grupos')
        self._difundir_estado(g)
        self._evento('grupo', gid=gid)

    def grupo_editar(self, gid, nome=None, desc=None):
        g = self._g_admin(gid)
        with self.L:
            if nome is not None:
                n = limpar(nome, 60)
                if not n:
                    raise ErroSocial('Dê um nome ao grupo.')
                g['nome'] = n
            if desc is not None:
                g['desc'] = limpar(desc, 300)
            g['versao'] += 1
            self.banco.sujar('grupos')
        self._difundir_estado(g)
        self._evento('grupo', gid=gid)

    def grupo_sair(self, gid):
        g = self.t['grupos'].get(gid)
        if not g or g['estado'] != 'ativo':
            raise ErroSocial('Grupo não encontrado.')
        for p in g['membros']:
            if p != self.pub():
                self._entregar(p, {'tipo': 'grupo_sair', 'gid': gid})
        with self.L:
            g['estado'] = 'saiu'
            self._sistema(gid, 'Você saiu do grupo')
            self.banco.sujar('grupos')
        self._evento('grupo', gid=gid)

    def listar_grupos(self):
        return [{'gid': g['gid'], 'nome': g['nome'], 'desc': g['desc'],
                 'estado': g['estado'], 'membros': len(g['membros']),
                 'admin': self.pub() in g['admins']}
                for g in self.t['grupos'].values()]

    def grupo_info(self, gid):
        g = self.t['grupos'].get(gid)
        if not g:
            raise ErroSocial('Grupo não encontrado.')
        mem = []
        for pub, v in g['membros'].items():
            mem.append({'pub': pub, 'eu': pub == self.pub(),
                        'nome': self.nome_de(pub) if pub != self.pub()
                        else self._nome_completo(),
                        'foto_mini': self._mini_de(pub) if pub != self.pub()
                        else self.t['perfil']['foto_mini'],
                        'admin': pub in g['admins'], 'dono': pub == g['dono'],
                        'contato': pub in self.t['contatos'],
                        'online': (self.online_visivel(pub) if pub in self.t['contatos']
                                   else self._online(pub)) if pub != self.pub() else True,
                        'addr': v['addr']})
        mem.sort(key=lambda x: (not x['dono'], not x['admin'], x['nome'].lower()))
        return {'gid': gid, 'nome': g['nome'], 'desc': g['desc'],
                'estado': g['estado'], 'versao': g['versao'], 'membros': mem,
                'sou_admin': self.pub() in g['admins'],
                'sou_dono': self.pub() == g['dono']}

    # ═══ painel / rede / exportar ════════════════════════════════════
    def estado(self):
        amigos = self.no.listar_amigos()
        p = self.t['perfil']
        return {'login': self.login, 'addr': self.addr(), 'pub': self.pub(),
                'rede': self.no.status_rede(),
                'conectados': sum(1 for a in amigos if a['status']),
                'diretorio': self.rede.contagem(),
                'pedidos': len(self.t['pedidos']),
                'convites': len(self.t['convites']),
                'nao_lidas': sum(c['nao_lidas'] for c in self.t['convs'].values()),
                'fila': len(self.t['outbox']),
                'perfil': {'nome': p['nome'], 'sobrenome': p['sobrenome'],
                           'foto_mini': p['foto_mini']},
                'relay_tcp': self.no.tcp_porta, 'nos_tox': len(carregar_nos(self.arq_nos)),
                'catalogo': self.cat.contagem(),
                'cache': self.ent.cache_info(),
                'invisivel': self.t['ajustes']['invisivel']}

    def adicionar_no_manual(self, ip, porta, chave, tcp=0):
        chave = str(chave).strip().upper()
        try:
            porta, tcp = int(porta), int(tcp or 0)
        except (TypeError, ValueError):
            raise ErroSocial('Porta inválida.')
        if not RE_HEX64.match(chave) or not str(ip).strip() \
                or not 1 <= porta <= 65535:
            raise ErroSocial('Informe IP, porta e a chave pública do nó (64 hex).')
        no = {'ip': str(ip).strip(), 'porta': porta, 'chave_publica': chave,
              'tcp_ports': [tcp] if tcp else []}
        mesclar_nos(self.arq_nos, [no])
        self.no.bootstrap_simples([no])

    def atualizar_nos(self):
        ok, n = atualizar_nos_online(self.arq_nos)
        if not ok:
            raise ErroSocial('Sem acesso à lista online. Use Importar com um '
                             'arquivo exportado por alguém.')
        carregar = carregar_nos(self.arq_nos)
        self.no.bootstrap_simples(carregar)
        return n

    def exportar(self, cats):
        doc = {'formato': 'rrfs-social', 'versao': 1, 'categorias': {}}
        if 'rede' in cats:
            doc['categorias']['rede'] = self.rede.exportar()
        if 'catalogo' in cats:
            doc['categorias']['catalogo'] = self.cat.exportar()
        if 'nos' in cats:
            doc['categorias']['nos'] = carregar_nos(self.arq_nos)
        return doc

    def importar(self, doc, cats):
        if not isinstance(doc, dict) or doc.get('formato') != 'rrfs-social':
            raise ErroSocial('Arquivo não é uma exportação do RRFS Social.')
        c, res = doc.get('categorias') or {}, {}
        if 'rede' in cats and isinstance(c.get('rede'), dict):
            res['rede'] = self.rede.importar(c['rede'])
            for d in self.rede.hints_recentes(80):
                self.no.aplicar_dica(d)
        if 'catalogo' in cats and isinstance(c.get('catalogo'), dict):
            res['catalogo'] = self.cat.importar(c['catalogo'])
        if 'nos' in cats and isinstance(c.get('nos'), list):
            res['nos'] = {'novos': mesclar_nos(self.arq_nos, c['nos'])}
            self.no.bootstrap_simples(carregar_nos(self.arq_nos))
        return res
