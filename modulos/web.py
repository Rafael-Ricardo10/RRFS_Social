# -*- coding: utf-8 -*-
"""RRFS Social - servidor web LOCAL (127.0.0.1) com a API usada pelas telas
em templates/. Contas: senha -> chave (scrypt) -> tudo cifrado em disco."""
import os
import re
import json
import time
import secrets
import shutil
import zipfile
import tempfile
import threading
from datetime import datetime
from urllib.parse import quote

from flask import Flask, request, Response, jsonify, redirect

from .util import log, RE_LOGIN, RE_HEX64, RE_ID, MIMES_INLINE, limpar
from .cofre import Cofre, ErroCofre, derivar_chave
from .social import Social, MAX_ARQ
from .util import ErroSocial
from .tunel import Remoto, RE_CODIGO

SESSAO_HORAS = 24 * 7
VERIFICADOR = b'RRFS-SOCIAL-OK'


class ErroApi(Exception):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


class Estado:
    """Uma conta ativa por vez neste computador."""

    def __init__(self, raiz, criar_no=None):
        self.raiz, self.criar_no = raiz, criar_no
        self.social = None
        self.login = None
        self.sessoes = {}
        self.falhas = {}
        self.trava = threading.RLock()
        self.executor = None
        self._tok_int = None
        from .rede import Rede
        self.rede = Rede(raiz)
        from .catalogo import Catalogo
        self.cat = Catalogo(raiz)

    def token_interno(self):
        if not self.valida(self._tok_int):
            self._tok_int = self._nova_sessao()
        return self._tok_int

    def _ligar(self, soc):
        soc.tunel.exec = self.executor

    def vincular(self, codigo, login, senha, nome):
        m = RE_CODIGO.match(str(codigo or '').strip())
        login = str(login or '').strip().lower()
        if not m:
            raise ErroApi('Código inválido. Gere um novo no aparelho principal (Conta > Dispositivos).')
        if not RE_LOGIN.match(login):
            raise ErroApi('Usuário: 3 a 32 letras minúsculas, números, _ . -')
        if len(str(senha)) < 8:
            raise ErroApi('A senha deste aparelho precisa ter 8 caracteres ou mais.')
        nome = limpar(nome, 40) or 'Dispositivo'
        with self.trava:
            if self.social:
                raise ErroApi('Encerre a sessão atual antes de vincular.')
            pasta = self._pasta(login)
            if os.path.exists(os.path.join(pasta, 'verificador.dat')):
                raise ErroApi('Este usuário já existe neste computador.')
            os.makedirs(pasta, mode=0o700, exist_ok=True)
            sal = os.urandom(16)
            with open(os.path.join(pasta, 'sal.bin'), 'wb') as f:
                f.write(sal)
            cofre = Cofre(derivar_chave(senha, sal))
            rem = None
            try:
                rem = Remoto(pasta, cofre, self.raiz, m.group(1), self.criar_no)
                ok = rem.parear(m.group(2), nome)
            except Exception:
                log.exception("vincular dispositivo")
                ok = False
            if not ok:
                if rem:
                    try:
                        rem.parar()
                    except Exception:
                        pass
                shutil.rmtree(pasta, ignore_errors=True)
                raise ErroApi('Não consegui falar com o aparelho principal. Confira o código '
                              '(vale 10 minutos) e se ele está ligado e conectado.')
            cofre.salvar_json(os.path.join(pasta, 'remoto.dat'), {'addr': m.group(1), 'nome': nome})
            cofre.gravar_bytes(os.path.join(pasta, 'verificador.dat'), VERIFICADOR)
            self.social, self.login = rem, login
            return self._nova_sessao()

    def contas(self):
        base = os.path.join(self.raiz, 'contas')
        if not os.path.isdir(base):
            return []
        return sorted(d for d in os.listdir(base) if os.path.exists(
            os.path.join(base, d, 'verificador.dat')))

    def _pasta(self, login):
        return os.path.join(self.raiz, 'contas', login)

    def criar_conta(self, login, senha, nome, sobrenome):
        login = str(login or '').strip().lower()
        if not RE_LOGIN.match(login):
            raise ErroApi('Usuário: 3 a 32 letras minúsculas, números, _ . -')
        if len(str(senha)) < 8:
            raise ErroApi('A senha precisa ter 8 caracteres ou mais.')
        if not limpar(nome, 40):
            raise ErroApi('Informe o seu nome.')
        with self.trava:
            if self.social:
                raise ErroApi('Encerre a sessão atual antes de criar outra conta.')
            pasta = self._pasta(login)
            if os.path.exists(os.path.join(pasta, 'verificador.dat')):
                raise ErroApi('Este usuário já existe neste computador.')
            os.makedirs(pasta, mode=0o700, exist_ok=True)
            sal = os.urandom(16)
            with open(os.path.join(pasta, 'sal.bin'), 'wb') as f:
                f.write(sal)
            cofre = Cofre(derivar_chave(senha, sal))
            soc = Social(self.raiz, login, cofre, self.rede, self.criar_no, self.cat)
            soc.atualizar_perfil({'nome': nome, 'sobrenome': sobrenome})
            soc.banco.salvar_tudo()
            self._ligar(soc)
            soc.iniciar()
            cofre.gravar_bytes(os.path.join(pasta, 'verificador.dat'),
                               VERIFICADOR)
            self.social, self.login = soc, login
            return self._nova_sessao()

    def entrar(self, login, senha, ip):
        login = str(login or '').strip().lower()
        t = time.time()
        f = self.falhas.get(ip, [0, 0])
        if f[1] > t:
            raise ErroApi('Muitas tentativas. Aguarde %ds.' % int(f[1] - t), 429)
        pasta = self._pasta(login)
        ok = False
        cofre = None
        try:
            if RE_LOGIN.match(login):
                with open(os.path.join(pasta, 'sal.bin'), 'rb') as fs:
                    sal = fs.read()
                cofre = Cofre(derivar_chave(senha, sal))
                ok = cofre.ler_bytes(os.path.join(pasta, 'verificador.dat')) \
                    == VERIFICADOR
        except (OSError, ErroCofre):
            ok = False
        if not ok:
            n = f[0] + 1
            self.falhas[ip] = [n, t + (0 if n < 5 else min(300, 15 * 2 ** (n - 5)))]
            time.sleep(0.6)
            raise ErroApi('Usuário ou senha incorretos.', 401)
        self.falhas.pop(ip, None)
        with self.trava:
            if self.social and self.login != login:
                raise ErroApi('Há outra conta aberta. Saia dela primeiro.')
            if not self.social:
                rem = cofre.ler_json(os.path.join(pasta, 'remoto.dat'), None)
                if rem:                       # conta vinculada: tela remota do principal
                    self.social = Remoto(pasta, cofre, self.raiz, rem['addr'], self.criar_no)
                    self.social.garantir_vinculo()
                else:
                    self.social = Social(self.raiz, login, cofre, self.rede,
                                         self.criar_no, self.cat)
                    self._ligar(self.social)
                    self.social.iniciar()
                self.login = login
            return self._nova_sessao()

    def _nova_sessao(self):
        tok = secrets.token_urlsafe(32)
        self.sessoes[tok] = time.time() + SESSAO_HORAS * 3600
        return tok

    def valida(self, tok):
        exp = self.sessoes.get(tok or '')
        if exp and exp > time.time() and self.social:
            return True
        self.sessoes.pop(tok or '', None)
        return False

    def sair(self):
        with self.trava:
            s, self.social, self.login = self.social, None, None
            self.sessoes.clear()
        if s:
            s.parar()


def criar_app(raiz_dados, raiz_app, porta, criar_no=None, host='127.0.0.1'):
    E = Estado(raiz_dados, criar_no)
    pasta_tpl = os.path.join(raiz_app, 'templates')
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = MAX_ARQ + 1024 * 1024
    hosts_ok = {f'127.0.0.1:{porta}', f'localhost:{porta}', f'[::1]:{porta}'}
    publicos = ('/api/contas', '/api/login', '/api/criar_conta', '/api/sessao',
                '/api/vincular', '/api/restaurar')
    locais_remoto = ('/api/contas', '/api/login', '/api/logout', '/api/criar_conta',
                     '/api/sessao', '/api/vincular', '/api/restaurar', '/api/remoto/estado')

    def S():
        return E.social

    def ok(**kw):
        return jsonify(dict(ok=True, **kw))

    def corpo():
        return request.get_json(silent=True) or {}

    @app.errorhandler(ErroApi)
    def _e1(e):
        r = jsonify({'erro': str(e)})
        r.status_code = e.status
        return r

    @app.errorhandler(ErroSocial)
    def _e2(e):
        r = jsonify({'erro': str(e)})
        r.status_code = 400
        return r

    @app.errorhandler(413)
    def _e3(e):
        return jsonify({'erro': 'Arquivo grande demais.'}), 413

    @app.errorhandler(Exception)
    def _e4(e):
        if hasattr(e, 'code') and isinstance(e.code, int):
            return jsonify({'erro': getattr(e, 'description', 'Erro')}), e.code
        log.exception("erro na API")
        return jsonify({'erro': 'Erro interno.'}), 500

    def proxiar():
        qs = request.query_string.decode()
        caminho = request.path + ('?' + qs if qs else '')
        espera = 40 if request.path == '/api/eventos' else 70
        try:
            st, hs, gen = E.social.proxy(request.method, caminho, request.content_type,
                                         request.headers.get('Range'), request.stream,
                                         request.content_length or 0, espera)
        except ErroSocial as e:
            return jsonify({'erro': str(e)}), 503
        return Response(gen, status=st, headers=hs)

    @app.before_request
    def protecoes():
        if request.host not in hosts_ok and host in ('127.0.0.1', 'localhost'):
            return Response('Host não permitido', 403)
        if request.path.startswith('/api/'):
            sfs = request.headers.get('Sec-Fetch-Site')
            if sfs and sfs not in ('same-origin', 'none'):
                return jsonify({'erro': 'Origem não permitida'}), 403
            if request.method != 'GET' and request.headers.get('X-RRFS') != '1':
                return jsonify({'erro': 'Requisição inválida'}), 403
            if request.path not in publicos and \
                    not E.valida(request.cookies.get('rrfs_sessao')):
                return jsonify({'erro': 'Sessão expirada'}), 401
            if getattr(E.social, 'remoto', False) and request.path not in locais_remoto:
                return proxiar()

    @app.after_request
    def cabecalhos(r):
        r.headers.setdefault('Cache-Control', 'no-store')
        # só /entretenimento pode ser incorporada, e só pelo próprio app
        embutivel = request.path in ('/entretenimento', '/social')
        r.headers['X-Frame-Options'] = 'SAMEORIGIN' if embutivel else 'DENY'
        r.headers['X-Content-Type-Options'] = 'nosniff'
        r.headers['Referrer-Policy'] = 'no-referrer'
        if not request.path.startswith('/api/midia/'):
            r.headers['Content-Security-Policy'] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                "media-src 'self' blob:; frame-ancestors "
                + ("'self'" if embutivel else "'none'"))
        return r

    # ── páginas (HTML em templates/) ─────────────────────────────
    def pagina(nome):
        p = os.path.join(pasta_tpl, nome)
        if not os.path.exists(p):
            return Response(f'Falta o arquivo templates/{nome}.', 500,
                            mimetype='text/plain; charset=utf-8')
        with open(p, 'rb') as f:
            return Response(f.read(), mimetype='text/html')

    @app.route('/')
    def raiz():
        if E.valida(request.cookies.get('rrfs_sessao')):
            return pagina('app.html')
        return pagina('login.html')

    # ── sessão / contas ─────────────────────────────────────────
    def cookie(tok):
        r = ok()
        r.set_cookie('rrfs_sessao', tok, httponly=True, samesite='Strict',
                     max_age=SESSAO_HORAS * 3600, path='/')
        return r

    @app.route('/api/contas')
    def api_contas():
        return jsonify({'contas': E.contas(), 'aberta': E.login})

    @app.route('/api/sessao')
    def api_sessao():
        return jsonify({'logado': E.valida(request.cookies.get('rrfs_sessao')),
                        'login': E.login})

    @app.route('/api/criar_conta', methods=['POST'])
    def api_criar():
        d = corpo()
        return cookie(E.criar_conta(d.get('login'), d.get('senha', ''),
                                    d.get('nome'), d.get('sobrenome')))

    @app.route('/api/login', methods=['POST'])
    def api_login():
        d = corpo()
        return cookie(E.entrar(d.get('login'), d.get('senha', ''),
                               request.remote_addr or '?'))

    @app.route('/api/logout', methods=['POST'])
    def api_logout():
        E.sair()
        r = ok()
        r.delete_cookie('rrfs_sessao', path='/')
        return r

    @app.route('/api/estado')
    def api_estado():
        return jsonify(S().estado())

    @app.route('/api/eventos')
    def api_eventos():
        try:
            desde = int(request.args.get('desde', 0))
        except ValueError:
            desde = 0
        ev, n = S().esperar_eventos(desde, 20)
        return jsonify({'eventos': ev, 'n': n})

    # ── perfil ──────────────────────────────────────────────────
    @app.route('/api/perfil', methods=['GET', 'POST'])
    def api_perfil():
        if request.method == 'POST':
            S().atualizar_perfil(corpo())
        p = S().perfil_proprio()
        return jsonify({'perfil': {k: p[k] for k in (
            'nome', 'sobrenome', 'bio', 'foto_mid', 'capa_mid', 'foto_mini',
            'visivel', 'addr', 'pub')}})

    # ── contatos / busca ────────────────────────────────────────
    @app.route('/api/contatos')
    def api_contatos():
        return jsonify({'contatos': S().listar_contatos(),
                        'pedidos': S().listar_pedidos()})

    @app.route('/api/contatos/adicionar', methods=['POST'])
    def api_c_add():
        S().adicionar_contato(corpo().get('addr'))
        return ok()

    @app.route('/api/contatos/aceitar', methods=['POST'])
    def api_c_ace():
        S().aceitar_pedido(corpo().get('pub'))
        return ok()

    @app.route('/api/contatos/recusar', methods=['POST'])
    def api_c_rec():
        d = corpo()
        S().recusar_pedido(d.get('pub'), bool(d.get('bloquear')))
        return ok()

    @app.route('/api/contatos/remover', methods=['POST'])
    def api_c_rem():
        S().remover_contato(corpo().get('pub'))
        return ok()

    @app.route('/api/contatos/bloquear', methods=['POST'])
    def api_c_blo():
        S().bloquear(corpo().get('pub'))
        return ok()

    @app.route('/api/contato/<pub>')
    def api_contato(pub):
        return jsonify(S().contato_info(pub))

    @app.route('/api/buscar')
    def api_buscar():
        return jsonify(S().buscar(request.args.get('q', '')))

    # ── conversas ───────────────────────────────────────────────
    @app.route('/api/conversas')
    def api_conversas():
        return jsonify({'conversas': S().listar_conversas()})

    @app.route('/api/conversa/<cid>')
    def api_conversa(cid):
        try:
            lim = int(request.args.get('limite', 60))
        except ValueError:
            lim = 60
        return jsonify({'mensagens': S().mensagens(
            cid, request.args.get('antes'), lim)})

    @app.route('/api/lido', methods=['POST'])
    def api_lido():
        S().marcar_lido(str(corpo().get('cid', '')))
        return ok()

    @app.route('/api/enviar', methods=['POST'])
    def api_enviar():
        d = corpo()
        return ok(id=S().enviar_texto(str(d.get('cid', '')), d.get('texto')))

    @app.route('/api/enviar_arquivo', methods=['POST'])
    def api_enviar_arq():
        cid = str(request.form.get('cid', ''))
        f = request.files.get('arquivo')
        if not f:
            raise ErroApi('Escolha um arquivo.')
        S()._destinos(cid)
        mid, esc = S().iniciar_upload()
        try:
            while True:
                ch = f.stream.read(256 * 1024)
                if not ch:
                    break
                esc.escrever(ch)
                if esc.tam > MAX_ARQ:
                    raise ErroApi('Arquivo grande demais (máx. 2 GB).')
            S().concluir_upload(mid, esc, f.filename,
                                f.mimetype or 'application/octet-stream')
        except Exception:
            esc.cancelar()
            raise
        return ok(id=S().enviar_arquivo(cid, mid, request.form.get('legenda', '')))

    @app.route('/api/baixar', methods=['POST'])
    def api_baixar():
        d = corpo()
        S().baixar_manual(str(d.get('cid', '')), str(d.get('mid', '')))
        return ok()

    @app.route('/api/midia/<mid>')
    def api_midia(mid):
        if not re.match(r'^[0-9a-f]{16}$', mid):
            raise ErroApi('Mídia inválida.', 404)
        meta, caminho = S().midia_meta(mid)
        if not meta:
            raise ErroApi('Arquivo não encontrado.', 404)
        tam = int(meta['tam'])
        ini, fim, st = 0, tam - 1, 200
        rng = request.headers.get('Range', '')
        m = re.match(r'^bytes=(\d*)-(\d*)$', rng)
        if m and tam and (m.group(1) or m.group(2)):
            if m.group(1):
                ini = int(m.group(1))
                fim = int(m.group(2)) if m.group(2) else tam - 1
            else:
                ini, fim = max(0, tam - int(m.group(2))), tam - 1
            fim = min(fim, tam - 1)
            if ini > fim:
                return Response(status=416, headers={
                    'Content-Range': f'bytes */{tam}'})
            st = 206
        mime = meta['mime']
        h = {'Content-Type': mime, 'Accept-Ranges': 'bytes',
             'Content-Length': str(max(0, fim - ini + 1)),
             'Content-Security-Policy': "default-src 'none'; sandbox",
             'Cache-Control': 'private, max-age=3600'}
        if st == 206:
            h['Content-Range'] = f'bytes {ini}-{fim}/{tam}'
        disp = 'inline' if mime in MIMES_INLINE else 'attachment'
        h['Content-Disposition'] = \
            f"{disp}; filename*=UTF-8''{quote(meta['nome'])}"
        gen = S().cofre.ler_arquivo(caminho, ini, fim + 1) if tam else iter(())
        return Response(gen, status=st, headers=h)

    # ── grupos ──────────────────────────────────────────────────
    @app.route('/api/grupos')
    def api_grupos():
        return jsonify({'grupos': S().listar_grupos(),
                        'convites': S().listar_convites()})

    @app.route('/api/grupos/criar', methods=['POST'])
    def api_g_criar():
        d = corpo()
        gid, erros = S().criar_grupo(d.get('nome'), d.get('desc', ''),
                                     d.get('membros') or [])
        return ok(gid=gid, avisos=erros)

    @app.route('/api/grupo/<gid>')
    def api_g_info(gid):
        return jsonify(S().grupo_info(gid))

    @app.route('/api/grupo/<gid>/<acao>', methods=['POST'])
    def api_g_acao(gid, acao):
        d = corpo()
        if acao == 'convidar':
            S().grupo_convidar(gid, d.get('addr'))
        elif acao == 'remover':
            S().grupo_remover(gid, d.get('pub'))
        elif acao == 'admin':
            S().grupo_admin(gid, d.get('pub'), bool(d.get('admin')))
        elif acao == 'editar':
            S().grupo_editar(gid, d.get('nome'), d.get('desc'))
        elif acao == 'sair':
            S().grupo_sair(gid)
        else:
            raise ErroApi('Ação inválida.', 404)
        return ok()

    @app.route('/api/convites/<acao>', methods=['POST'])
    def api_convites(acao):
        gid = str(corpo().get('gid', ''))
        if acao == 'aceitar':
            S().aceitar_convite(gid)
        elif acao == 'recusar':
            S().recusar_convite(gid)
        else:
            raise ErroApi('Ação inválida.', 404)
        return ok()

    # ── status (24 h) ───────────────────────────────────────────
    @app.route('/api/status', methods=['GET', 'POST'])
    def api_status():
        if request.method == 'GET':
            return jsonify({'status': S().listar_status()})
        mid = None
        f = request.files.get('arquivo')
        if f:
            mid, esc = S().iniciar_upload()
            try:
                while True:
                    ch = f.stream.read(256 * 1024)
                    if not ch:
                        break
                    esc.escrever(ch)
                    if esc.tam > 200 * 1048576:
                        raise ErroApi('Status aceita até 200 MB.')
                S().concluir_upload(mid, esc, f.filename,
                                    f.mimetype or 'application/octet-stream')
            except Exception:
                esc.cancelar()
                raise
        return ok(id=S().postar_status(request.form.get('texto', ''), mid))

    @app.route('/api/status/<sid>', methods=['DELETE'])
    def api_status_apagar(sid):
        S().apagar_status(sid)
        return ok()

    @app.route('/api/status/<sid>/visto', methods=['POST'])
    def api_status_visto(sid):
        S().marcar_status_visto(sid)
        return ok()

    # ── rede / exportar / importar ──────────────────────────────
    @app.route('/api/rede/no_manual', methods=['POST'])
    def api_no_manual():
        d = corpo()
        S().adicionar_no_manual(d.get('ip'), d.get('porta'), d.get('chave'),
                                d.get('tcp'))
        return ok()

    @app.route('/api/nos/atualizar', methods=['POST'])
    def api_nos():
        return ok(novos=S().atualizar_nos())

    @app.route('/api/exportar')
    def api_exportar():
        cats = [c for c in request.args.get('cats', 'rede,nos,catalogo').split(',')
                if c in ('rede', 'nos', 'catalogo')]
        nome = 'rrfs-social-%s.json' % datetime.now().strftime('%Y%m%d-%H%M')
        return Response(json.dumps(S().exportar(cats), ensure_ascii=False,
                                   indent=1),
                        mimetype='application/json',
                        headers={'Content-Disposition':
                                 f'attachment; filename={nome}'})

    @app.route('/api/importar', methods=['POST'])
    def api_importar():
        d = corpo()
        cats = [c for c in (d.get('categorias') or []) if c in ('rede', 'nos', 'catalogo')]
        return ok(resultado=S().importar(d.get('conteudo'), cats))

    def executar(metodo, caminho, ct, rg, corpo, n):
        c = app.test_client()
        c.set_cookie('rrfs_sessao', E.token_interno(), domain='localhost')
        h = {'X-RRFS': '1'}
        if rg:
            h['Range'] = rg
        kw = {}
        if ct:
            kw['content_type'] = ct
        if n:
            kw['input_stream'] = corpo
            kw['content_length'] = n
        return c.open(caminho, method=metodo, headers=h, base_url=f'http://localhost:{porta}',
                      buffered=False, **kw)
    E.executor = executar

    # ── vários dispositivos ─────────────────────────────────────
    @app.route('/api/vincular', methods=['POST'])
    def api_vincular():
        d = corpo()
        return cookie(E.vincular(d.get('codigo'), d.get('login'), d.get('senha', ''), d.get('nome')))

    @app.route('/api/remoto/estado')
    def api_remoto_estado():
        s = S()
        rem = bool(getattr(s, 'remoto', False))
        return jsonify({'remoto': rem, 'principal_online': s.online() if rem else True})

    def so_principal():
        if getattr(S(), 'remoto', False):
            raise ErroApi('Faça isso no aparelho principal.', 403)

    @app.route('/api/dispositivos')
    def api_dispositivos():
        so_principal()
        return jsonify({'dispositivos': S().tunel.lista()})

    @app.route('/api/dispositivos/codigo', methods=['POST'])
    def api_disp_codigo():
        so_principal()
        return ok(codigo=S().tunel.codigo(), validade=600)

    @app.route('/api/dispositivos/remover', methods=['POST'])
    def api_disp_remover():
        so_principal()
        S().tunel.remover(corpo().get('pub', ''))
        return ok()

    @app.route('/api/conta/backup')
    def api_backup():
        so_principal()
        s = S()
        s.banco.salvar_tudo()
        s.no.salvar()
        com_midia = request.args.get('midia', '1') == '1'
        os.makedirs(os.path.join(raiz_dados, 'tmp'), mode=0o700, exist_ok=True)
        tmp = os.path.join(raiz_dados, 'tmp', 'backup-%s.zip' % secrets.token_hex(4))
        with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_STORED) as z:
            z.writestr('LOGIN.txt', E.login)
            for dp, dns, fns in os.walk(s.pasta):
                dns[:] = [x for x in dns if x != 'tmp_live' and (com_midia or x not in ('midia', 'video'))]
                for fn in fns:
                    if not fn.endswith('.tmp'):
                        cam = os.path.join(dp, fn)
                        z.write(cam, os.path.relpath(cam, s.pasta))

        def gerar():
            try:
                with open(tmp, 'rb') as f:
                    while True:
                        b = f.read(1 << 20)
                        if not b:
                            break
                        yield b
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        nome = 'rrfs-backup-%s-%s.zip' % (E.login, datetime.now().strftime('%Y%m%d'))
        return Response(gerar(), mimetype='application/zip',
                        headers={'Content-Disposition': f'attachment; filename={nome}',
                                 'Content-Length': str(os.path.getsize(tmp))})

    PERMITIDO = re.compile(r'^(sal\.bin|verificador\.dat|identidade\.dat|[a-z_]{3,20}\.dat|LOGIN\.txt|'
                           r'conv/[0-9a-f]{32}\.dat|midia/[0-9a-f]{16}|video/[0-9a-f]{16}/[0-9]{1,7})$')

    @app.route('/api/restaurar', methods=['POST'])
    def api_restaurar():
        if E.social:
            raise ErroApi('Saia da conta atual antes de restaurar um backup.')
        f = request.files.get('arquivo')
        if not f:
            raise ErroApi('Escolha o arquivo de backup (.zip).')
        os.makedirs(os.path.join(raiz_dados, 'tmp'), mode=0o700, exist_ok=True)
        tmp = os.path.join(raiz_dados, 'tmp', 'restaurar-%s.zip' % secrets.token_hex(4))
        try:
            f.save(tmp)
            try:
                z = zipfile.ZipFile(tmp)
            except zipfile.BadZipFile:
                raise ErroApi('Arquivo de backup inválido.')
            with z:
                nomes = [i.filename for i in z.infolist() if not i.is_dir()]
                if any(not PERMITIDO.match(n) for n in nomes) or 'sal.bin' not in nomes \
                        or 'verificador.dat' not in nomes:
                    raise ErroApi('Este arquivo não é um backup do RRFS Social.')
                login = (request.form.get('login') or '').strip().lower()
                if not login and 'LOGIN.txt' in nomes:
                    login = z.read('LOGIN.txt').decode('utf-8', 'ignore').strip().lower()
                if not RE_LOGIN.match(login):
                    raise ErroApi('Informe um nome de usuário válido para este aparelho.')
                dest = E._pasta(login)
                if os.path.exists(dest):
                    raise ErroApi('Já existe um usuário "%s" neste computador.' % login)
                os.makedirs(dest, mode=0o700)
                try:
                    for n in nomes:
                        if n == 'LOGIN.txt':
                            continue
                        alvo = os.path.join(dest, n)
                        os.makedirs(os.path.dirname(alvo), mode=0o700, exist_ok=True)
                        with z.open(n) as src, open(alvo, 'wb') as out:
                            shutil.copyfileobj(src, out)
                        os.chmod(alvo, 0o600)
                except Exception:
                    shutil.rmtree(dest, ignore_errors=True)
                    raise
            return ok(login=login)
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass

    from .web_ent import registrar
    registrar(app, S, ok, corpo, ErroApi, pagina)
    from .web_soc import registrar as reg_soc
    reg_soc(app, S, ok, corpo, ErroApi, pagina)
    from .web_cham import registrar as reg_cham
    reg_cham(app, S, ok, corpo, ErroApi)
    app.estado_app = E
    return app
