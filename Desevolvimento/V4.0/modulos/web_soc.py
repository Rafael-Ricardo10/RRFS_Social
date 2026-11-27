# -*- coding: utf-8 -*-
"""RRFS Social - rotas HTTP da rede social (feed, publicações, perfil)."""
import re
from flask import request, jsonify, redirect

RE_KEY = re.compile(r'^[0-9A-F]{16}[0-9a-f]{16}$')
RE_PUB = re.compile(r'^[0-9A-Fa-f]{64}([0-9A-Fa-f]{12})?$')
MAX_FOTO = 25 * 1048576
MAX_VIDEO = 500 * 1048576


def registrar(app, S, ok, corpo, ErroApi, pagina):
    def P():
        return S().posts

    def key_ok(k):
        if not RE_KEY.match(k):
            raise ErroApi('Publicação inválida.', 404)
        return k

    @app.route('/social')
    def pg_social():
        if not S() or not request.cookies.get('rrfs_sessao'):
            return redirect('/')
        return pagina('social.html')

    def ler_upload(f, limite):
        s = S()
        mid, esc = s.iniciar_upload()
        try:
            while True:
                ch = f.stream.read(256 * 1024)
                if not ch:
                    break
                esc.escrever(ch)
                if esc.tam > limite:
                    raise ErroApi('Arquivo grande demais.')
            s.concluir_upload(mid, esc, f.filename, f.mimetype or 'application/octet-stream')
        except Exception:
            esc.cancelar()
            raise
        return mid

    @app.route('/api/soc/upload', methods=['POST'])
    def soc_upload():
        f = request.files.get('arquivo')
        if not f:
            raise ErroApi('Escolha um arquivo.')
        mid = ler_upload(f, MAX_VIDEO)
        meta = S().t['midia'][mid]
        if not (meta['mime'].startswith(('image/', 'video/'))):
            S().banco.apagar_midia(mid)
            raise ErroApi('Use fotos (JPEG, PNG, WebP, GIF) ou vídeo (MP4, WebM).')
        if meta['mime'].startswith('image/') and meta['tam'] > MAX_FOTO:
            S().banco.apagar_midia(mid)
            raise ErroApi('Foto grande demais (máx. 25 MB).')
        return ok(mid=mid, tipo=meta['mime'].split('/')[0])

    @app.route('/api/soc/feed')
    def soc_feed():
        return jsonify(P().feed(request.args.get('antes'), request.args.get('limite', 15)))

    @app.route('/api/soc/post', methods=['POST'])
    def soc_post():
        d = corpo()
        return ok(key=P().criar(d.get('texto', ''), d.get('mids') or [], d.get('vid'),
                                d.get('orig')))

    @app.route('/api/soc/post/<key>/editar', methods=['POST'])
    def soc_editar(key):
        d = corpo()
        P().editar(key_ok(key), d.get('texto', ''), d.get('manter'), d.get('mids') or [])
        return ok()

    @app.route('/api/soc/post/<key>', methods=['DELETE'])
    def soc_apagar(key):
        P().apagar(key_ok(key))
        return ok()

    @app.route('/api/soc/post/<key>/curtir', methods=['POST'])
    def soc_curtir(key):
        P().curtir(key_ok(key), bool(corpo().get('on')))
        return ok()

    @app.route('/api/soc/post/<key>/comentar', methods=['POST'])
    def soc_comentar(key):
        P().comentar(key_ok(key), corpo().get('texto', ''))
        return ok()

    @app.route('/api/soc/post/<key>/comentario/<cid>', methods=['DELETE'])
    def soc_capagar(key, cid):
        P().apagar_comentario(key_ok(key), cid)
        return ok()

    @app.route('/api/soc/post/<key>/compartilhar', methods=['POST'])
    def soc_compartilhar(key):
        return ok(key=P().criar(corpo().get('texto', ''), [], None, key_ok(key)))

    @app.route('/api/soc/video', methods=['POST'])
    def soc_video():
        d = corpo()
        return ok(key=P().criar(d.get('texto', ''), [], str(d.get('vid', ''))))

    @app.route('/api/soc/pessoa/<pub>')
    def soc_pessoa(pub):
        if not RE_PUB.match(pub):
            raise ErroApi('Pessoa inválida.', 404)
        s = S()
        pub = pub.upper()
        if pub[:64] == s.pub():
            p = s.perfil_proprio()
            return jsonify({'tipo': 'eu', 'pub': s.pub(), 'addr': s.addr(), 'nome': p['nome'],
                            'sobrenome': p['sobrenome'], 'bio': p['bio'],
                            'foto': p['foto_mid'], 'capa': p['capa_mid'],
                            'foto_mini': p['foto_mini'], 'posts': P().n_posts(s.pub()),
                            'amigos': len([c for c in s.listar_contatos()
                                           if c['estado'] == 'ativo'])})
        if pub[:64] in s.t['contatos'] and s.t['contatos'][pub[:64]]['estado'] == 'ativo':
            i = s.contato_info(pub[:64])
            i.update(tipo='amigo', posts=P().n_posts(pub[:64]))
            return jsonify(i)
        if len(pub) == 76:
            return jsonify(P().perfil_publico(pub))
        c = s.t['contatos'].get(pub[:64])
        if c and c.get('addr'):
            return jsonify(P().perfil_publico(c['addr']))
        raise ErroApi('Pessoa não encontrada. Use a busca por nome.', 404)

    @app.route('/api/soc/pessoa/<pub>/posts')
    def soc_pessoa_posts(pub):
        return jsonify(P().do_autor(pub[:64], request.args.get('antes'),
                                    request.args.get('limite', 15)))

    @app.route('/api/soc/pessoa/<pub>/fotos')
    def soc_pessoa_fotos(pub):
        return jsonify({'fotos': P().fotos(pub[:64])})

    @app.route('/api/soc/pessoa/<pub>/amigos')
    def soc_pessoa_amigos(pub):
        return jsonify({'amigos': P().amigos_de(pub[:64])})

    @app.route('/api/online')
    def api_online():
        return jsonify({'online': S().amigos_online()})

    @app.route('/api/privacidade', methods=['GET', 'POST'])
    def api_privacidade():
        return jsonify(S().privacidade(corpo() if request.method == 'POST' else None))
