# -*- coding: utf-8 -*-
"""RRFS Social - rotas HTTP do Entretenimento (vídeos, canais, lives)."""
import re
from flask import request, jsonify, Response, redirect

from .catalogo import CATEGORIAS

RE_ID = re.compile(r'^[0-9a-f]{16}$')


def registrar(app, S, ok, corpo, ErroApi, pagina):
    def E():
        return S().ent

    def vid_ok(v):
        if not RE_ID.match(v):
            raise ErroApi('Vídeo inválido.', 404)
        return v

    @app.route('/entretenimento')
    def pg_entretenimento():
        if not S() or not request.cookies.get('rrfs_sessao'):
            return redirect('/')
        return pagina('entretenimento.html')

    # ── navegação ───────────────────────────────────────────────
    @app.route('/api/ent/categorias')
    def ent_cats():
        return jsonify({'categorias': CATEGORIAS, 'cache': E().cache_info()})

    @app.route('/api/ent/inicio')
    def ent_inicio():
        return jsonify(E().inicio())

    @app.route('/api/ent/buscar')
    def ent_buscar():
        return jsonify(E().buscar(request.args.get('q', '')))

    @app.route('/api/ent/canal/<cid>')
    def ent_canal(cid):
        return jsonify(E().canal_info(vid_ok(cid)))

    @app.route('/api/ent/inscrever', methods=['POST'])
    def ent_inscrever():
        d = corpo()
        E().inscrever(vid_ok(str(d.get('cid', ''))), bool(d.get('on')))
        return ok()

    @app.route('/api/ent/inscricoes')
    def ent_inscricoes():
        return jsonify({'canais': E().inscricoes()})

    # ── meu canal / estúdio ─────────────────────────────────────
    @app.route('/api/ent/meu_canal', methods=['GET', 'POST'])
    def ent_meu_canal():
        if request.method == 'POST':
            E().salvar_canal(corpo())
        c = E().meu_canal()
        return jsonify({'canal': c, 'videos': E().meus_videos() if c else [],
                        'bloqueados': E().bloqueados(),
                        'rtmp_chave': (S().t['canal_meu'] or {}).get('rtmp')})

    @app.route('/api/ent/video/enviar', methods=['POST'])
    def ent_enviar():
        f = request.files.get('arquivo')
        if not f:
            raise ErroApi('Escolha um vídeo.')
        try:
            dur = int(float(request.form.get('dur') or 0))
        except ValueError:
            dur = 0
        vid = E().receber_video(
            f.stream.read, request.form.get('titulo', ''),
            request.form.get('desc', ''),
            [c for c in request.form.get('cats', '').split(',') if c], dur,
            request.form.get('thumb', ''))
        return ok(vid=vid)

    @app.route('/api/ent/video/<vid>', methods=['DELETE'])
    def ent_apagar(vid):
        E().apagar_video(vid_ok(vid))
        return ok()

    @app.route('/api/ent/bloquear', methods=['POST'])
    def ent_bloquear():
        d = corpo()
        if d.get('on', True):
            E().bloquear(d.get('pub'))
        else:
            E().desbloquear(d.get('pub'))
        return ok()

    # ── assistir ────────────────────────────────────────────────
    @app.route('/api/ent/video/<vid>/abrir', methods=['POST'])
    def ent_abrir(vid):
        vid_ok(vid)
        v = S().cat.videos.get(vid)
        info = E().abrir(vid)
        info['video'] = E()._card(v)
        info['desc'] = v['desc']
        info['mime_live'] = v['mime']
        return jsonify(info)

    @app.route('/api/ent/video/<vid>/estado')
    def ent_estado(vid):
        return jsonify(E().estado_video(vid_ok(vid)))

    def intervalo(tam):
        ini, fim, st = 0, tam - 1, 200
        m = re.match(r'^bytes=(\d*)-(\d*)$', request.headers.get('Range', ''))
        if m and tam and (m.group(1) or m.group(2)):
            if m.group(1):
                ini = int(m.group(1))
                fim = int(m.group(2)) if m.group(2) else tam - 1
            else:
                ini, fim = max(0, tam - int(m.group(2))), tam - 1
            fim = min(fim, tam - 1)
            st = 206
        return ini, fim, st

    @app.route('/api/ent/video/<vid>/stream')
    def ent_stream(vid):
        vid_ok(vid)
        mime, tam = E().mime_video(vid)
        if not tam:
            raise ErroApi('Vídeo ainda não está pronto.', 404)
        ini, fim, st = intervalo(tam)
        if ini > fim:
            return Response(status=416, headers={'Content-Range': f'bytes */{tam}'})
        h = {'Content-Type': mime, 'Accept-Ranges': 'bytes',
             'Content-Length': str(fim - ini + 1),
             'Content-Security-Policy': "default-src 'none'; sandbox",
             'Cache-Control': 'no-store'}
        if st == 206:
            h['Content-Range'] = f'bytes {ini}-{fim}/{tam}'
        return Response(E().ler_intervalo(vid, ini, fim), status=st, headers=h)

    @app.route('/api/ent/video/<vid>/peca/<int:idx>')
    def ent_peca(vid, idx):
        vid_ok(vid)
        try:
            d = E().obter_peca(vid, idx, timeout=30)
        except TimeoutError:
            raise ErroApi('Sem fontes disponíveis agora.', 504)
        return Response(d, mimetype='application/octet-stream',
                        headers={'Content-Security-Policy': "default-src 'none'; sandbox"})

    # ── votos, comentários, compartilhar ────────────────────────
    @app.route('/api/ent/video/<vid>/social')
    def ent_social(vid):
        return jsonify(E().social(vid_ok(vid)))

    @app.route('/api/ent/video/<vid>/voto', methods=['POST'])
    def ent_voto(vid):
        try:
            v = int(corpo().get('v', 0))
        except (TypeError, ValueError):
            v = 0
        E().votar(vid_ok(vid), v)
        return ok()

    @app.route('/api/ent/video/<vid>/comentar', methods=['POST'])
    def ent_comentar(vid):
        d = corpo()
        E().comentar(vid_ok(vid), d.get('texto'), d.get('resp', ''))
        return ok()

    @app.route('/api/ent/video/<vid>/comentario/<cid>/voto', methods=['POST'])
    def ent_cvoto(vid, cid):
        E().voto_comentario(vid_ok(vid), cid, bool(corpo().get('on')))
        return ok()

    @app.route('/api/ent/video/<vid>/comentario/<cid>', methods=['DELETE'])
    def ent_capagar(vid, cid):
        E().apagar_comentario(vid_ok(vid), cid)
        return ok()

    @app.route('/api/ent/compartilhar', methods=['POST'])
    def ent_compartilhar():
        d = corpo()
        S().enviar_video(str(d.get('cid', '')), vid_ok(str(d.get('vid', ''))))
        return ok()

    # ── live ────────────────────────────────────────────────────
    @app.route('/api/ent/live/iniciar', methods=['POST'])
    def ent_live_ini():
        d = corpo()
        vid = E().live_iniciar(d.get('titulo'), d.get('desc', ''),
                               d.get('cats') or [], d.get('mime'), d.get('thumb', ''))
        return ok(vid=vid)

    @app.route('/api/ent/live/<vid>/segmento', methods=['POST'])
    def ent_live_seg(vid):
        try:
            dur = float(request.args.get('dur', 4))
        except ValueError:
            dur = 4.0
        return ok(i=E().live_segmento(vid_ok(vid), request.get_data(), dur))

    @app.route('/api/ent/live/<vid>/encerrar', methods=['POST'])
    def ent_live_fim(vid):
        E().live_encerrar(vid_ok(vid))
        return ok()

    @app.route('/api/ent/live/<vid>/rtmp', methods=['POST'])
    def ent_live_rtmp(vid):
        return ok(**E().live_rtmp(vid_ok(vid)))

    @app.route('/api/ent/live/<vid>/entrar', methods=['POST'])
    def ent_live_entrar(vid):
        return jsonify(E().live_entrar(vid_ok(vid)))

    @app.route('/api/ent/live/<vid>/estado')
    def ent_live_estado(vid):
        return jsonify(E().live_estado(vid_ok(vid)))
