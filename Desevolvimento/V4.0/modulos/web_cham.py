# -*- coding: utf-8 -*-
"""RRFS Social - rotas HTTP de chamadas e de silenciar conversas."""
import re
from flask import jsonify

RE_ID = re.compile(r'^[0-9a-f]{16}$')


def registrar(app, S, ok, corpo, ErroApi):
    def call_ok(c):
        if not RE_ID.match(str(c)):
            raise ErroApi('Chamada inválida.')
        return str(c)

    @app.route('/api/chamadas')
    def ch_lista():
        s = S()
        return jsonify({'ativas': s.cham.ativas(), 'ice': s.cham.ice(),
                        'stun_extra': s.t['ajustes']['stun_extra'],
                        'stun': s.stun.porta if s.stun else 0, 'pub': s.pub()})

    @app.route('/api/chamadas/stun', methods=['POST'])
    def ch_stun():
        urls = [str(u).strip()[:200] for u in (corpo().get('urls') or [])[:5]
                if str(u).strip().startswith(('stun:', 'turn:'))]
        S().t['ajustes']['stun_extra'] = urls
        S().banco.sujar('ajustes')
        return ok()

    @app.route('/api/chamada/iniciar', methods=['POST'])
    def ch_iniciar():
        d = corpo()
        return jsonify(S().cham.iniciar(str(d.get('cid', '')), bool(d.get('video'))))

    @app.route('/api/chamada/entrar', methods=['POST'])
    def ch_entrar():
        d = corpo()
        return jsonify(S().cham.entrar(call_ok(d.get('call')), bool(d.get('video'))))

    @app.route('/api/chamada/sair', methods=['POST'])
    def ch_sair():
        S().cham.sair(call_ok(corpo().get('call')))
        return ok()

    @app.route('/api/chamada/recusar', methods=['POST'])
    def ch_recusar():
        S().cham.recusar(call_ok(corpo().get('call')))
        return ok()

    @app.route('/api/chamada/sinal', methods=['POST'])
    def ch_sinal():
        d = corpo()
        S().cham.sinal(call_ok(d.get('call')), d.get('para', ''), d.get('dado'))
        return ok()

    @app.route('/api/silenciar', methods=['POST'])
    def silenciar():
        d = corpo()
        S().silenciar(str(d.get('cid', '')), bool(d.get('on')))
        return ok()

    @app.route('/api/silenciados')
    def silenciados():
        return jsonify({'silenciados': S().lista_silenciados()})
