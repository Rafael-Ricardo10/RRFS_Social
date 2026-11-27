#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RRFS Social - mensageiro P2P sobre Tox (sem servidores, sem internet obrigatória).
Requer: python3, flask, cryptography, libtoxcore.
  Debian: sudo apt install python3-flask python3-cryptography libtoxcore2
Uso: python3 rrfs_social.py   ->  http://localhost:3800
Estrutura: dados/ (gerada), modulos/ (código), templates/ (telas HTML).
"""
import os
import sys
import logging
from logging.handlers import RotatingFileHandler

RAIZ = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, RAIZ)

from modulos.util import ler_json, salvar_json            # noqa: E402
from modulos.web import criar_app                         # noqa: E402

PORTA = 3800
SUBS = ('config', 'tox', 'rede', 'contas', 'logs', 'exportacoes', 'tmp')


def main():
    dados = os.path.join(RAIZ, 'dados')
    for s in SUBS:
        os.makedirs(os.path.join(dados, s), mode=0o700, exist_ok=True)
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    logging.getLogger().setLevel(logging.INFO)
    for h in (RotatingFileHandler(os.path.join(dados, 'logs', 'social.log'),
                                  maxBytes=2_000_000, backupCount=3,
                                  encoding='utf-8'), logging.StreamHandler()):
        h.setFormatter(fmt)
        logging.getLogger().addHandler(h)
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    cfg_p = os.path.join(dados, 'config', 'config.json')
    cfg = {'porta': PORTA}
    cfg.update(ler_json(cfg_p, {}) or {})
    salvar_json(cfg_p, cfg)
    app = criar_app(dados, RAIZ, int(cfg['porta']))
    logging.info("RRFS Social: http://localhost:%d", cfg['porta'])
    try:
        app.run(host='127.0.0.1', port=int(cfg['porta']), threaded=True,
                use_reloader=False)
    finally:
        app.estado_app.sair()


if __name__ == '__main__':
    main()
