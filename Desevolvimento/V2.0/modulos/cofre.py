# -*- coding: utf-8 -*-
"""RRFS Social - cofre: tudo que fica em disco é cifrado com ChaCha20-Poly1305.
A chave vem da senha do usuário (scrypt). Arquivos grandes são cifrados em
blocos de 256 KB (permite ler trechos, ex.: avançar um vídeo)."""
import os
import json
import struct
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

BLOCO = 256 * 1024
TAG = 16


class ErroCofre(Exception):
    pass


def derivar_chave(senha, sal):
    return Scrypt(salt=sal, length=32, n=2 ** 15, r=8, p=1).derive(
        str(senha).encode('utf-8'))


class Cofre:
    def __init__(self, chave):
        self.aead = ChaCha20Poly1305(chave)

    # ── blocos pequenos ────────────────────────────────────
    def cifrar(self, dados, aad=b''):
        nonce = os.urandom(12)
        return nonce + self.aead.encrypt(nonce, dados, aad)

    def decifrar(self, blob, aad=b''):
        try:
            return self.aead.decrypt(blob[:12], blob[12:], aad)
        except InvalidTag:
            raise ErroCofre('Dados corrompidos ou senha incorreta')

    # ── arquivos pequenos ──────────────────────────────────
    def gravar_bytes(self, caminho, dados):
        tmp = caminho + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(self.cifrar(dados, b'bytes'))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, caminho)

    def ler_bytes(self, caminho):
        if not os.path.exists(caminho):
            return None
        with open(caminho, 'rb') as f:
            return self.decifrar(f.read(), b'bytes')

    def salvar_json(self, caminho, obj):
        self.gravar_bytes(caminho, json.dumps(
            obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))

    def ler_json(self, caminho, padrao=None):
        d = self.ler_bytes(caminho)
        return padrao if d is None else json.loads(d.decode('utf-8'))

    # ── arquivos grandes ───────────────────────────────────
    def escritor(self, caminho):
        return EscritorCifrado(self, caminho)

    def ler_arquivo(self, caminho, inicio=0, fim=None):
        """Gera o texto claro de [inicio, fim) (fim=None: até o final)."""
        with open(caminho, 'rb') as f:
            pref = f.read(8)
            b = inicio // BLOCO
            pos = b * BLOCO
            f.seek(8 + b * (BLOCO + TAG))
            while fim is None or pos < fim:
                ct = f.read(BLOCO + TAG)
                if not ct:
                    break
                n = struct.pack('>I', b)
                try:
                    pt = self.aead.decrypt(pref + n, ct, n)
                except InvalidTag:
                    raise ErroCofre('Arquivo corrompido')
                a = max(0, inicio - pos)
                z = len(pt) if fim is None else min(len(pt), fim - pos)
                if z > a:
                    yield pt[a:z]
                pos += len(pt)
                b += 1


class EscritorCifrado:
    def __init__(self, cofre, caminho):
        self.c, self.caminho = cofre, caminho
        self.tmp = caminho + '.tmp'
        self.f = open(self.tmp, 'wb')
        self.pref = os.urandom(8)
        self.f.write(self.pref)
        self.buf = bytearray()
        self.n = 0
        self.tam = 0
        self.h = hashlib.sha256()

    def escrever(self, d):
        self.h.update(d)
        self.tam += len(d)
        self.buf += d
        while len(self.buf) >= BLOCO:
            self._bloco(bytes(self.buf[:BLOCO]))
            del self.buf[:BLOCO]

    def _bloco(self, b):
        n = struct.pack('>I', self.n)
        self.f.write(self.c.aead.encrypt(self.pref + n, b, n))
        self.n += 1

    def fechar(self):
        """Finaliza e retorna (tamanho, sha256 hex)."""
        if self.buf:
            self._bloco(bytes(self.buf))
            self.buf.clear()
        self.f.flush()
        os.fsync(self.f.fileno())
        self.f.close()
        os.chmod(self.tmp, 0o600)
        os.replace(self.tmp, self.caminho)
        return self.tam, self.h.hexdigest()

    def cancelar(self):
        try:
            self.f.close()
        except Exception:
            pass
        try:
            os.remove(self.tmp)
        except OSError:
            pass
