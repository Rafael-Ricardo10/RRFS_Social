# -*- coding: utf-8 -*-
"""RRFS Social - constantes, validações, IPs, busca aproximada, JSON."""
import os
import re
import json
import time
import base64
import socket
import difflib
import logging
import secrets
import hashlib
import ipaddress
import threading
import subprocess
import unicodedata
import urllib.request

log = logging.getLogger("RRFS.Social")

# ── protocolo ────────────────────────────────────────────────────────────
PROTO = 1
PACOTE_DADOS = 160            # JSON fragmentado (faixa lossless 160-191)
PACOTE_BIN = 161              # pedaço binário de arquivo
PACOTE_PEDACO = 162           # pedaço de vídeo (enxame)
MAX_FRAGMENTO = 1200
MAX_FRAGMENTOS_MSG = 4000
ERRO_SENDQ = 7
TIMEOUT_FRAGMENTOS = 600
TOX_ADDRESS_SIZE = 38
CHUNK_BIN = 1100

RE_ADDR = re.compile(r'^[0-9A-Fa-f]{76}$')
RE_HEX64 = re.compile(r'^[0-9A-Fa-f]{64}$')
RE_HEX64_MIN = re.compile(r'^[0-9a-f]{64}$')
RE_ID = re.compile(r'^[0-9a-f]{16}$')
RE_LOGIN = re.compile(r'^[a-z0-9_.-]{3,32}$')
_RE_CTRL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')

IFACES_IGNORAR = ('lo', 'docker', 'br-', 'veth', 'virbr', 'tun', 'tap',
                  'wg', 'zt', 'tailscale', 'cni', 'flannel', 'kube')

MIMES_INLINE = {'image/jpeg', 'image/png', 'image/gif', 'image/webp',
                'video/mp4', 'video/webm', 'audio/mpeg', 'audio/ogg',
                'audio/webm', 'audio/mp4', 'audio/wav'}


class ErroSocial(Exception):
    pass


def agora():
    return int(time.time())


def novo_id():
    return secrets.token_hex(8)


def limpar(t, n):
    return _RE_CTRL.sub('', str(t or '')).strip()[:n]


def limpar_multilinha(t, n):
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(t or ''))[:n]


def mime_seguro(mime, nome=''):
    m = str(mime or '').lower().split(';')[0].strip()
    return m if m in MIMES_INLINE else 'application/octet-stream'


def tipo_por_mime(mime):
    m = str(mime or '')
    if m.startswith('image/') and m in MIMES_INLINE:
        return 'imagem'
    if m.startswith('video/') and m in MIMES_INLINE:
        return 'video'
    if m.startswith('audio/') and m in MIMES_INLINE:
        return 'audio'
    return 'arquivo'


def nome_arquivo(n):
    n = os.path.basename(str(n or '').replace('\\', '/'))
    n = _RE_CTRL.sub('', n).strip().strip('.')[:120]
    return n or 'arquivo'


def decodificar_imagem(data_url, max_bytes):
    """data:image/...;base64 -> (bytes, mime) ou (None, None)."""
    m = re.match(r'^data:(image/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$',
                 str(data_url or ''))
    if not m:
        return None, None
    try:
        raw = base64.b64decode(m.group(2), validate=True)
    except Exception:
        return None, None
    if not raw or len(raw) > max_bytes:
        return None, None
    ok = (raw[:3] == b'\xff\xd8\xff' or raw[:4] == b'\x89PNG'
          or (raw[:4] == b'RIFF' and raw[8:12] == b'WEBP'))
    return (raw, m.group(1)) if ok else (None, None)


def validar_mini(s):
    """Miniatura de perfil (data URL pequena) ou ''."""
    s = str(s or '')
    if len(s) > 9000 or not re.match(
            r'^data:image/(?:jpeg|png|webp);base64,[A-Za-z0-9+/=]+$', s):
        return ''
    return s


# ── arquivos JSON simples (dados públicos: rede, nós) ───────────────────
_json_lock = threading.Lock()


def ler_json(caminho, padrao=None):
    try:
        if os.path.exists(caminho):
            with open(caminho, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        log.error("ler_json %s: %s", caminho, e)
    return padrao


def salvar_json(caminho, obj):
    with _json_lock:
        tmp = caminho + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, caminho)


# ── IPs ─────────────────────────────────────────────────────────────────
def ip_lan_valido(ip):
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if a.version != 4:
        return False
    if (a.is_loopback or a.is_link_local or a.is_multicast
            or a.is_unspecified or a.is_reserved):
        return False
    return a.is_private or a in ipaddress.ip_network('100.64.0.0/10')


def ip_global_valido(ip):
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return bool(a.is_global and not a.is_multicast)


def _ip_cmd(familia):
    saida = []
    try:
        r = subprocess.run(['ip', familia, '-o', 'addr', 'show', 'scope',
                            'global'], capture_output=True, text=True,
                           timeout=5)
        for l in r.stdout.splitlines():
            p = l.split()
            if len(p) >= 4 and 'temporary' not in l and 'deprecated' not in l:
                saida.append((p[1], p[3].split('/')[0].split('%')[0]))
    except Exception:
        pass
    return saida


def _ip_rota_padrao(familia, alvo):
    try:
        u = socket.socket(familia, socket.SOCK_DGRAM)
        u.connect((alvo, 9))
        ip = u.getsockname()[0].split('%')[0]
        u.close()
        return ip
    except Exception:
        return None


def ips_lan_locais():
    ips = [ip for n, ip in _ip_cmd('-4') if not n.startswith(IFACES_IGNORAR)]
    r = _ip_rota_padrao(socket.AF_INET, '203.0.113.1')
    if r:
        ips.append(r)
    saida = []
    for ip in ips:
        if ip_lan_valido(ip) and ip not in saida:
            saida.append(ip)
    return saida[:6]


def ips_globais_locais():
    ips = [ip for fam in ('-6', '-4') for n, ip in _ip_cmd(fam)
           if not n.startswith(IFACES_IGNORAR)]
    for fam, alvo in ((socket.AF_INET6, '2001:db8::1'),
                      (socket.AF_INET, '203.0.113.1')):
        r = _ip_rota_padrao(fam, alvo)
        if r:
            ips.append(r)
    saida = []
    for ip in ips:
        if ip_global_valido(ip) and ip not in saida:
            saida.append(ip)
    return saida[:6]


def validar_dica(d, permitir_lan=False):
    """Valida/limpa uma 'dica de rede' (como alcançar um nó) vinda de um par."""
    try:
        if not isinstance(d, dict):
            return None
        dht = str(d.get('dht_id', '')).upper()
        porta = int(d.get('porta', 0))
        if not RE_HEX64.match(dht) or not 1024 <= porta <= 65535:
            return None
        tcp = int(d.get('tcp_porta', 0) or 0)
        if not 1024 <= tcp <= 65535:
            tcp = 0
        lan = [i for i in (d.get('ips') or [])[:6] if ip_lan_valido(i)] \
            if permitir_lan else []
        glob = [i for i in (d.get('ips_globais') or [])[:6]
                if ip_global_valido(i)]
        if not lan and not glob:
            return None
        stun = int(d.get('stun_porta', 0) or 0)
        if not 1024 <= stun <= 65535:
            stun = 0
        return {'dht_id': dht, 'porta': porta, 'ips': lan,
                'ips_globais': glob, 'tcp_porta': tcp, 'stun_porta': stun}
    except Exception:
        return None


# ── busca aproximada (tolera erro de digitação e texto parcial) ─────────
def normalizar(t):
    t = unicodedata.normalize('NFKD', str(t))
    t = ''.join(c for c in t if not unicodedata.combining(c)).lower()
    return re.sub(r'[^a-z0-9]+', ' ', t).strip()


def _trigramas(t):
    t = f'  {t} '
    return {t[i:i + 3] for i in range(len(t) - 2)} if t.strip() else set()


def preparar(texto):
    n = normalizar(texto)
    return {'n': n, 'tok': n.split(), 'tri': _trigramas(n)}


def _jaccard(a, b):
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def pontuar(q, c):
    if not q['n'] or not c['n']:
        return 0.0
    sub = 1.0 if q['n'] in c['n'] else 0.0
    toks = []
    for t in q['tok']:
        melhor = 0.0
        for w in c['tok']:
            if w == t:
                melhor = 1.0
                break
            if len(t) >= 2 and w.startswith(t):
                melhor = max(melhor, 0.92)
            elif len(t) >= 3 and t in w:
                melhor = max(melhor, 0.8)
            elif abs(len(w) - len(t)) <= max(2, len(t) // 2):
                r = difflib.SequenceMatcher(None, t, w).ratio()
                if r >= 0.6:
                    melhor = max(melhor, r * 0.9)
        toks.append(melhor)
    tok = sum(toks) / len(toks) if toks else 0.0
    tri = min(1.0, _jaccard(q['tri'], c['tri']) * 2)
    return max(sub, 0.7 * tok + 0.3 * tri)


# ── nós públicos de bootstrap do Tox (dados/tox/nos_bootstrap.json) ─────
def carregar_nos(caminho):
    nos = ler_json(caminho, []) or []
    return [n for n in nos if isinstance(n, dict)
            and RE_HEX64.match(str(n.get('chave_publica', ''))) and n.get('ip')]


def mesclar_nos(caminho, novos):
    atuais = carregar_nos(caminho)
    ex = {(n['ip'], int(n['porta'])) for n in atuais}
    add = 0
    for n in novos:
        try:
            chave = str(n.get('chave_publica', '')).upper()
            ip, porta = str(n.get('ip', '')), int(n.get('porta', 33445))
            if not RE_HEX64.match(chave) or not ip or (ip, porta) in ex:
                continue
            atuais.append({'ip': ip, 'porta': porta, 'chave_publica': chave,
                           'tcp_ports': [int(p) for p in
                                         (n.get('tcp_ports') or [])][:3]})
            ex.add((ip, porta))
            add += 1
        except (TypeError, ValueError):
            continue
    salvar_json(caminho, atuais)
    return add


def atualizar_nos_online(caminho):
    try:
        req = urllib.request.Request('https://nodes.tox.chat/json',
                                     headers={'User-Agent': 'RRFS-Social'})
        with urllib.request.urlopen(req, timeout=10) as r:
            dd = json.loads(r.read().decode('utf-8'))
        novos = []
        for it in dd.get('nodes', []):
            ip = it.get('ipv4')
            if not it.get('status_udp') or not ip or ip == '-':
                continue
            novos.append({'ip': ip, 'porta': it.get('port', 33445),
                          'chave_publica': it.get('public_key') or '',
                          'tcp_ports': it.get('tcp_ports') or []})
        return True, mesclar_nos(caminho, novos)
    except Exception as e:
        log.info("Sem acesso à lista online de nós Tox: %s", e)
        return False, 0
