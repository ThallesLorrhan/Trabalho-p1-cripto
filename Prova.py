#!/usr/bin/env python3
# Prova.py (encrypt_postorder.py) — versão atualizada
# Encriptador: recebe mensagem, codifica (ascii_decimal | binary), organiza em árvore balanceada,
# faz pós-ordem e salva JSON com criptografia híbrida (AES-GCM + RSA-OAEP).
# Melhorias: aceita caminho custom de public.pem, loop de tentativa, mensagens de erro claras.

import json, base64, os, sys
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# ---------- Árvore ----------
class Node:
    def __init__(self, val=None, left=None, right=None):
        self.val = val
        self.left = left
        self.right = right

def build_balanced_tree(values):
    nodes = [Node(val=v) for v in values]
    if not nodes:
        return None
    while len(nodes) > 1:
        next_level = []
        i = 0
        while i < len(nodes):
            left = nodes[i]
            right = nodes[i+1] if i+1 < len(nodes) else None
            parent = Node(val=None, left=left, right=right)
            next_level.append(parent)
            i += 2
        nodes = next_level
    return nodes[0]

def postorder(node, out):
    if node is None:
        return
    postorder(node.left, out)
    postorder(node.right, out)
    out.append(node.val)

def serialize_tree(node):
    arr = []
    def helper(n):
        if n is None:
            return -1
        idx = len(arr)
        arr.append({"val": n.val, "left": None, "right": None})
        li = helper(n.left)
        ri = helper(n.right)
        arr[idx]["left"] = li
        arr[idx]["right"] = ri
        return idx
    helper(node)
    return arr

# ---------- RSA helpers ----------
def load_rsa_pub(pubfile):
    """
    Tenta carregar uma chave pública PEM do caminho dado.
    Lança OSError/ValueError se não for possível abrir ou carregar.
    """
    with open(pubfile, "rb") as f:
        data = f.read()
    return serialization.load_pem_public_key(data)

def rsa_encrypt(pub, plaintext):
    return pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

# ---------- util ----------
def ask_public_key_path(default="public.pem"):
    """
    Tenta usar default; se não existir, pergunta ao usuário repetidamente.
    Retorna caminho válido (string) ou raises SystemExit se usuário digitar 'exit'.
    """
    # se foi fornecido explicitamente (arquivo na pasta atual)
    if os.path.exists(default) and os.path.isfile(default):
        return default

    print(f"A chave pública padrão '{default}' não foi encontrada no diretório atual.")
    print("Digite o caminho para o arquivo public.pem (ou 'exit' para cancelar).")
    while True:
        path = input("Caminho para public.pem: ").strip()
        if not path:
            print("Caminho vazio — digite o caminho ou 'exit'.")
            continue
        if path.lower() in ("exit","sair","quit","q"):
            print("Operação cancelada pelo usuário.")
            raise SystemExit(1)
        if not os.path.exists(path):
            print("Arquivo não encontrado no caminho informado. Tente novamente.")
            continue
        if not os.path.isfile(path):
            print("O caminho informado não é um arquivo. Tente novamente.")
            continue
        # tentativa de carregar
        try:
            _ = load_rsa_pub(path)
            return path
        except Exception as e:
            print("Falha ao carregar chave a partir deste arquivo:", e)
            print("Tente outro arquivo ou 'exit' para cancelar.")

# ---------- Main ----------
def main():
    print("=== ENCRYPT POSTORDER ===")

    # mensagem
    msg = input("Mensagem à criptografar: ")
    if msg is None or msg == "":
        print("Nenhuma mensagem foi fornecida. Saindo.")
        return

    # encoding
    encoding = input("Escolha encoding (ascii_decimal / binary) [ascii_decimal]: ").strip() or "ascii_decimal"
    if encoding not in ("ascii_decimal","binary"):
        print("Encoding inválido. Usando ascii_decimal.")
        encoding = "ascii_decimal"

    # converte mensagem em tokens (cada caractere -> token)
    if encoding == "ascii_decimal":
        tokens = [str(ord(c)) for c in msg]
    else:
        tokens = [format(ord(c), "08b") for c in msg]

    # constroi árvore e pós-ordem
    root = build_balanced_tree(tokens)
    post = []
    postorder(root, post)
    tree_meta = serialize_tree(root)

    payload = {
        "postorder_list": post,
        "tree_meta": tree_meta,
        "original_length": len(msg),
        "encoding": encoding
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    # AES-GCM (simétrico)
    aes_key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, payload_bytes, None)

    # RSA (usa public.pem do destinatário) — aceitar default ou caminho informado
    # Primeiro tenta arquivo 'public.pem' no diretório atual; se não, pergunta.
    try:
        pub_path = ask_public_key_path("public.pem")
    except SystemExit:
        print("Nenhuma chave pública fornecida — saindo sem gerar arquivo.")
        return

    try:
        pub = load_rsa_pub(pub_path)
    except Exception as e:
        print("Erro ao carregar chave pública (fatal):", e)
        return

    try:
        encrypted_key = rsa_encrypt(pub, aes_key)
    except Exception as e:
        print("Erro ao criptografar a chave AES com a chave pública:", e)
        return

    out = {
        "version": "1.0",
        "encoding": encoding,
        "symmetric":"AES-GCM-256",
        "rsa":"RSA-OAEP-2048",
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tree_meta_note": "tree serializada dentro do payload cifrado",
        "public_key_encryptor": None,  # opcional: se quiser incluir seu public.pem, coloque aqui como string
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    fname = f"mensagem_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname,"w",encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print("Arquivo salvo:", fname)
    print("Pronto — entregue o JSON ao destinatário (eles precisarão da private key).")

if __name__ == "__main__":
    main()
