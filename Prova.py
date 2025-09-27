"""
Prova.py — Encriptador Profissional de Mensagens
------------------------------------------------
Funções:
1. Recebe mensagem e converte em tokens (ASCII decimal ou binário)
2. Constroi árvore binária balanceada
3. Percorre árvore em pós-ordem
4. Serializa árvore
5. Criptografa payload com AES-GCM + RSA-OAEP
6. Salva JSON com nome padrão: json_decriptografar.json
"""

import json, base64, os
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# ---------------- Árvore Binária ----------------
class Node:
    """Nó da árvore binária: val, left, right"""
    def __init__(self, val=None, left=None, right=None): self.val, self.left, self.right = val, left, right

# ---------------- Construção de Árvore ----------------
def build_balanced_tree(values):
    """Constrói árvore binária balanceada a partir de lista de valores"""
    nodes = [Node(v) for v in values]
    while len(nodes) > 1:
        nodes = [Node(left=nodes[i], right=nodes[i+1] if i+1<len(nodes) else None)
                 for i in range(0, len(nodes), 2)]
    return nodes[0] if nodes else None

# ---------------- Pós-Ordem ----------------
def postorder(node, out):
    """Percorre árvore em pós-ordem e adiciona valores a out"""
    node and (postorder(node.left, out), postorder(node.right, out), out.append(node.val))

# ---------------- Serialização da Árvore ----------------
def serialize_tree(node):
    """Serializa árvore em lista de dicionários com índices de filhos"""
    arr = []
    def helper(n):
        if not n: return -1
        idx = len(arr)
        arr.append({"val": n.val, "left": None, "right": None})
        arr[idx]["left"], arr[idx]["right"] = helper(n.left), helper(n.right)
        return idx
    helper(node)
    return arr

# ---------------- RSA Helpers ----------------
def load_rsa_pub(pubfile):
    """Carrega chave pública RSA de arquivo PEM"""
    with open(pubfile, "rb") as f: return serialization.load_pem_public_key(f.read())

def rsa_encrypt(pub, plaintext):
    """Encripta plaintext usando RSA-OAEP"""
    return pub.encrypt(plaintext, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

# ---------------- Caminho da Chave Pública ----------------
def ask_public_key_path(default="public.pem"):
    """Retorna caminho válido para public.pem ou solicita ao usuário"""
    if os.path.isfile(default): return default
    print(f"Chave pública padrão '{default}' não encontrada.")
    while True:
        path = input("Caminho para public.pem (ou 'exit'): ").strip()
        if path.lower() in ("exit","sair","quit","q"): raise SystemExit("Operação cancelada.")
        if os.path.isfile(path):
            try: load_rsa_pub(path); return path
            except Exception as e: print("Falha ao carregar chave:", e)
        else: print("Arquivo não encontrado. Tente novamente.")

# ---------------- Função Principal ----------------
def main():
    print("=== ENCRYPT POSTORDER ===")
    msg = input("Mensagem a criptografar: ")
    if not msg: return print("Nenhuma mensagem fornecida. Saindo.")

    # Encoding: ascii_decimal ou binary
    encoding = input("Escolha encoding [ascii_decimal/binary]: ").strip() or "ascii_decimal"
    encoding = encoding if encoding in ("ascii_decimal","binary") else "ascii_decimal"

    # Tokens da mensagem
    tokens = [str(ord(c)) if encoding=="ascii_decimal" else format(ord(c),"08b") for c in msg]

    # Construção e pós-ordem da árvore
    root = build_balanced_tree(tokens)
    post_list = []; postorder(root, post_list)
    tree_meta = serialize_tree(root)

    # Payload JSON para criptografia simétrica
    payload_bytes = json.dumps({
        "postorder_list": post_list,
        "tree_meta": tree_meta,
        "original_length": len(msg),
        "encoding": encoding
    }, ensure_ascii=False).encode("utf-8")

    # Criptografia AES-GCM
    aes_key = AESGCM.generate_key(bit_length=256)
    aes, nonce = AESGCM(aes_key), os.urandom(12)
    ciphertext = aes.encrypt(nonce, payload_bytes, None)

    # Chave pública RSA
    try: pub_path = ask_public_key_path("public.pem")
    except SystemExit: return print("Nenhuma chave pública fornecida. Saindo.")
    try: pub = load_rsa_pub(pub_path)
    except Exception as e: return print("Erro ao carregar chave pública:", e)
    try: encrypted_key = rsa_encrypt(pub, aes_key)
    except Exception as e: return print("Erro ao criptografar chave AES:", e)

    # JSON final
    output = {
        "version":"1.0", "encoding":encoding, "symmetric":"AES-GCM-256", "rsa":"RSA-OAEP-2048",
        "encrypted_key":base64.b64encode(encrypted_key).decode(), "nonce":base64.b64encode(nonce).decode(),
        "ciphertext":base64.b64encode(ciphertext).decode(),
        "tree_meta_note":"Árvore serializada dentro do payload cifrado", "public_key_encryptor":None,
        "timestamp":datetime.utcnow().isoformat()+"Z"
    }

    # Salva arquivo com nome padrão
    fname = "json_decriptografar.json"
    with open(fname,"w",encoding="utf-8") as f: json.dump(output,f,indent=2,ensure_ascii=False)
    print(f"✅ Arquivo salvo: {fname}")
    print("🔐 Entregue o JSON ao destinatário (eles precisarão da private key).")

if __name__ == "__main__": main()