# decrypt_postorder.py
import json, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def load_private(privfile="private.pem"):
    with open(privfile, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=None)

def rsa_decrypt(priv, ciphertext):
    return priv.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

def build_tree_from_meta(meta):
    # meta é lista de dicts {"val":..., "left": idx_or_-1, "right": idx_or_-1}
    if not meta:
        return None
    class Node:
        def __init__(self, val=None):
            self.val = val
            self.left = None
            self.right = None
    nodes = [Node(d["val"]) for d in meta]
    for idx, d in enumerate(meta):
        li = d["left"]
        ri = d["right"]
        nodes[idx].left = None if li == -1 else nodes[li]
        nodes[idx].right = None if ri == -1 else nodes[ri]
    return nodes[0]  # root is index 0 (mesma convention do Prova.py)

def collect_leaves_left_to_right(node, out):
    if node is None:
        return
    # if leaf (both children None) -> it's an original token
    if getattr(node, "left", None) is None and getattr(node, "right", None) is None:
        out.append(node.val)
        return
    collect_leaves_left_to_right(node.left, out)
    collect_leaves_left_to_right(node.right, out)

def main():
    fname = input("Arquivo JSON gerado (ex: mensagem_YYYYMMDD_HHMMSS.json): ").strip()
    if not fname:
        print("Arquivo não informado. Saindo.")
        return

    with open(fname, "r", encoding="utf-8") as f:
        data = json.load(f)

    enc_key_b64 = data["encrypted_key"]
    nonce_b64 = data["nonce"]
    ciphertext_b64 = data["ciphertext"]

    enc_key = base64.b64decode(enc_key_b64)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    priv = load_private("private.pem")
    aes_key = rsa_decrypt(priv, enc_key)

    aes = AESGCM(aes_key)
    plaintext = aes.decrypt(nonce, ciphertext, None)
    payload = json.loads(plaintext.decode("utf-8"))

    # Reconstruir árvore e extrair tokens (folhas) na ordem esquerda->direita
    tree_meta = payload["tree_meta"]
    root = build_tree_from_meta(tree_meta)
    tokens = []
    collect_leaves_left_to_right(root, tokens)

    # Reconstruir mensagem a partir dos tokens
    encoding = payload.get("encoding", "ascii_decimal")
    original_len = payload.get("original_length", None)

    chars = []
    for t in tokens:
        if t is None:
            continue
        if encoding == "ascii_decimal":
            try:
                chars.append(chr(int(t)))
            except Exception:
                chars.append('?')
        else:  # binary
            try:
                chars.append(chr(int(t, 2)))
            except Exception:
                chars.append('?')

    message = "".join(chars)
    if original_len is not None:
        message = message[:original_len]

    print("=== DESCRIPTOGRAFADO ===")
    print("Mensagem reconstruída:", message)
    print("\nPayload completo (para inspeção):")
    print(json.dumps(payload, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
