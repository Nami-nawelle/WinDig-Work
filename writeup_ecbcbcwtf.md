# Writeup — ECB CBC, C'EST QUOI CE DÉLIRE ?
**Plateforme :** CryptoHack — [aes.cryptohack.org](https://aes.cryptohack.org/ecbcbcwtf/)  
**Catégorie :** Cryptographie / AES  
**Difficulté :** Intermédiaire  
**Flag :** `crypto{3cb_5uck5_4v01d_17_!!!!!}`

---

## 1. Description du challenge

Le challenge expose deux endpoints HTTP :

- `GET /ecbcbcwtf/encrypt_flag/` — Chiffre le flag en **AES-CBC** et retourne `IV || ciphertext` en hex.
- `GET /ecbcbcwtf/decrypt/<ciphertext>/` — Déchiffre un bloc en **AES-ECB** et retourne le plaintext en hex.

Le code source fourni est le suivant :

```python
from Crypto.Cipher import AES
import os

KEY = ?
FLAG = ?

@chal.route('/ecbcbcwtf/decrypt/<ciphertext>/')
def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)
    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}
    return {"plaintext": decrypted.hex()}

@chal.route('/ecbcbcwtf/encrypt_flag/')
def encrypt_flag():
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()
    return {"ciphertext": ciphertext}
```

---

## 2. Analyse de la vulnérabilité

### Rappels sur AES-CBC et AES-ECB

**AES-ECB (Electronic CodeBook)** chiffre chaque bloc indépendamment :

```
C[i] = ECB_encrypt(P[i])
P[i] = ECB_decrypt(C[i])
```

**AES-CBC (Cipher Block Chaining)** enchaîne les blocs avec un XOR :

```
Chiffrement : C[i] = ECB_encrypt(P[i] XOR C[i-1])   (C[-1] = IV)
Déchiffrement : P[i] = ECB_decrypt(C[i]) XOR C[i-1]  (C[-1] = IV)
```

### La faille

Le serveur **chiffre en CBC** mais **déchiffre en ECB**. C'est la confusion volontaire du challenge.

En CBC, pour déchiffrer un bloc, on a besoin de :
```
P[i] = ECB_decrypt(C[i]) XOR C[i-1]
```

Or le endpoint `/decrypt/` nous fournit exactement `ECB_decrypt(C[i])` pour n'importe quel bloc qu'on lui envoie. Il suffit donc de faire le **XOR manuellement** avec le bloc précédent (ou l'IV pour le premier bloc) pour retrouver le plaintext.

**Sans jamais connaître la KEY**, on peut déchiffrer le flag entier !

---

## 3. Exploitation

### Étape 1 — Récupérer le ciphertext

```
GET /ecbcbcwtf/encrypt_flag/
→ {"ciphertext": "329cb62872718ee89186b2c89f15b916b6b1ab34b4a866c370b75fa30026d9d96052fb851438aa63347f09770b34633b"}
```

On sépare :
- **IV** (16 premiers bytes) : `329cb62872718ee89186b2c89f15b916`
- **C1** (bloc 1) : `b6b1ab34b4a866c370b75fa30026d9d9`
- **C2** (bloc 2) : `6052fb851438aa63347f09770b34633b`

### Étape 2 — Appeler l'oracle ECB

```
GET /ecbcbcwtf/decrypt/b6b1ab34b4a866c370b75fa30026d9d9/
→ {"plaintext": "51eecf58061ef5dbf2e4edfdea76d223"}   ← ECB_decrypt(C1)

GET /ecbcbcwtf/decrypt/6052fb851438aa63347f09770b34633b/
→ {"plaintext": "e985dd0485cc39f247e87e822107f8a4"}   ← ECB_decrypt(C2)
```

### Étape 3 — XOR pour retrouver le plaintext

```
P[0] = ECB_decrypt(C1) XOR IV
     = 51eecf58061ef5dbf2e4edfdea76d223
       XOR
       329cb62872718ee89186b2c89f15b916
     = "crypto{3cb_5uck5"

P[1] = ECB_decrypt(C2) XOR C1
     = e985dd0485cc39f247e87e822107f8a4
       XOR
       b6b1ab34b4a866c370b75fa30026d9d9
     = "_4v01d_17_!!!!!}"
```

### Script d'exploitation complet

```python
import requests

# Étape 1 : Récupérer le ciphertext chiffré en CBC
ciphertext_hex = requests.get("https://aes.cryptohack.org/ecbcbcwtf/encrypt_flag/").json()["ciphertext"]
ciphertext_bytes = bytes.fromhex(ciphertext_hex)

iv               = ciphertext_bytes[:16]
encrypted_blocks = ciphertext_bytes[16:]

# Étape 2 : Oracle ECB du serveur
def ecb_oracle(block: bytes) -> bytes:
    url  = f"https://aes.cryptohack.org/ecbcbcwtf/decrypt/{block.hex()}/"
    resp = requests.get(url)
    return bytes.fromhex(resp.json()["plaintext"])

# Étape 3 : Déchiffrement CBC via XOR
def exploit(iv, encrypted_blocks):
    block_size = 16
    plaintext  = b""
    prev_block = iv

    for i in range(0, len(encrypted_blocks), block_size):
        current_block = encrypted_blocks[i:i + block_size]
        ecb_dec       = ecb_oracle(current_block)
        plain_block   = bytes(a ^ b for a, b in zip(ecb_dec, prev_block))
        plaintext    += plain_block
        prev_block    = current_block

    return plaintext

flag = exploit(iv, encrypted_blocks)
print(f"FLAG : {flag.decode(errors='replace')}")
```

---

## 4. Résultat

```
FLAG : crypto{3cb_5uck5_4v01d_17_!!!!!}
```

---

## 5. Leçon retenue

> **"ECB sucks, avoid it"** — c'est le flag lui-même qui le dit.

| Mode | Problème |
|------|----------|
| **AES-ECB** | Chaque bloc est chiffré indépendamment → déterministe, pas de diffusion entre blocs |
| **Mélange ECB/CBC** | Exposer un oracle ECB suffit à casser le CBC sans connaître la clé |

**Règles d'or :**
- Ne jamais utiliser AES-ECB pour chiffrer des données sensibles.
- Ne jamais exposer un oracle de déchiffrement sans authentification.
- Toujours utiliser des modes authentifiés comme **AES-GCM** ou **AES-CCM**.
