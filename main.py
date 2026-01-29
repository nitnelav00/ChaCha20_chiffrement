#!/usr/bin/env python3
"""
Ce programme a été créé par Nitnelav00

Un outil de chiffrement et déchiffrement de dossier, fichier et texte
utilisant l'algorithme ChaCha20 Poly1305
"""

import os
import zipfile
from base64 import b64decode, b64encode
import binascii
from hashlib import sha256

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes


def charger_cle() -> tuple[bytes | None, int | None]:
    """Fonction utilisée pour charger la clé enregistrée dans le fichier "cle.txt".

    === Retourne ===
    :return: la clé et la taille du nonce, ou (None, None) si le fichier n'existe pas
    """
    if not os.path.exists("cle.txt"):
        print("Fichier de clé non trouvé. Veuillez créer une nouvelle clé.")
        return None, None

    with open("cle.txt", "r") as f:
        try:
            cle: bytes = b64decode(f.readline().strip())
        except binascii.Error as e:
            print(e)
            return None, None
        taille_nonce: int = int(f.readline().strip())

    if not (taille_nonce == 12 or taille_nonce == 8 or taille_nonce == 24):
        print("La taille du nonce est invalide, il doit être égal à 8, 12 ou 24")
        return None, None

    if len(cle) != 32:
        print("Clé invalide : La clé doit faire 32 octets (256 bits).")
        return None, None

    return cle, taille_nonce


def enregistrer_cle(cle: bytes, taille_nonce: int) -> None:
    """
    enregistrer la clé dans un fichier cle.txt

    === Paramètres ===
    :param cle: la clé à enregistrer
    :param taille_nonce: la taille du nonce utilisée pour le chiffrement
    """
    assert taille_nonce == 12 or taille_nonce == 8 or taille_nonce == 24

    with open("cle.txt", "w") as f:
        _ = f.write(b64encode(cle).decode("utf-8") + "\n")
        _ = f.write(str(taille_nonce) + "\n")
    print("Clé enregistrée dans cle.txt")


def nouvelle_cle() -> None:
    """
    L'utilisateur peut entrer une clé existante, en générer une nouvelle ou utiliser
    un mot de passe pour générer la clé.
    """
    # L'utilisateur peut entrer une clé existante ou en générer une nouvelle.
    # La clé est stockée dans un fichier cle.txt ou mettre un mot de passe pour générer la clé
    securite_choix = input(
        "Voulez-vous définir la taille du nonce (8, 12 ou 24 octets ou rien pour 12) ? "
    )
    taille_nonce = 12
    if securite_choix.isdigit() and int(securite_choix) in [8, 12, 24]:
        taille_nonce = int(securite_choix)

    choix = input(
        "Voulez-vous entrer une clé existante (1), en générer une nouvelle (2 / défaut) "
        "ou utiliser un mot de passe (3) ? "
    )
    if choix == "":
        choix = "2"
    if choix == "1":
        cle: str = input("Entrez la clé en base64 : ")
        # vérifier que la clé est valide
        cle2: bytes = b64decode(cle)
        if len(cle) != 32:
            print("Clé invalide : La clé doit faire 32 octets (256 bits).")
            return
        enregistrer_cle(cle2, taille_nonce)
    elif choix == "2":
        cle3: bytes = get_random_bytes(32)  # XChaCha20 requires a 256-bit (32-byte) key
        enregistrer_cle(cle3, taille_nonce)
    elif choix == "3":
        mot_de_passe = input("Entrez le mot de passe : ")
        # dériver une clé de 32 octets à partir du mot de passe
        # (simple hachage pour l'exemple, utiliser PBKDF2 ou Argon2 en production)
        cle4: bytes = sha256(mot_de_passe.encode("utf-8")).digest()
        enregistrer_cle(cle4, taille_nonce)
    else:
        print("Choix invalide.")


def chiffrer_message(cle: bytes, taille_nonce: int) -> None:
    """
    chiffrer un message avec la clé donnée et afficher le message chiffré en base64.

    === Paramètres ===
    :param cle: La clé de chiffrement
    :param taille_nonce: La taille du nonce utilisée pour le chiffrement
    """
    assert type(cle) is bytes and len(cle) == 32, "Clé invalide"
    assert taille_nonce == 12 or taille_nonce == 8 or taille_nonce == 24

    message = input("Entrez le message à chiffrer : ").encode("utf-8")
    nonce = get_random_bytes(taille_nonce)
    cipher = ChaCha20_Poly1305.new(key=cle, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    print("Message chiffré (base64) :")
    print(b64encode(cipher.nonce + tag + ciphertext).decode("utf-8"))


def chiffrer_fichier(cle: bytes, taille_nonce: int) -> None:
    """
    Chiffrer un fichier avec la clé donnée et enregistrer le fichier chiffré.

    === Paramètres ===
    :param cle: la clé de chiffrement
    :param taille_nonce: la taille du nonce utilisée pour le chiffrement
    """
    assert type(cle) is bytes and len(cle) == 32, "Clé invalide"
    assert taille_nonce == 12 or taille_nonce == 8 or taille_nonce == 24

    nom_fichier = input("Entrez le nom du fichier à chiffrer : ")

    with open(nom_fichier, "rb") as f:
        data = f.read()

    nonce = get_random_bytes(taille_nonce)
    cipher = ChaCha20_Poly1305.new(key=cle, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(nom_fichier + ".chiffre", "wb") as f:
        _ = f.write(cipher.nonce + tag + ciphertext)

    print(f"Fichier chiffré enregistré sous {nom_fichier}.chiffre")


def chiffrer_dossier(cle: bytes, taille_nonce: int) -> None:
    """
    Chiffrer un dossier en le compressant d'abord en un fichier zip,
    puis en chiffrant ce fichier zip avec la clé donnée.

    === Paramètres ===
    :param cle: La clé de chiffrement
    :param taille_nonce: La taille du nonce utilisée pour le chiffrement
    """
    assert type(cle) is bytes and len(cle) == 32, "Clé invalide"
    assert taille_nonce == 12 or taille_nonce == 8 or taille_nonce == 24

    nom_dossier = input("Entrez le nom du dossier à chiffrer : ")
    zip_nom = nom_dossier + ".zip"

    # compresser le dossier en un fichier zip temporaire
    with zipfile.ZipFile(zip_nom, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(nom_dossier):
            for file in files:
                filepath = os.path.join(root, file)
                zipf.write(filepath, os.path.relpath(filepath, nom_dossier))

    # chiffrer le fichier zip
    with open(zip_nom, "rb") as f:
        data = f.read()

    nonce = get_random_bytes(taille_nonce)
    cipher = ChaCha20_Poly1305.new(key=cle, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(zip_nom + ".chiffre", "wb") as f:
        _ = f.write(cipher.nonce + tag + ciphertext)

    os.remove(zip_nom)  # supprimer le fichier zip temporaire
    print(f"Dossier chiffré et enregistré sous {zip_nom}.chiffre")


def chiffrement() -> None:
    """
    chiffrer un message, un fichier ou un dossier en fonction du choix de l'utilisateur.
    """
    choix = input(
        "Voulez-vous chiffrer un message (1), un fichier (2) ou un dossier (3) ? "
    )
    cle, taille_nonce = charger_cle()
    if cle is None or taille_nonce is None:
        return
    if choix == "1":
        chiffrer_message(cle, taille_nonce)
    elif choix == "2":
        chiffrer_fichier(cle, taille_nonce)
    elif choix == "3":
        chiffrer_dossier(cle, taille_nonce)
    else:
        print("Choix invalide.")


def dechiffrer(data: bytes, cle: bytes, taille_nonce: int) -> bytes | None:
    """
    Déchiffre les données avec l'algorithme ChaCha20 en prenant en argument
    les données à déchiffrer, la clé de déchiffrement et la taille du nonce.
    Renvoie None si le déchiffrement est impossible

    :param data: Les données à déchiffrer
    :param cle: La clé de déchiffrement
    :param taille_nonce: La taille du nonce utilisé
    :return: Les données déchiffrés ou None si erreur
    """
    assert type(cle) is bytes and len(cle) == 32, "Clé invalide"
    assert taille_nonce == 12 or taille_nonce == 8 or taille_nonce == 24
    assert type(data) is bytes and len(data) > taille_nonce + 16

    # le nonce l'as pas toujours la même taille, on le récupère en fonction de la taille définie
    nonce: bytes = data[:taille_nonce]
    tag: bytes = data[taille_nonce: taille_nonce + 16]
    ciphertext: bytes = data[taille_nonce + 16:]
    cipher = ChaCha20_Poly1305.new(key=cle, nonce=nonce)
    donnees = None
    try:
        donnees = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        print("Échec de la vérification du tag. Le message peut avoir été altéré ou être chiffré avec une clé "
              "différente.")
    return donnees


assert dechiffrer(b64decode("UVNJWHYifRpuXyqmt3EFGkyKs6WhzbFMSmC0GMVyOwY="),
                  b64decode("jXgGOPjUipRoY+qR+u4AUjfItE1NX8P81DY7o47YTvg="),
                  12) == b'True'


def dechiffrer_message(cle: bytes, taille_nonce: int) -> None:
    """
    déchiffrer un message chiffré en base64 avec la clé donnée et afficher le message déchiffré.

    :param cle: La clé de déchiffrement
    :param taille_nonce: La taille du nonce utilisée pour le chiffrement
    """
    assert type(cle) is bytes and len(cle) == 32, "Clé invalide"
    assert taille_nonce == 12 or taille_nonce == 8 or taille_nonce == 24

    data_b64 = input("Entrez le message chiffré en base64 : ")
    data = b64decode(data_b64)
    plaintext = dechiffrer(data, cle, taille_nonce)
    if plaintext is None:
        return
    print("Message déchiffré :")
    print(plaintext.decode("utf-8"))


def lire_fichier_chiffre(fichier: str) -> bytes | None:
    """
    Lire un fichier chiffré et retourner ses données.
    Vérifie aussi que le fichier existe et renvoie None s'il n'existe pas

    === Paramètres ===
    :param fichier: le nom du fichier chiffré

    === Retourne ===
    :return: les données du fichier chiffré, ou None si le fichier n'existe pas
    """
    assert type(fichier) is str

    if not fichier.endswith(".chiffre"):
        fichier += ".chiffre"
    if not os.path.exists(fichier):
        print("Fichier non trouvé.")
        return None
    with open(fichier, "rb") as f:
        data = f.read()

    assert type(data) is bytes
    return data


def dechiffrer_fichier(cle: bytes, taille_nonce: int) -> None:
    """
    déchiffrer un fichier chiffré avec la clé donnée et enregistrer le fichier déchiffré.

    === Paramètres ===
    :param cle: la clé de déchiffrement
    :param taille_nonce: la taille du nonce utilisée pour le chiffrement
    """
    assert type(cle) is bytes and len(cle) == 32, "Clé invalide"
    assert taille_nonce == 12 or taille_nonce == 8 or taille_nonce == 24

    nom_fichier = input("Entrez le nom du fichier à déchiffrer : ")
    data = lire_fichier_chiffre(nom_fichier)
    if data is None:
        return
    plaintext = dechiffrer(data, cle, taille_nonce)
    if plaintext is None:
        return

    with open(nom_fichier.replace(".chiffre", ""), "wb") as f:
        _ = f.write(plaintext)
    print(
        f"Fichier déchiffré enregistré sous {nom_fichier.replace('.chiffre', '')}"
    )


def lire_dossier_chiffre(dossier: str) -> bytes | None:
    """
    Lire un dossier chiffré (fichier zip.chiffre) et retourner ses données.
    Vérifie aussi que le fichier existe et renvoie None s'il n'existe pas

    === Paramètres ===
    :param dossier: le nom du dossier chiffré (fichier zip.chiffre)

    === Retourne ===
    :return: retourne les données du dossier chiffré, ou None si le fichier n'existe pas
    """
    assert type(dossier) is str

    if not dossier.endswith(".zip.chiffre"):
        dossier += ".zip.chiffre"
    if not os.path.exists(dossier):
        print("Fichier non trouvé.")
        return None
    with open(dossier, "rb") as f:
        data = f.read()

    assert type(data) is bytes
    return data


def dechiffrer_dossier(cle: bytes, taille_nonce: int) -> None:
    """
    Déchiffrer un dossier chiffré (fichier zip.chiffre) avec la clé donnée, extraire le fichier zip
    et enregistrer le dossier déchiffré.

    === Paramètres ===
    :param cle: la clé de déchiffrement
    :param taille_nonce: la taille du nonce utilisée pour le chiffrement
    """
    assert type(cle) is bytes and len(cle) == 32, "Clé invalide"
    assert taille_nonce == 12 or taille_nonce == 8 or taille_nonce == 24

    dossier = input("Entrez le nom du dossier à déchiffrer (fichier .zip.chiffre) : ")
    data = lire_dossier_chiffre(dossier)
    if data is None:
        return

    plaintext = dechiffrer(data, cle, taille_nonce)
    if plaintext is None:
        return

    zip_nom = dossier.replace(".chiffre", "")
    with open(zip_nom, "wb") as f:
        _ = f.write(plaintext)
    # extraire le fichier zip
    with zipfile.ZipFile(zip_nom, "r") as zipf:
        zipf.extractall(dossier.replace(".zip.chiffre", ""))
    os.remove(zip_nom)  # supprimer le fichier zip temporaire
    print(
        f"Dossier déchiffré et extrait sous {dossier.replace('.zip.chiffre', '')}"
    )


def dechiffrement() -> None:
    """
    déchiffrer un message, un fichier ou un dossier en fonction du choix de l'utilisateur.
    """
    choix = input(
        "Voulez-vous déchiffrer un message (1), un fichier (2) ou un dossier compressé (3) ? "
    )
    cle, taille_nonce = charger_cle()
    if cle is None or taille_nonce is None:
        return
    if choix == "1":
        dechiffrer_message(cle, taille_nonce)
    elif choix == "2":
        dechiffrer_fichier(cle, taille_nonce)
    elif choix == "3":
        dechiffrer_dossier(cle, taille_nonce)
    else:
        print("Choix invalide.")


def select_option(choice: str) -> bool:
    """
    sélectionner l'option en fonction du choix de l'utilisateur.

    === Paramètres ===
    :param choice: Le choix de l'utilisateur entre 1 et 4.

    === Retourne ===
    :return: True si l'utilisateur continue, sinon False
    """
    assert type(choice) is str

    match choice:
        case "1":
            chiffrement()
        case "2":
            dechiffrement()
        case "3":
            nouvelle_cle()
        case "4":
            print("Au revoir!")
            return False
        case _:
            pass
    return True


def menu() -> None:
    """
    Le menu principal de l'application
    """
    continuer: bool = True
    while continuer:
        print(
            "1 pour chiffrer, 2 pour déchiffrer, 3 pour entrer ou créer une nouvelle clé, 4 pour quitter"
        )
        choice: str = input("Choix : ")
        continuer = select_option(choice)


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\nau revoir")
