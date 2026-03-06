#!/usr/bin/env python3
"""
Ce programme a été créé par Nitnelav00

Un outil de chiffrement et déchiffrement de dossier, fichier et texte
utilisant l'algorithme ChaCha20 Poly1305
Avec une interface graphique simple et intuitive pour faciliter son utilisation

Converti chaque fonction en une fenêtre séparée pour une meilleure organisation et une expérience utilisateur améliorée
"""

import os
import sys
import zipfile
from base64 import b64decode, b64encode
from hashlib import sha256

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

from tkinter import Tk, Label, Entry, Button, Text, END, filedialog, messagebox, ttk


def get_taille_nonce() -> int:
    # la taille du nonce est indiquée dans la deuxième ligne du fichier de la clé
    with open("cle.txt", "r") as f:
        lines = f.readlines()
        if len(lines) >= 2:
            taille_nonce = int(lines[1].strip())
            if taille_nonce == 8 or taille_nonce == 12 or taille_nonce == 24:
                return taille_nonce
            else:
                messagebox.showwarning("taille du nonce invalide", "La taille du nonce est invalide. Utilisation de la taille par défaut (12).")
    return 12  # Valeur par défaut si la clé n'est pas trouvée ou mal formatée


def get_cle() -> bytes | None:
    # la clé est indiquée dans la première ligne du fichier de la clé
    with open("cle.txt", "r") as f:
        lines = f.readlines()
        if len(lines) >= 1:
            return b64decode(lines[0].strip())
    return None  # Retourne None si la clé n'est pas trouvée ou mal formatée


class TextChiffrer(Tk):
    def __init__(self):
        super().__init__()
        self.title("Chiffrement de texte")
        self.geometry("340x350")
        self.label = Label(self, text="Entrez le texte à chiffrer:")
        self.label.pack(pady=10)
        self.text_input = Text(self, height=10, width=40)
        self.text_input.pack(pady=5)
        self.btn_chiffrer = Button(self, text="Chiffrer", command=self.chiffrer_texte)
        self.btn_chiffrer.pack(pady=5)
        self.btn_retour = Button(self, text="Retour", command=self.retour_menu)
        self.btn_retour.pack(pady=5)

    def chiffrer_texte(self):
        texte = self.text_input.get("1.0", END).strip()
        if texte:
            nonce = get_random_bytes(get_taille_nonce())
            cipher = ChaCha20_Poly1305.new(key=get_cle(), nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(texte.encode())
            resultat = b64encode(nonce + tag + ciphertext).decode()
            copier = messagebox.askokcancel("Résultat du chiffrement",
                                            f"Texte chiffré:\n{resultat}\n\nVoulez-vous copier le résultat dans le presse-papiers ?")
            if copier:
                self.clipboard_clear()
                self.clipboard_append(resultat)
                messagebox.showinfo("Copié", "Le texte chiffré a été copié dans le presse-papiers.")
        else:
            messagebox.showerror("Erreur", "Veuillez entrer du texte à chiffrer.")

    def retour_menu(self):
        self.destroy()
        Chiffrer()


class Chiffrer(Tk):
    def __init__(self):
        super().__init__()
        self.title("Chiffrement ChaCha20 Poly1305")
        self.geometry("400x260")
        self.label = Label(self, text="Chiffrement de dossier, fichier ou texte")
        self.label.pack(pady=10)
        self.btn_dossier = Button(self, text="Chiffrer un dossier", command=self.chiffrer_dossier)
        self.btn_dossier.pack(pady=5)
        self.btn_fichier = Button(self, text="Chiffrer un fichier", command=self.chiffrer_fichier)
        self.btn_fichier.pack(pady=5)
        self.btn_texte = Button(self, text="Chiffrer du texte", command=self.chiffrer_texte)
        self.btn_texte.pack(pady=5)
        self.btn_retour = Button(self, text="Retour au menu", command=self.retour_menu)
        self.btn_retour.pack(pady=5)

    @staticmethod
    def chiffrer_dossier():
        # Fonction pour chiffrer un dossier
        nom_dossier = filedialog.askdirectory(title="Sélectionnez un dossier à chiffrer")
        if nom_dossier:
            # Créer un fichier zip du dossier sélectionné
            zip_nom = nom_dossier + ".zip"
            print(zip_nom)
            with zipfile.ZipFile(zip_nom, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(nom_dossier):
                    for file in files:
                        filepath = os.path.join(root, file)
                        zipf.write(filepath, os.path.relpath(filepath, nom_dossier))
            with open(zip_nom, 'rb') as f:
                data = f.read()
            nonce = get_random_bytes(get_taille_nonce())
            cipher = ChaCha20_Poly1305.new(key=get_cle(), nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            with open(nom_dossier + ".chiffre", 'wb') as f:
                f.write(nonce + tag + ciphertext)
            os.remove(zip_nom)
            # vérifier que le fichier a été créé et afficher un message de succès
            if os.path.exists(nom_dossier + ".chiffre"):
                messagebox.showinfo("Succès", f"Dossier {zip_nom} chiffré avec succès !")
            else:
                messagebox.showerror("Erreur", f"Une erreur est survenue lors du chiffrement du dossier {zip_nom}.")

    @staticmethod
    def chiffrer_fichier():
        # Fonction pour chiffrer un fichier
        nom_fichier = filedialog.askopenfilename(title="Sélectionnez un fichier à chiffrer")
        if nom_fichier:
            with open(nom_fichier, 'rb') as f:
                data = f.read()
            nonce = get_random_bytes(get_taille_nonce())
            cipher = ChaCha20_Poly1305.new(key=get_cle(), nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            with open(nom_fichier + ".chiffre", 'wb') as f:
                f.write(nonce + tag + ciphertext)
            # vérifier que le fichier a été créé et afficher un message de succès
            if os.path.exists(nom_fichier + ".chiffre"):
                messagebox.showinfo("Succès", f"Fichier {nom_fichier} chiffré avec succès !")
            else:
                messagebox.showerror("Erreur", f"Une erreur est survenue lors du chiffrement du fichier {nom_fichier}.")
        else:
            messagebox.showerror("Fichier non séléctionné", "Aucun fichier n'a été séléctionné.")

    def chiffrer_texte(self):
        # Fonction pour chiffrer du texte
        self.destroy()
        TextChiffrer()

    def retour_menu(self):
        self.destroy()
        Menu()


class TextDechiffrer(Tk):
    def __init__(self):
        super().__init__()
        self.title("Déchiffrement de texte")
        self.geometry("340x350")
        self.label = Label(self, text="Entrez le texte à déchiffrer:")
        self.label.pack(pady=10)
        self.text_input = Text(self, height=10, width=40)
        self.text_input.pack(pady=5)
        self.btn_dechiffrer = Button(self, text="Déchiffrer", command=self.dechiffrer_texte)
        self.btn_dechiffrer.pack(pady=5)
        self.btn_retour = Button(self, text="Retour", command=self.retour_menu)
        self.btn_retour.pack(pady=5)

    def dechiffrer_texte(self):
        texte_chiffre = self.text_input.get("1.0", END).strip()
        if texte_chiffre:
            try:
                data = b64decode(texte_chiffre)
                nonce = data[:get_taille_nonce()]
                tag = data[get_taille_nonce():get_taille_nonce() + 16]
                ciphertext = data[get_taille_nonce() + 16:]
                cipher = ChaCha20_Poly1305.new(key=get_cle(), nonce=nonce)
                decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
                messagebox.showinfo("Résultat du déchiffrement", f"Texte déchiffré:\n{decrypted_data.decode()}")
            except Exception as e:
                messagebox.showerror("Erreur",
                                     f"Une erreur est survenue lors du déchiffrement du texte.\nDétails: {str(e)}")
        else:
            messagebox.showerror("Erreur", "Veuillez entrer du texte à déchiffrer.")

    def retour_menu(self):
        self.destroy()
        Dechiffrer()


class Dechiffrer(Tk):
    def __init__(self):
        super().__init__()
        self.title("Déchiffrement ChaCha20 Poly1305")
        self.geometry("400x300")
        self.label = Label(self, text="Déchiffrement de dossier, fichier ou texte")
        self.label.pack(pady=10)
        self.btn_dossier = Button(self, text="Déchiffrer un dossier", command=self.dechiffrer_dossier)
        self.btn_dossier.pack(pady=5)
        self.btn_fichier = Button(self, text="Déchiffrer un fichier", command=self.dechiffrer_fichier)
        self.btn_fichier.pack(pady=5)
        self.btn_texte = Button(self, text="Déchiffrer du texte", command=self.dechiffrer_texte)
        self.btn_texte.pack(pady=5)
        self.btn_retour = Button(self, text="Retour au menu", command=self.retour_menu)
        self.btn_retour.pack(pady=5)

    @staticmethod
    def dechiffrer_dossier():
        # Fonction pour déchiffrer un dossier
        nom_fichier = filedialog.askopenfilename(title="Sélectionnez un fichier .chiffre à déchiffrer",
                                                 filetypes=[("Fichiers chiffrés", "*.chiffre")])
        if nom_fichier:
            with open(nom_fichier, 'rb') as f:
                data = f.read()
            nonce = data[:get_taille_nonce()]
            tag = data[get_taille_nonce():get_taille_nonce() + 16]
            ciphertext = data[get_taille_nonce() + 16:]
            cipher = ChaCha20_Poly1305.new(key=get_cle(), nonce=nonce)
            try:
                decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
                zip_nom = nom_fichier.replace(".chiffre", ".zip")
                with open(zip_nom, 'wb') as f:
                    f.write(decrypted_data)
                with zipfile.ZipFile(zip_nom, 'r') as zipf:
                    zipf.extractall(nom_fichier.replace(".chiffre", ""))
                os.remove(zip_nom)
                messagebox.showinfo("Succès", f"Dossier {nom_fichier} déchiffré avec succès !")
            except Exception as e:
                messagebox.showerror("Erreur",
                                     f"Une erreur est survenue lors du déchiffrement du dossier {nom_fichier}.\nDétails: {str(e)}")

    @staticmethod
    def dechiffrer_fichier():
        # Fonction pour déchiffrer un fichier
        nom_fichier = filedialog.askopenfilename(title="Sélectionnez un fichier .chiffre à déchiffrer",
                                                 filetypes=[("Fichiers chiffrés", "*.chiffre")])
        if nom_fichier:
            with open(nom_fichier, 'rb') as f:
                data = f.read()
            nonce = data[:get_taille_nonce()]
            tag = data[get_taille_nonce():get_taille_nonce() + 16]
            ciphertext = data[get_taille_nonce() + 16:]
            cipher = ChaCha20_Poly1305.new(key=get_cle(), nonce=nonce)
            try:
                decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
                with open(nom_fichier.replace(".chiffre", ".dechiffre"), 'wb') as f:
                    f.write(decrypted_data)
                messagebox.showinfo("Succès", f"Fichier {nom_fichier} déchiffré avec succès !")
            except Exception as e:
                messagebox.showerror("Erreur",
                                     f"Une erreur est survenue lors du déchiffrement du fichier {nom_fichier}.\nDétails: {str(e)}")

    def dechiffrer_texte(self):
        # Fonction pour déchiffrer du texte
        self.destroy()
        TextDechiffrer()

    def retour_menu(self):
        self.destroy()
        Menu()


class MotDePasse(Tk):
    def __init__(self):
        super().__init__()
        self.title("Ajouter un mot de passe")
        self.geometry("400x250")
        self.label = Label(self, text="Entrez un mot de passe pour générer une clé dérivée:")
        self.label.pack(pady=10)
        self.taille_nonce_label = Label(self, text="Taille du nonce (en octets, généralement 12 pour ChaCha20):")
        self.taille_nonce_label.pack(pady=5)
        nonce_values = ["8", "12", "24"]
        self.taille_nonce = ttk.Combobox(self, values=nonce_values, state="readonly")
        self.taille_nonce.current(1)  # Sélectionne 12 par défaut
        self.taille_nonce.pack(pady=5)
        self.entry_mot_de_passe = Entry(self, show="*", width=30)
        self.entry_mot_de_passe.pack(pady=5)
        self.btn_generer = Button(self, text="Générer la clé dérivée", command=self.generer_cle_deriv)
        self.btn_generer.pack(pady=5)
        self.btn_retour = Button(self, text="Retour", command=self.retour_menu)
        self.btn_retour.pack(pady=5)

    def generer_cle_deriv(self):
        mot_de_passe = self.entry_mot_de_passe.get()
        if mot_de_passe:
            # Générer une clé dérivée à partir du mot de passe en utilisant SHA-256
            cle_deriv = sha256(mot_de_passe.encode()).digest()
            with open("cle.txt", "w") as f:
                f.write(b64encode(cle_deriv).decode() + "\n")
                f.write(self.taille_nonce.get() + "\n")
            messagebox.showinfo("Succès",
                                "Une clé dérivée a été générée à partir du mot de passe et enregistrée dans cle.txt !")
        else:
            messagebox.showerror("Erreur", "Veuillez entrer un mot de passe pour générer une clé dérivée.")

    def retour_menu(self):
        self.destroy()
        GererCles()


class GenererCles(Tk):
    def __init__(self):
        super().__init__()
        self.title("Gérer les clés")
        self.geometry("400x300")
        self.label = Label(self, text="Générer une clé de chiffrement")
        self.label.pack(pady=10)
        self.taille_nonce_label = Label(self, text="Taille du nonce (en octets, généralement 12 pour ChaCha20):")
        self.taille_nonce_label.pack(pady=5)
        nonce_values = ["8", "12", "24"]
        self.taille_nonce = ttk.Combobox(self, values=nonce_values, state="readonly")
        self.taille_nonce.current(1)  # Sélectionne 12 par défaut
        self.taille_nonce.pack(pady=5)
        self.btn_generer = Button(self, text="Générer une nouvelle clé", command=self.generer_cle)
        self.btn_generer.pack(pady=5)

    def generer_cle(self):
        # Fonction pour générer une nouvelle clé
        nouvelle_cle = get_random_bytes(32)
        with open("cle.txt", "w") as f:
            f.write(b64encode(nouvelle_cle).decode() + "\n")
            f.write(self.taille_nonce.get() + "\n")
        messagebox.showinfo("Succès", "Une nouvelle clé a été générée et enregistrée dans cle.txt !")
        self.destroy()
        GererCles()


class GererCles(Tk):
    def __init__(self):
        super().__init__()
        self.title("Gestion des clés")
        self.geometry("400x300")
        self.label = Label(self, text="Gérer les clés de chiffrement")
        self.label.pack(pady=10)
        self.btn_generer = Button(self, text="Générer une nouvelle clé", command=self.generer_cle)
        self.btn_generer.pack(pady=5)
        self.btn_ajouter = Button(self, text="Ajouter une clé existante", command=self.ajouter_cle)
        self.btn_ajouter.pack(pady=5)
        self.btn_mot_de_passe = Button(self, text="Ajouter un mot de passe", command=self.mot_de_passe)
        self.btn_mot_de_passe.pack(pady=5)
        self.btn_retour = Button(self, text="Retour au menu", command=self.retour_menu)
        self.btn_retour.pack(pady=5)

    def generer_cle(self):
        # Fonction pour générer une nouvelle clé
        self.destroy()
        GenererCles()

    @staticmethod
    def ajouter_cle():
        # Fonction pour ajouter une clé existante
        nom_fichier = filedialog.askopenfilename(title="Sélectionnez un fichier de clé à ajouter",
                                                 filetypes=[("Fichiers de clé", "*.txt")])
        if nom_fichier:
            with open(nom_fichier, "r") as f:
                lines = f.readlines()
                if len(lines) >= 2:
                    cle = lines[0].strip()
                    nonce_size = lines[1].strip()
                    with open("cle.txt", "w") as f_cle:
                        f_cle.write(cle + "\n")
                        f_cle.write(nonce_size + "\n")
                    messagebox.showinfo("Succès", "La clé a été ajoutée avec succès !")
                else:
                    messagebox.showerror("Erreur",
                                         "Le fichier de clé est mal formaté. Il doit contenir au moins deux lignes : la clé et la taille du nonce.")

    def mot_de_passe(self):
        # Fonction pour ajouter un mot de passe et générer une clé dérivée
        self.destroy()
        MotDePasse()

    def retour_menu(self):
        self.destroy()
        Menu()


class Menu(Tk):
    def __init__(self):
        super().__init__()
        self.title("Menu Principal")
        self.geometry("300x220")
        self.label = Label(self, text="Choisissez une option:")
        self.label.pack(pady=10)
        self.btn_chiffrer = Button(self, text="Chiffrer", command=self.open_chiffrer)
        self.btn_chiffrer.pack(pady=5)
        self.btn_dechiffrer = Button(self, text="Déchiffrer", command=self.open_dechiffrer)
        self.btn_dechiffrer.pack(pady=5)
        self.btn_cle = Button(self, text="Gérer les clés", command=self.open_gerer_cles)
        self.btn_cle.pack(pady=5)
        self.btn_quitter = Button(self, text="Quitter", command=sys.exit)
        self.btn_quitter.pack(pady=5)

    def open_chiffrer(self):
        self.destroy()
        Chiffrer()

    def open_dechiffrer(self):
        self.destroy()
        Dechiffrer()

    def open_gerer_cles(self):
        self.destroy()
        GererCles()


if __name__ == "__main__":
    app = Menu()
    app.mainloop()
