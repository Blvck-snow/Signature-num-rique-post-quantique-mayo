import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import ctypes
import os
import sys
import json

# =============================================================================
# COULEURS ET STYLE (CONFIGURATION DU DESIGN)
# =============================================================================
COLOR_BG_DARK = "#1e1e1e"       # Fond principal (Noir/Gris foncé)
COLOR_BG_PANEL = "#2d2d2d"      # Fond des panneaux/onglets
COLOR_ACCENT = "#007acc"        # Bleu Cyber (Boutons principaux)
COLOR_ACCENT_HOVER = "#005f9e"  # Bleu plus foncé au survol
COLOR_TEXT = "#ffffff"          # Texte blanc
COLOR_TEXT_DIM = "#aaaaaa"      # Texte secondaire (gris clair)
COLOR_ENTRY_BG = "#3e3e3e"      # Fond des champs de saisie
COLOR_ERROR = "#d32f2f"         # Rouge (Erreur)
COLOR_SUCCESS = "#388e3c"       # Vert (Succès)

# =============================================================================
# PARTIE 1 : BACKEND (Cryptographie C - Inchangé)
# =============================================================================

class MayoBinding:
    def __init__(self):
        self.lib = None
        self.params = None
        self._charger_bibliotheque()
        self._configurer_parametres()

    def _charger_bibliotheque(self):
        dossier_courant = os.path.dirname(os.path.abspath(__file__))
        chemin_so = os.path.join(dossier_courant, "libmayo.so")
        if not os.path.exists(chemin_so):
            raise FileNotFoundError(f"Le fichier {chemin_so} est introuvable.")
        try:
            self.lib = ctypes.CDLL(chemin_so)
        except OSError as e:
            raise Exception(f"Erreur chargement DLL: {e}")

    def _configurer_parametres(self):
        class MayoParamsStruct(ctypes.Structure):
            _fields_ = [
                ("m", ctypes.c_int), ("n", ctypes.c_int), ("o", ctypes.c_int),
                ("k", ctypes.c_int), ("q", ctypes.c_int),
                ("f_tail", ctypes.POINTER(ctypes.c_ubyte)),
                ("m_bytes", ctypes.c_int), ("O_bytes", ctypes.c_int),
                ("v_bytes", ctypes.c_int), ("r_bytes", ctypes.c_int),
                ("R_bytes", ctypes.c_int), ("P1_bytes", ctypes.c_int),
                ("P2_bytes", ctypes.c_int), ("P3_bytes", ctypes.c_int),
                ("csk_bytes", ctypes.c_int), ("cpk_bytes", ctypes.c_int),
                ("sig_bytes", ctypes.c_int), ("salt_bytes", ctypes.c_int),
                ("sk_seed_bytes", ctypes.c_int), ("digest_bytes", ctypes.c_int),
                ("pk_seed_bytes", ctypes.c_int), ("m_vec_limbs", ctypes.c_int),
                ("name", ctypes.c_char_p),
            ]

        self.params = MayoParamsStruct()
        self.params.m = 78
        self.params.n = 86
        self.params.o = 8
        self.params.k = 10
        self.params.q = 16 
        self.params.m_bytes = 39
        self.params.O_bytes = 312
        self.params.v_bytes = 39
        self.params.r_bytes = 40
        self.params.P1_bytes = 120159
        self.params.P2_bytes = 24336
        self.params.P3_bytes = 1404
        self.params.csk_bytes = 24
        self.params.cpk_bytes = 1420
        self.params.sig_bytes = 454
        self.params.salt_bytes = 24
        self.params.sk_seed_bytes = 24
        self.params.digest_bytes = 32
        self.params.pk_seed_bytes = 16
        self.params.m_vec_limbs = 5
        self.params.name = b"MAYO_1"

        f_tail_arr = (ctypes.c_ubyte * 4)(8, 1, 1, 0)
        self.params.f_tail = ctypes.cast(f_tail_arr, ctypes.POINTER(ctypes.c_ubyte))

        self.lib.mayo_keypair_compact.argtypes = [ctypes.POINTER(MayoParamsStruct), ctypes.c_char_p, ctypes.c_char_p]
        self.lib.mayo_keypair_compact.restype = ctypes.c_int

        self.lib.mayo_sign_signature.argtypes = [
            ctypes.POINTER(MayoParamsStruct), ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p
        ]
        self.lib.mayo_sign_signature.restype = ctypes.c_int

        self.lib.mayo_verify.argtypes = [
            ctypes.POINTER(MayoParamsStruct), ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p
        ]
        self.lib.mayo_verify.restype = ctypes.c_int

    def generer_cles(self):
        cpk = ctypes.create_string_buffer(self.params.cpk_bytes)
        csk = ctypes.create_string_buffer(self.params.csk_bytes)
        if self.lib.mayo_keypair_compact(ctypes.byref(self.params), cpk, csk) != 0:
            raise Exception("Erreur génération clés")
        return cpk.raw, csk.raw

    def signer(self, message_bytes, secret_key_bytes):
        sig_buffer = ctypes.create_string_buffer(self.params.sig_bytes)
        sig_len = ctypes.c_size_t(self.params.sig_bytes)
        c_sk = ctypes.create_string_buffer(secret_key_bytes, len(secret_key_bytes))

        res = self.lib.mayo_sign_signature(
            ctypes.byref(self.params), sig_buffer, ctypes.byref(sig_len),
            message_bytes, len(message_bytes), c_sk
        )
        if res != 0: raise Exception("Échec de la signature C")
        return sig_buffer.raw

    def verifier(self, message_bytes, signature_bytes, public_key_bytes):
        c_pk = ctypes.create_string_buffer(public_key_bytes, len(public_key_bytes))
        c_sig = ctypes.create_string_buffer(signature_bytes, len(signature_bytes))

        res = self.lib.mayo_verify(
            ctypes.byref(self.params), message_bytes, len(message_bytes),
            c_sig, c_pk
        )
        return res == 0

# =============================================================================
# PARTIE 2 : FRONTEND (NOUVEAU DESIGN)
# =============================================================================

class MayoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MAYO Secure Signer")
        self.root.geometry("700x700")
        self.root.configure(bg=COLOR_BG_DARK)
        
        # Configuration du style (Look & Feel)
        self._configure_style()

        try:
            self.mayo = MayoBinding()
            self.status_text = " SYSTÈME CRYPTOGRAPHIQUE ACTIF "
            self.status_color = COLOR_ACCENT
        except Exception as e:
            self.mayo = None
            self.status_text = f" ERREUR : {str(e)} "
            self.status_color = COLOR_ERROR

        self._setup_ui()

    def _configure_style(self):
        style = ttk.Style()
        try:
            style.theme_use('clam') # Utilise 'clam' comme base
        except:
            pass # Si 'clam' n'existe pas, utilise le defaut

        # Configuration des Onglets (TNotebook)
        style.configure("TNotebook", background=COLOR_BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", 
                        background=COLOR_BG_PANEL, 
                        foreground=COLOR_TEXT, 
                        padding=[20, 10], 
                        font=("Segoe UI", 10))
        style.map("TNotebook.Tab", 
                  background=[("selected", COLOR_ACCENT)], 
                  foreground=[("selected", "white")])

        # Configuration des Frames
        style.configure("TFrame", background=COLOR_BG_DARK)

    def _setup_ui(self):
        # En-tête
        header_frame = tk.Frame(self.root, bg=COLOR_BG_DARK)
        header_frame.pack(fill="x", pady=20)
        
        tk.Label(header_frame, text="MAYO SECURITY", font=("Segoe UI", 24, "bold"), 
                 bg=COLOR_BG_DARK, fg=COLOR_ACCENT).pack()
        # CORRECTION ICI : Suppression de letterspacing
        tk.Label(header_frame, text="SIGNATURE POST-QUANTIQUE CERTIFIÉE", font=("Segoe UI", 10, "bold"), 
                 bg=COLOR_BG_DARK, fg=COLOR_TEXT_DIM).pack()
        
        # Status Bar (Haut)
        status_lbl = tk.Label(self.root, text=self.status_text, bg=self.status_color, fg="white", 
                              font=("Consolas", 9, "bold"), pady=5)
        status_lbl.pack(fill="x", padx=0)

        # Contenu principal (Onglets)
        notebook = ttk.Notebook(self.root)
        notebook.pack(pady=20, padx=20, expand=True, fill="both")

        # --- Onglet 1 : Clés ---
        self._build_keys_tab(notebook)

        # --- Onglet 2 : Signer ---
        self._build_sign_tab(notebook)

        # --- Onglet 3 : Vérifier ---
        self._build_verify_tab(notebook)

    # -------------------------------------------------------------------------
    # CONSTRUCTION DES ONGLETS (HELPERS)
    # -------------------------------------------------------------------------

    def _build_keys_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="  GÉNÉRER IDENTITÉ  ")
        
        container = tk.Frame(frame, bg=COLOR_BG_PANEL, padx=30, pady=30)
        container.pack(expand=True, fill="both", padx=10, pady=10)

        tk.Label(container, text="Création d'une nouvelle identité", bg=COLOR_BG_PANEL, fg=COLOR_ACCENT, font=("Segoe UI", 14, "bold")).pack(pady=(0, 10))
        tk.Label(container, text="Génère une paire de clés (.json) pour signer vos documents.\nLa clé privée ne doit jamais être partagée.", 
                 bg=COLOR_BG_PANEL, fg=COLOR_TEXT_DIM, justify="center").pack(pady=(0, 30))

        self.btn_gen = self._create_button(container, "GÉNÉRER LES CLÉS", self.action_generer_cles, icon_char="🔑")
        self.btn_gen.pack(pady=10, ipadx=20)

        self.lbl_keys_info = tk.Label(container, text="En attente de génération...", bg=COLOR_BG_PANEL, fg=COLOR_TEXT_DIM, font=("Consolas", 9))
        self.lbl_keys_info.pack(pady=20)

    def _build_sign_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="  SIGNER DOCUMENT  ")

        container = tk.Frame(frame, bg=COLOR_BG_PANEL, padx=30, pady=30)
        container.pack(expand=True, fill="both", padx=10, pady=10)

        # Champ 1 : Identité
        self._create_label_input(container, "VOTRE NOM (IDENTITÉ) :", "ex: Dr. Elie")
        self.entry_nom = self._create_entry(container)
        self.entry_nom.pack(fill="x", pady=(5, 20))

        # Champ 2 : Fichier
        self._create_label_input(container, "FICHIER À SIGNER :", "Image, PDF, Texte...")
        frm_file = tk.Frame(container, bg=COLOR_BG_PANEL)
        frm_file.pack(fill="x", pady=(5, 20))
        self.entry_file_sign = self._create_entry(frm_file)
        self.entry_file_sign.pack(side="left", fill="x", expand=True)
        self._create_small_btn(frm_file, "...", lambda: self._browser_file(self.entry_file_sign)).pack(side="right", padx=(5,0))

        # Champ 3 : Clé Privée
        self._create_label_input(container, "VOTRE CLÉ PRIVÉE (_SK.JSON) :", "Fichier confidentiel")
        frm_sk = tk.Frame(container, bg=COLOR_BG_PANEL)
        frm_sk.pack(fill="x", pady=(5, 30))
        self.entry_sk_sign = self._create_entry(frm_sk)
        self.entry_sk_sign.pack(side="left", fill="x", expand=True)
        self._create_small_btn(frm_sk, "...", lambda: self._browser_file(self.entry_sk_sign, "json")).pack(side="right", padx=(5,0))

        # Bouton Action
        self._create_button(container, "SCELLER ET SIGNER", self.action_signer, bg_color=COLOR_ACCENT).pack(fill="x", pady=10)

    def _build_verify_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="  VÉRIFIER & CONTRÔLER  ")

        container = tk.Frame(frame, bg=COLOR_BG_PANEL, padx=30, pady=30)
        container.pack(expand=True, fill="both", padx=10, pady=10)

        # Zone Sécurité
        sec_frame = tk.Frame(container, bg="#3d2b2b", padx=10, pady=10, highlightbackground=COLOR_ERROR, highlightthickness=1)
        sec_frame.pack(fill="x", pady=(0, 20))
        tk.Label(sec_frame, text="⚠️ CONTRÔLE DE SÉCURITÉ", bg="#3d2b2b", fg=COLOR_ERROR, font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(sec_frame, text="NOM ATTENDU DU SIGNATAIRE :", bg="#3d2b2b", fg="white", font=("Segoe UI", 8)).pack(anchor="w", pady=(5,0))
        self.entry_nom_verif = tk.Entry(sec_frame, bg="#5c3a3a", fg="white", relief="flat", insertbackground="white", font=("Segoe UI", 10))
        self.entry_nom_verif.pack(fill="x", pady=5, ipady=3)

        # Inputs standards
        self._create_label_input(container, "FICHIER ORIGINAL :")
        frm_1 = tk.Frame(container, bg=COLOR_BG_PANEL); frm_1.pack(fill="x", pady=(2, 10))
        self.entry_file_verif = self._create_entry(frm_1); self.entry_file_verif.pack(side="left", fill="x", expand=True)
        self._create_small_btn(frm_1, "...", lambda: self._browser_file(self.entry_file_verif)).pack(side="right", padx=5)

        self._create_label_input(container, "SIGNATURE (_SIG.JSON) :")
        frm_2 = tk.Frame(container, bg=COLOR_BG_PANEL); frm_2.pack(fill="x", pady=(2, 10))
        self.entry_sig_verif = self._create_entry(frm_2); self.entry_sig_verif.pack(side="left", fill="x", expand=True)
        self._create_small_btn(frm_2, "...", lambda: self._browser_file(self.entry_sig_verif, "json")).pack(side="right", padx=5)

        self._create_label_input(container, "CLÉ PUBLIQUE DE L'ÉMETTEUR (_PK.JSON) :")
        frm_3 = tk.Frame(container, bg=COLOR_BG_PANEL); frm_3.pack(fill="x", pady=(2, 20))
        self.entry_pk_verif = self._create_entry(frm_3); self.entry_pk_verif.pack(side="left", fill="x", expand=True)
        self._create_small_btn(frm_3, "...", lambda: self._browser_file(self.entry_pk_verif, "json")).pack(side="right", padx=5)

        # Bouton Action
        self._create_button(container, "VÉRIFIER L'AUTHENTICITÉ", self.action_verifier, bg_color=COLOR_SUCCESS).pack(fill="x")
        
        self.lbl_result = tk.Label(container, text="", bg=COLOR_BG_PANEL, font=("Segoe UI", 12, "bold"))
        self.lbl_result.pack(pady=20)

    # -------------------------------------------------------------------------
    # COMPOSANTS GRAPHIQUES PERSONNALISÉS (DESIGN SYSTEM)
    # -------------------------------------------------------------------------

    def _create_label_input(self, parent, text, subtext=None):
        frame = tk.Frame(parent, bg=COLOR_BG_PANEL)
        frame.pack(fill="x")
        tk.Label(frame, text=text, bg=COLOR_BG_PANEL, fg=COLOR_TEXT, font=("Segoe UI", 9, "bold")).pack(side="left")
        if subtext:
            tk.Label(frame, text=f"  {subtext}", bg=COLOR_BG_PANEL, fg=COLOR_TEXT_DIM, font=("Segoe UI", 8, "italic")).pack(side="left")

    def _create_entry(self, parent):
        return tk.Entry(parent, bg=COLOR_ENTRY_BG, fg="white", insertbackground="white", 
                        relief="flat", font=("Consolas", 10))

    def _create_button(self, parent, text, command, bg_color=COLOR_ACCENT, icon_char=""):
        btn = tk.Button(parent, text=f"{icon_char}  {text}" if icon_char else text, 
                        command=command, 
                        bg=bg_color, fg="white", 
                        activebackground="white", activeforeground=bg_color,
                        relief="flat", font=("Segoe UI", 11, "bold"), cursor="hand2")
        return btn

    def _create_small_btn(self, parent, text, command):
        return tk.Button(parent, text=text, command=command, bg=COLOR_ENTRY_BG, fg="white", relief="flat", cursor="hand2")

    def _browser_file(self, entry, filetype="all"):
        types = [("Fichiers JSON", "*.json"), ("Tous", "*.*")] if filetype == "json" else [("Tous", "*.*")]
        f = filedialog.askopenfilename(filetypes=types)
        if f:
            entry.delete(0, tk.END)
            entry.insert(0, f)

    # -------------------------------------------------------------------------
    # LOGIQUE MÉTIER (INCHANGÉE)
    # -------------------------------------------------------------------------

    def _preparer_donnees(self, nom_str, contenu_fichier_bytes):
        return nom_str.strip().encode('utf-8') + b'\x00||MAYO_SIGNED||\x00' + contenu_fichier_bytes

    def action_generer_cles(self):
        try:
            pk_raw, sk_raw = self.mayo.generer_cles()
            path = filedialog.asksaveasfilename(title="Enregistrer clés", initialfile="identite")
            if not path: return
            
            pk_data = {"type": "MAYO_PUBLIC_KEY", "key_hex": pk_raw.hex()}
            sk_data = {"type": "MAYO_SECRET_KEY", "key_hex": sk_raw.hex()}

            with open(path + "_pk.json", "w") as f: json.dump(pk_data, f, indent=4)
            with open(path + "_sk.json", "w") as f: json.dump(sk_data, f, indent=4)
            
            self.lbl_keys_info.config(text=f"✅ SUCCÈS : Clés enregistrées dans {os.path.dirname(path)}", fg=COLOR_SUCCESS)
            messagebox.showinfo("Succès", "Identité numérique générée avec succès.")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def action_signer(self):
        nom = self.entry_nom.get().strip()
        f_path = self.entry_file_sign.get()
        sk_json_path = self.entry_sk_sign.get()

        if not nom or not f_path or not sk_json_path:
            messagebox.showwarning("Erreur", "Tous les champs sont obligatoires.")
            return

        try:
            with open(sk_json_path, "r") as f: sk_data = json.load(f)
            sk_bytes = bytes.fromhex(sk_data["key_hex"])
            with open(f_path, "rb") as f: file_content = f.read()

            donnees = self._preparer_donnees(nom, file_content)
            signature_raw = self.mayo.signer(donnees, sk_bytes)

            sig_data = {
                "type": "MAYO_SIGNATURE_PROOF",
                "signataire": nom,
                "signature_hex": signature_raw.hex()
            }
            save_path = f_path + "_sig.json"
            with open(save_path, "w") as f: json.dump(sig_data, f, indent=4)
            messagebox.showinfo("Succès", f"Document signé et scellé.\nSignature : {save_path}")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def action_verifier(self):
        nom_attendu = self.entry_nom_verif.get().strip()
        f_path = self.entry_file_verif.get()
        sig_json_path = self.entry_sig_verif.get()
        pk_json_path = self.entry_pk_verif.get()

        self.lbl_result.config(text="")

        if not nom_attendu or not f_path or not sig_json_path or not pk_json_path:
            messagebox.showwarning("Erreur", "Remplissez tous les champs, y compris le Nom Attendu.")
            return

        try:
            with open(sig_json_path, "r") as f: sig_data = json.load(f)
            if nom_attendu != sig_data.get("signataire", "").strip():
                self.lbl_result.config(text="⛔ USURPATION DÉTECTÉE (NOM INCORRECT)", fg=COLOR_ERROR)
                messagebox.showerror("Alerte Sécurité", "Le nom dans la signature ne correspond pas au nom attendu.")
                return

            with open(pk_json_path, "r") as f: pk_data = json.load(f)
            pk_bytes = bytes.fromhex(pk_data["key_hex"])
            sig_bytes = bytes.fromhex(sig_data["signature_hex"])
            with open(f_path, "rb") as f: file_content = f.read()

            donnees_a_verifier = self._preparer_donnees(nom_attendu, file_content)
            est_valide = self.mayo.verifier(donnees_a_verifier, sig_bytes, pk_bytes)

            if est_valide:
                self.lbl_result.config(text=f"✅ AUTHENTIQUE : {nom_attendu.upper()}", fg=COLOR_SUCCESS)
                messagebox.showinfo("Vérification", "Le document est authentique et signé par la bonne personne.")
            else:
                self.lbl_result.config(text="❌ PREUVE MATHÉMATIQUE INVALIDE", fg=COLOR_ERROR)
                messagebox.showerror("Erreur", "Signature cryptographique invalide.")

        except Exception as e:
            messagebox.showerror("Erreur Technique", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = MayoApp(root)
    root.mainloop()