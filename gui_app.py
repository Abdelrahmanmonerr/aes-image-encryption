import os
from datetime import datetime
import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image
from aes_core import (MODES, generate_key, key_id, save_key, load_key, read_info,
                      encrypt_image, decrypt_image, verify, WrongKeyError, NotEncryptedError)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

PREVIEW = (400, 400)
COMPARE = (180, 180)

MODE_INFO = {
    "ECB": "Each block is encrypted independently. Identical blocks give identical ciphertext, so image patterns stay visible (insecure for images).",
    "CBC": "Each block is XORed with the previous ciphertext block, using a random IV. Patterns are hidden.",
    "CTR": "Turns AES into a stream cipher using a counter and a random nonce. Patterns are hidden, no padding needed.",
    "OFB": "Turns AES into a stream cipher by repeatedly encrypting the IV to produce a keystream. Patterns are hidden, no padding needed.",
}

PAGES = [
    ("encrypt", "Encrypt"),
    ("decrypt", "Decrypt"),
    ("compare", "Compare modes"),
    ("keys", "Key"),
    ("settings", "Settings & Log"),
]

ACCENT, OK, ERR, WARN, MUTED = "#3b82f6", "#22c55e", "#ef4444", "#f59e0b", "gray70"


def unique_path(path):
    base, ext = os.path.splitext(path)
    i, p = 1, path
    while os.path.exists(p):
        p = f"{base}_{i}{ext}"
        i += 1
    return p


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("AES Image Encryption  |  SCE 422e")
        self.geometry("1200x860")
        self.minsize(1050, 760)

        # ---- state
        self.key = generate_key(32)
        self.output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
        self.enc_in = self.enc_out = self.dec_in = self.dec_out = self.cmp_in = None
        self._imgs = {}
        self.pages = {}
        self.ask_var = ctk.BooleanVar(value=False)
        self.verify_var = ctk.BooleanVar(value=True)
        self.autokey_var = ctk.BooleanVar(value=True)
        self.size_var = ctk.StringVar(value="256")

        # ---- layout: nav | content / key bar / status bar
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.build_nav()
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.grid(row=0, column=1, sticky="nsew", padx=20, pady=(16, 6))
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)
        self.build_keybar()
        self.status = ctk.CTkLabel(self, text="Ready.", anchor="w", text_color="gray75")
        self.status.grid(row=2, column=0, columnspan=2, sticky="ew", padx=20, pady=(0, 8))

        self.build_encrypt()
        self.build_decrypt()
        self.build_compare()
        self.build_keys()
        self.build_settings()

        self.update_key_box()
        self.update_out_label()
        self.on_mode("CBC")
        self.show_page("encrypt")
        self.log_msg("Ready. Output folder: " + self.output_dir)

    # ============================================================ navigation
    def build_nav(self):
        nav = ctk.CTkFrame(self, width=220, corner_radius=0)
        nav.grid(row=0, column=0, rowspan=3, sticky="nsew")
        nav.grid_propagate(False)
        nav.pack_propagate(False)

        ctk.CTkLabel(nav, text="AES Image\nEncryptor", font=ctk.CTkFont(size=24, weight="bold"),
                     justify="left").pack(anchor="w", padx=18, pady=(22, 0))
        ctk.CTkLabel(nav, text="ECB  •  CBC  •  CTR", text_color=MUTED).pack(anchor="w", padx=18, pady=(0, 20))

        self.nav_btns = {}
        for name, label in PAGES:
            b = ctk.CTkButton(nav, text=label, anchor="w", height=42, corner_radius=8,
                              fg_color="transparent", text_color=("gray10", "gray90"),
                              hover_color=("gray75", "gray30"),
                              command=lambda n=name: self.show_page(n))
            b.pack(fill="x", padx=12, pady=3)
            self.nav_btns[name] = b

    def build_keybar(self):
        bar = ctk.CTkFrame(self)
        bar.grid(row=1, column=1, sticky="ew", padx=20, pady=(0, 6))
        bar.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(bar, text="KEY", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=MUTED).grid(row=0, column=0, padx=(14, 8), pady=(10, 2))
        self.bar_size = ctk.CTkSegmentedButton(bar, values=["128", "192", "256"],
                                               variable=self.size_var, command=self.on_size_change)
        self.bar_size.grid(row=0, column=1, padx=4, pady=(10, 2))
        ctk.CTkButton(bar, text="Generate", width=90, command=self.new_key).grid(
            row=0, column=2, padx=8, pady=(10, 2))
        self.bar_hex = ctk.CTkLabel(bar, text="", anchor="w", text_color=ACCENT,
                                    font=ctk.CTkFont(family="Consolas", size=13))
        self.bar_hex.grid(row=0, column=3, sticky="ew", padx=8, pady=(10, 2))
        ctk.CTkButton(bar, text="Copy", width=60, fg_color="gray30", hover_color="gray40",
                      command=self.copy_key).grid(row=0, column=4, padx=(4, 14), pady=(10, 2))
        self.bar_meta = ctk.CTkLabel(bar, text="", text_color=MUTED, anchor="w")
        self.bar_meta.grid(row=1, column=0, columnspan=5, sticky="w", padx=14, pady=(0, 8))

    def on_size_change(self, value):
        self.set_key(generate_key(int(value) // 8))
        self.set_status(f"New AES-{value} key generated.", OK)

    def show_page(self, name):
        for n, f in self.pages.items():
            if n != name:
                f.grid_remove()
        self.pages[name].grid()
        for n, b in self.nav_btns.items():
            b.configure(fg_color=ACCENT if n == name else "transparent")

    def new_page(self, name, title, subtitle):
        f = ctk.CTkFrame(self.container, fg_color="transparent")
        f.grid(row=0, column=0, sticky="nsew")
        f.grid_columnconfigure(0, weight=1)
        h = ctk.CTkFrame(f, fg_color="transparent")
        h.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        ctk.CTkLabel(h, text=title, font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(h, text=subtitle, text_color=MUTED).pack(anchor="w")
        self.pages[name] = f
        return f

    def step_label(self, parent, text, row):
        ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(weight="bold")).grid(
            row=row, column=0, padx=(16, 10), pady=10, sticky="w")

    def make_card(self, parent, col, title, uniform):
        card = ctk.CTkFrame(parent)
        card.grid(row=0, column=col, sticky="nsew", padx=5)
        parent.grid_columnconfigure(col, weight=1, uniform=uniform)
        card.grid_rowconfigure(1, weight=1)
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=MUTED).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 0))
        img = ctk.CTkLabel(card, text="No image", text_color="gray50")
        img.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
        cap = ctk.CTkLabel(card, text="", text_color=MUTED, wraplength=220)
        cap.grid(row=2, column=0, pady=(0, 12))
        return img, cap

    # ============================================================ pages
    def build_encrypt(self):
        p = self.new_page("encrypt", "Encrypt", "Choose a plaintext image and a mode, then encrypt it.")
        p.grid_rowconfigure(2, weight=1)

        ctl = ctk.CTkFrame(p)
        ctl.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        ctl.grid_columnconfigure(2, weight=1)

        self.step_label(ctl, "1.  Image", 0)
        ctk.CTkButton(ctl, text="Browse image...", width=150, command=self.enc_browse).grid(row=0, column=1, pady=10)
        self.enc_name = ctk.CTkLabel(ctl, text="No image selected", text_color=MUTED, anchor="w")
        self.enc_name.grid(row=0, column=2, padx=14, sticky="ew")

        self.step_label(ctl, "2.  Mode", 1)
        self.mode_seg = ctk.CTkSegmentedButton(ctl, values=list(MODES), command=self.on_mode)
        self.mode_seg.set("CBC")
        self.mode_seg.grid(row=1, column=1, pady=10)
        self.mode_desc = ctk.CTkLabel(ctl, text="", text_color="gray75", justify="left", anchor="w", wraplength=520)
        self.mode_desc.grid(row=1, column=2, padx=14, sticky="ew")

        self.step_label(ctl, "3.  Run", 2)
        run = ctk.CTkFrame(ctl, fg_color="transparent")
        run.grid(row=2, column=1, columnspan=2, sticky="w", pady=(4, 14))
        ctk.CTkButton(run, text="Encrypt", width=150, height=38, fg_color="#16a34a", hover_color="#15803d",
                      command=self.do_encrypt).pack(side="left", padx=(0, 8))
        ctk.CTkButton(run, text="Send result to Decrypt", width=190, height=38, fg_color="gray30",
                      hover_color="gray40", command=self.send_to_decrypt).pack(side="left")

        prev = ctk.CTkFrame(p, fg_color="transparent")
        prev.grid(row=2, column=0, sticky="nsew")
        prev.grid_rowconfigure(0, weight=1)
        self.enc_in_img, self.enc_in_cap = self.make_card(prev, 0, "PLAINTEXT IMAGE", "e")
        self.enc_out_img, self.enc_out_cap = self.make_card(prev, 1, "CIPHERTEXT IMAGE", "e")

    def build_decrypt(self):
        p = self.new_page("decrypt", "Decrypt", "Choose an encrypted image. The mode is detected automatically.")
        p.grid_rowconfigure(2, weight=1)

        ctl = ctk.CTkFrame(p)
        ctl.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        ctl.grid_columnconfigure(2, weight=1)

        self.step_label(ctl, "1.  Image", 0)
        ctk.CTkButton(ctl, text="Browse encrypted...", width=170, command=self.dec_browse).grid(row=0, column=1, pady=10)
        self.dec_name = ctk.CTkLabel(ctl, text="No image selected", text_color=MUTED, anchor="w")
        self.dec_name.grid(row=0, column=2, padx=14, sticky="ew")

        self.step_label(ctl, "2.  Check", 1)
        self.dec_info = ctk.CTkLabel(ctl, text="Select an encrypted image to see its mode and key status.",
                                     text_color=MUTED, anchor="w", justify="left", wraplength=700)
        self.dec_info.grid(row=1, column=1, columnspan=2, padx=0, pady=10, sticky="w")

        self.step_label(ctl, "3.  Run", 2)
        ctk.CTkButton(ctl, text="Decrypt", width=150, height=38, fg_color="#d97706", hover_color="#b45309",
                      command=self.do_decrypt).grid(row=2, column=1, sticky="w", pady=(4, 14))

        prev = ctk.CTkFrame(p, fg_color="transparent")
        prev.grid(row=2, column=0, sticky="nsew")
        prev.grid_rowconfigure(0, weight=1)
        self.dec_in_img, self.dec_in_cap = self.make_card(prev, 0, "CIPHERTEXT IMAGE", "d")
        self.dec_out_img, self.dec_out_cap = self.make_card(prev, 1, "DECRYPTED IMAGE", "d")

    def build_compare(self):
        p = self.new_page("compare", "Compare modes",
                          "Encrypt one image with ECB, CBC and CTR and see the results side by side.")
        p.grid_rowconfigure(2, weight=1)

        ctl = ctk.CTkFrame(p)
        ctl.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        ctl.grid_columnconfigure(2, weight=1)
        self.step_label(ctl, "1.  Image", 0)
        ctk.CTkButton(ctl, text="Browse image...", width=150, command=self.cmp_browse).grid(row=0, column=1, pady=10)
        self.cmp_name = ctk.CTkLabel(ctl, text="No image selected", text_color=MUTED, anchor="w")
        self.cmp_name.grid(row=0, column=2, padx=14, sticky="ew")
        self.step_label(ctl, "2.  Run", 1)
        ctk.CTkButton(ctl, text="Encrypt with all modes", width=210, height=38, fg_color="#0d9488",
                      hover_color="#0f766e", command=self.do_encrypt_all).grid(row=1, column=1, sticky="w", pady=(4, 14))

        prev = ctk.CTkFrame(p, fg_color="transparent")
        prev.grid(row=2, column=0, sticky="nsew")
        prev.grid_rowconfigure(0, weight=1)
        self.cmp = {}
        for i, name in enumerate(("ORIGINAL",) + tuple(MODES)):
            self.cmp[name] = self.make_card(prev, i, name, "c")

    def build_keys(self):
        p = self.new_page("keys", "Key", "Generate, save or load the AES key used for encryption and decryption.")
        card = ctk.CTkFrame(p)
        card.grid(row=1, column=0, sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card, text="Key size (bits)", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, sticky="w", padx=16, pady=(16, 4))
        ctk.CTkSegmentedButton(card, values=["128", "192", "256"], variable=self.size_var,
                               command=self.on_size_change).grid(row=1, column=0, sticky="w", padx=16)

        btns = ctk.CTkFrame(card, fg_color="transparent")
        btns.grid(row=2, column=0, sticky="w", padx=16, pady=14)
        ctk.CTkButton(btns, text="Generate new key", width=160, command=self.new_key).pack(side="left", padx=(0, 8))
        for text, cmd in (("Save...", self.do_save_key), ("Load...", self.do_load_key), ("Copy", self.copy_key)):
            ctk.CTkButton(btns, text=text, width=90, fg_color="gray30", hover_color="gray40",
                          command=cmd).pack(side="left", padx=4)

        self.key_info = ctk.CTkLabel(card, text="", text_color=ACCENT, font=ctk.CTkFont(weight="bold"))
        self.key_info.grid(row=3, column=0, sticky="w", padx=16)
        self.key_box = ctk.CTkTextbox(card, height=80, wrap="char", font=ctk.CTkFont(family="Consolas", size=13))
        self.key_box.grid(row=4, column=0, sticky="ew", padx=16, pady=(4, 10))
        ctk.CTkSwitch(card, text="Auto-save a key file in the output folder when encrypting",
                      variable=self.autokey_var).grid(row=5, column=0, sticky="w", padx=16, pady=(0, 16))

    def build_settings(self):
        p = self.new_page("settings", "Settings & Log", "Where files are saved, options and activity log.")
        p.grid_rowconfigure(2, weight=1)

        card = ctk.CTkFrame(p)
        card.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(card, text="Output folder", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, sticky="w", padx=16, pady=(14, 0))
        self.out_label = ctk.CTkLabel(card, text="", text_color="gray75", anchor="w")
        self.out_label.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 6))
        b = ctk.CTkFrame(card, fg_color="transparent")
        b.grid(row=2, column=0, sticky="w", padx=16)
        ctk.CTkButton(b, text="Change folder", width=130, fg_color="gray30", hover_color="gray40",
                      command=self.change_folder).pack(side="left", padx=(0, 8))
        ctk.CTkButton(b, text="Open folder", width=130, fg_color="gray30", hover_color="gray40",
                      command=self.open_folder).pack(side="left")
        ctk.CTkSwitch(card, text="Ask where to save each time", variable=self.ask_var).grid(
            row=3, column=0, sticky="w", padx=16, pady=(14, 4))
        ctk.CTkSwitch(card, text="Verify after encrypting (round-trip check)", variable=self.verify_var).grid(
            row=4, column=0, sticky="w", padx=16, pady=(0, 16))

        logf = ctk.CTkFrame(p)
        logf.grid(row=2, column=0, sticky="nsew")
        logf.grid_rowconfigure(1, weight=1)
        logf.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(logf, text="Activity log", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, sticky="w", padx=16, pady=(12, 4))
        self.log = ctk.CTkTextbox(logf, font=ctk.CTkFont(family="Consolas", size=12), state="disabled")
        self.log.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))

    # ============================================================ helpers
    def log_msg(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", f"[{datetime.now():%H:%M:%S}] {msg}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def set_status(self, msg, color="gray75"):
        self.status.configure(text=msg, text_color=color)
        self.log_msg(msg)

    def show(self, label, caption, path, name, size=PREVIEW, cap_text=None):
        img = Image.open(path).convert("RGB")
        img.thumbnail(size)
        self._imgs[name] = ctk.CTkImage(light_image=img, dark_image=img, size=img.size)
        label.configure(image=self._imgs[name], text="")
        caption.configure(text=cap_text or os.path.basename(path))

    def update_key_box(self):
        bits = len(self.key) * 8
        hexkey = self.key.hex()
        rounds = {16: 10, 24: 12, 32: 14}[len(self.key)]
        self.key_info.configure(text=f"AES-{bits}   |   ID: {key_id(self.key)}")
        self.bar_hex.configure(text=hexkey)
        self.bar_meta.configure(
            text=f"AES-{bits}  •  {len(self.key)} bytes  •  {len(hexkey)} hex chars  •  {rounds} rounds  •  ID {key_id(self.key)}")
        self.key_box.configure(state="normal")
        self.key_box.delete("1.0", "end")
        self.key_box.insert("1.0", hexkey)
        self.key_box.configure(state="disabled")

    def update_out_label(self):
        self.out_label.configure(text=self.output_dir)

    def on_mode(self, mode):
        self.mode_desc.configure(text=MODE_INFO[mode])

    def set_key(self, key):
        self.key = key
        self.size_var.set(str(len(key) * 8))
        self.update_key_box()

    # ---------------------------------------------------- saving logic
    def clean_stem(self, src):
        stem = os.path.splitext(os.path.basename(src))[0]
        for m in MODES:
            if stem.endswith(f"_{m}_enc"):
                stem = stem[: -len(f"_{m}_enc")]
        return stem

    def pick_dest(self, src, mode, kind):
        stem = self.clean_stem(src)
        name = f"{stem}_{mode}_enc.png" if kind == "enc" else f"{stem}_decrypted.png"
        os.makedirs(self.output_dir, exist_ok=True)
        if self.ask_var.get():
            return filedialog.asksaveasfilename(initialdir=self.output_dir, initialfile=name,
                                                defaultextension=".png", filetypes=[("PNG", "*.png")])
        return unique_path(os.path.join(self.output_dir, name))

    def ensure_key_saved(self):
        if not self.autokey_var.get():
            return
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, f"key_{key_id(self.key)}.txt")
        if not os.path.exists(path):
            save_key(self.key, path)
            self.log_msg(f"Key file saved: {path}")

    def change_folder(self):
        d = filedialog.askdirectory(initialdir=self.output_dir)
        if d:
            self.output_dir = d
            self.update_out_label()
            self.log_msg(f"Output folder: {d}")

    def open_folder(self):
        os.makedirs(self.output_dir, exist_ok=True)
        try:
            os.startfile(self.output_dir)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------------------------------------------------- key actions
    def new_key(self):
        self.set_key(generate_key(int(self.size_var.get()) // 8))
        self.set_status(f"New AES-{self.size_var.get()} key generated.", OK)

    def do_save_key(self):
        os.makedirs(self.output_dir, exist_ok=True)
        path = filedialog.asksaveasfilename(initialdir=self.output_dir, defaultextension=".txt",
                                            initialfile=f"key_{key_id(self.key)}.txt")
        if path:
            save_key(self.key, path)
            self.set_status(f"Key saved: {path}", OK)

    def do_load_key(self):
        path = filedialog.askopenfilename(initialdir=self.output_dir, filetypes=[("Key file", "*.txt")])
        if not path:
            return
        try:
            key = load_key(path)
            if len(key) not in (16, 24, 32):
                raise ValueError("Key must be 16, 24 or 32 bytes")
            self.set_key(key)
            self.set_status(f"Key loaded (ID {key_id(key)}).", OK)
            if self.dec_in:
                self.inspect_input(self.dec_in)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def copy_key(self):
        self.clipboard_clear()
        self.clipboard_append(self.key.hex())
        self.set_status("Key copied to clipboard.", OK)

    # ---------------------------------------------------- Encrypt page
    def enc_browse(self):
        path = filedialog.askopenfilename(title="Select plaintext image",
                                          filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp")])
        if not path:
            return
        self.enc_in = path
        self.enc_name.configure(text=os.path.basename(path))
        self.show(self.enc_in_img, self.enc_in_cap, path, "enc_in")
        if read_info(path):
            self.set_status("Warning: this image is already encrypted.", WARN)
        else:
            self.log_msg(f"Loaded: {path}")

    def do_encrypt(self):
        if not self.enc_in:
            self.set_status("Select an image first (Browse image...).", ERR)
            return
        if read_info(self.enc_in) and not messagebox.askyesno(
                "Already encrypted", "This image is already encrypted.\nEncrypt it again?"):
            return
        mode = self.mode_seg.get()
        dst = self.pick_dest(self.enc_in, mode, "enc")
        if not dst:
            return
        try:
            encrypt_image(self.enc_in, dst, self.key, mode)
            self.ensure_key_saved()
            msg = f"Encrypted with AES-{len(self.key) * 8} {mode} -> {dst}"
            if self.verify_var.get():
                msg += "  |  round-trip check: " + ("OK" if verify(self.enc_in, dst, self.key) else "FAILED")
            self.enc_out = dst
            self.show(self.enc_out_img, self.enc_out_cap, dst, "enc_out")
            self.set_status(msg, OK)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def send_to_decrypt(self):
        if not self.enc_out:
            self.set_status("No encrypted result yet.", ERR)
            return
        self.set_dec_input(self.enc_out)
        self.show_page("decrypt")

    # ---------------------------------------------------- Decrypt page
    def dec_browse(self):
        path = filedialog.askopenfilename(title="Select ciphertext image", initialdir=self.output_dir,
                                          filetypes=[("PNG", "*.png")])
        if path:
            self.set_dec_input(path)

    def set_dec_input(self, path):
        self.dec_in = path
        self.dec_name.configure(text=os.path.basename(path))
        info = self.inspect_input(path)
        cap = os.path.basename(path) + (f"\n[ENCRYPTED - {info['mode']}]" if info else "")
        self.show(self.dec_in_img, self.dec_in_cap, path, "dec_in", cap_text=cap)

    def inspect_input(self, path):
        info = read_info(path)
        if not info:
            self.dec_info.configure(text="This image was not encrypted by this application.", text_color=ERR)
            return None
        mode, kid = info["mode"], info.get("kid")
        if kid and kid != key_id(self.key):
            kp = os.path.join(self.output_dir, f"key_{kid}.txt")
            if os.path.exists(kp):
                try:
                    self.set_key(load_key(kp))
                    self.dec_info.configure(
                        text=f"Mode: {mode}.  Matching key (ID {kid}) found in the output folder and loaded automatically.",
                        text_color=OK)
                    return info
                except Exception:
                    pass
            self.dec_info.configure(
                text=f"Mode: {mode}.  This image was encrypted with a DIFFERENT key (ID {kid}). Load the matching key in the Key page.",
                text_color=WARN)
        else:
            self.dec_info.configure(text=f"Mode: {mode}.  Key matches (ID {key_id(self.key)}). Ready to decrypt.",
                                    text_color=OK)
        return info

    def do_decrypt(self):
        if not self.dec_in:
            self.set_status("Select an encrypted image first.", ERR)
            return
        if not read_info(self.dec_in):
            self.set_status("This image is not encrypted by this application.", ERR)
            return
        dst = self.pick_dest(self.dec_in, None, "dec")
        if not dst:
            return
        try:
            mode = decrypt_image(self.dec_in, dst, self.key)
            self.dec_out = dst
            self.show(self.dec_out_img, self.dec_out_cap, dst, "dec_out")
            self.set_status(f"Decrypted successfully ({mode}) -> {dst}", OK)
        except WrongKeyError as e:
            self.set_status(str(e) + " Load the correct key file.", ERR)
            messagebox.showerror("Wrong key", str(e))
        except NotEncryptedError as e:
            self.set_status(str(e), ERR)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------------------------------------------------- Compare page
    def cmp_browse(self):
        path = filedialog.askopenfilename(title="Select plaintext image",
                                          filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp")])
        if not path:
            return
        self.cmp_in = path
        self.cmp_name.configure(text=os.path.basename(path))
        self.show(*self.cmp["ORIGINAL"], path, "cmp_orig", size=COMPARE)

    def do_encrypt_all(self):
        if not self.cmp_in:
            self.set_status("Select an image first (Browse image...).", ERR)
            return
        if read_info(self.cmp_in):
            self.set_status("The selected image is already encrypted. Select a plaintext image.", ERR)
            return
        os.makedirs(self.output_dir, exist_ok=True)
        try:
            stem = self.clean_stem(self.cmp_in)
            results = []
            for mode in MODES:
                dst = unique_path(os.path.join(self.output_dir, f"{stem}_{mode}_enc.png"))
                encrypt_image(self.cmp_in, dst, self.key, mode)
                ok = verify(self.cmp_in, dst, self.key) if self.verify_var.get() else None
                tag = "" if ok is None else ("  |  OK" if ok else "  |  FAILED")
                self.show(*self.cmp[mode], dst, f"cmp_{mode}", size=COMPARE,
                          cap_text=os.path.basename(dst) + tag)
                results.append(f"{mode}:{'OK' if ok else ('FAILED' if ok is False else '-')}")
            self.ensure_key_saved()
            self.set_status("Encrypted with all modes (saved in the output folder)  |  " + "  ".join(results), OK)
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    App().mainloop()