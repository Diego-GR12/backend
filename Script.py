import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import time
import subprocess
import os
import urllib.request
import urllib.error
import socket
from datetime import datetime

# --- Constantes ---
SHORT_RETRIES = 3
SHORT_DELAY = 60
LONG_DELAY = 300
TIMEOUTS = {
    'default': 30,
    'ls_remote': 45,
    'push': 120,
}

# --- Funciones Git ---

def run_git_command(cmd, update_status, silent=False, return_stdout=False, timeout=None):
    timeout = timeout or TIMEOUTS['default']
    update_status(f"Ejecutando: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=os.getcwd())
        if result.returncode == 0:
            if not silent:
                if result.stdout.strip():
                    update_status(result.stdout.strip(), is_detail=True)
            return result.stdout.strip() if return_stdout else True
        else:
            update_status(f"Error en comando: {' '.join(cmd)}")
            if result.stderr.strip():
                update_status(result.stderr.strip(), is_detail=True)
            return None if return_stdout else False
    except FileNotFoundError:
        update_status(f"Git no encontrado. Asegúrate de que esté instalado y en PATH.")
    except subprocess.TimeoutExpired:
        update_status(f"Timeout ({timeout}s) en comando: {' '.join(cmd)}")
    except Exception as e:
        update_status(f"Excepción ejecutando comando Git: {e}")
    return None if return_stdout else False

# --- Verificaciones ---

def check_in_git_repo(update_status):
    if not os.path.isdir(".git"):
        update_status("Este directorio no es un repositorio Git.")
        messagebox.showerror("Error", "Ejecuta esto desde un repositorio Git.")
        return False
    return True

def get_remote_url(update_status, remote="origin"):
    return run_git_command(["git", "remote", "get-url", remote], update_status, silent=True, return_stdout=True)

def check_github_connectivity(update_status, url="https://github.com"):
    try:
        urllib.request.urlopen(url, timeout=10)
        update_status("Conectividad general a GitHub: OK")
        return True
    except Exception as e:
        update_status(f"Conectividad general a GitHub fallida: {e}")
        return False

def check_remote_access(update_status, remote="origin"):
    url = get_remote_url(update_status, remote)
    if not url:
        return False
    update_status(f"Probando acceso a remoto: {url}")
    return run_git_command(["git", "ls-remote", "--exit-code", "--heads", url], update_status, silent=True, timeout=TIMEOUTS['ls_remote'])

# --- Push con Reintentos ---

def push_with_retries(update_status, remote="origin"):
    retries = 0
    while True:
        update_status(f"Intentando git push (intento #{retries + 1})...")
        if run_git_command(["git", "push", remote], update_status, timeout=TIMEOUTS['push']):
            update_status("Push exitoso.")
            return True
        retries += 1
        delay = SHORT_DELAY if retries <= SHORT_RETRIES else LONG_DELAY
        for i in range(delay, 0, -1):
            update_status(f"Reintentando push en {i} segundos...", is_detail=True)
            time.sleep(1)
        if retries > SHORT_RETRIES:
            update_status("Reiniciando ciclo de intentos...")

# --- Proceso Principal ---

def backup_process(update_status):
    try:
        if not check_in_git_repo(update_status):
            return False

        # git add
        if not run_git_command(["git", "add", "."], update_status):
            return False

        # git commit
        status = run_git_command(["git", "status", "--porcelain"], update_status, return_stdout=True, silent=True)
        if not status:
            update_status("No hay cambios para commitear.")
        else:
            msg = f"Backup {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            if not run_git_command(["git", "commit", "-m", msg], update_status):
                return False

        # check remoto
        if not check_remote_access(update_status):
            if not check_github_connectivity(update_status):
                update_status("Problema general de red.")
            else:
                update_status("Problema con el acceso al remoto. Verifica permisos.")
        
        # push
        return push_with_retries(update_status)

    except Exception as e:
        update_status(f"Error inesperado: {e}")
        return False

# --- GUI ---

class BackupApp:
    def __init__(self, root):
        self.root = root
        root.title("Backup GitHub")
        root.geometry("600x500")

        self.status_var = tk.StringVar()
        self.detail_var = tk.StringVar()

        tk.Button(root, text="Iniciar Backup", command=self.iniciar_hilo, width=20, height=2).pack(pady=10)
        tk.Label(root, textvariable=self.status_var, fg='blue').pack()
        tk.Label(root, textvariable=self.detail_var, fg='gray').pack()

        self.log = scrolledtext.ScrolledText(root, state='disabled', wrap=tk.WORD)
        self.log.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    def iniciar_hilo(self):
        threading.Thread(target=self.run_backup, daemon=True).start()

    def actualizar_estado(self, msg, is_detail=False):
        def _update():
            if is_detail:
                self.detail_var.set(msg)
            else:
                self.status_var.set(msg)
                self.detail_var.set("")
            self._log(msg)
        self.root.after_idle(_update)

    def _log(self, msg):
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        self.log.configure(state='normal')
        self.log.insert(tk.END, f"{timestamp} {msg}\n")
        self.log.configure(state='disabled')
        self.log.see(tk.END)

    def run_backup(self):
        self.actualizar_estado("Iniciando proceso de backup...")
        success = backup_process(self.actualizar_estado)
        msg = "Backup completado con éxito." if success else "Backup fallido."
        self.actualizar_estado(msg)
        if success:
            messagebox.showinfo("Éxito", msg)
        else:
            messagebox.showerror("Error", msg)

# --- Inicio ---

if __name__ == "__main__":
    root = tk.Tk()
    app = BackupApp(root)
    root.mainloop()
