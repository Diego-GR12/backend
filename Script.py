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
REINTENTOS_CORTOS = 3
ESPERA_CORTA = 60
ESPERA_LARGA = 300
TIEMPOS_ESPERA = {
    'por_defecto': 30,
    'ls_remote': 45,
    'push': 120,
}

# --- Funciones Git ---

def ejecutar_comando_git(comando, actualizar_estado, silencioso=False, devolver_salida=False, tiempo_espera=None):
    tiempo_espera = tiempo_espera or TIEMPOS_ESPERA['por_defecto']
    actualizar_estado(f"Ejecutando: {' '.join(comando)}")
    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=tiempo_espera, cwd=os.getcwd())
        if resultado.returncode == 0:
            if not silencioso and resultado.stdout.strip():
                actualizar_estado(resultado.stdout.strip(), es_detalle=True)
            return resultado.stdout.strip() if devolver_salida else True
        else:
            actualizar_estado(f"Error en comando: {' '.join(comando)}")
            if resultado.stderr.strip():
                actualizar_estado(resultado.stderr.strip(), es_detalle=True)
            return None if devolver_salida else False
    except FileNotFoundError:
        actualizar_estado("Git no encontrado. Asegúrate de que esté instalado y en PATH.")
    except subprocess.TimeoutExpired:
        actualizar_estado(f"Tiempo de espera excedido ({tiempo_espera}s) en comando: {' '.join(comando)}")
    except Exception as e:
        actualizar_estado(f"Excepción ejecutando comando Git: {e}")
    return None if devolver_salida else False

# --- Verificaciones ---

def esta_en_repositorio_git(actualizar_estado):
    if not os.path.isdir(".git"):
        actualizar_estado("Este directorio no es un repositorio Git.")
        messagebox.showerror("Error", "Ejecuta esto desde un repositorio Git.")
        return False
    return True

def obtener_url_remota(actualizar_estado, remoto="origin"):
    return ejecutar_comando_git(["git", "remote", "get-url", remoto], actualizar_estado, silencioso=True, devolver_salida=True)

def verificar_conectividad_github(actualizar_estado, url="https://github.com"):
    try:
        urllib.request.urlopen(url, timeout=10)
        actualizar_estado("Conectividad general a GitHub: OK")
        return True
    except Exception as e:
        actualizar_estado(f"Conectividad general a GitHub fallida: {e}")
        return False

def verificar_acceso_remoto(actualizar_estado, remoto="origin"):
    url = obtener_url_remota(actualizar_estado, remoto)
    if not url:
        return False
    actualizar_estado(f"Probando acceso al remoto: {url}")
    return ejecutar_comando_git(["git", "ls-remote", "--exit-code", "--heads", url], actualizar_estado, silencioso=True, tiempo_espera=TIEMPOS_ESPERA['ls_remote'])

# --- Push con Reintentos ---

def hacer_push_con_reintentos(actualizar_estado, remoto="origin"):
    intentos = 0
    while True:
        actualizar_estado(f"Intentando git push (intento #{intentos + 1})...")
        if ejecutar_comando_git(["git", "push", remoto], actualizar_estado, tiempo_espera=TIEMPOS_ESPERA['push']):
            actualizar_estado("Push exitoso.")
            return True
        intentos += 1
        espera = ESPERA_CORTA if intentos <= REINTENTOS_CORTOS else ESPERA_LARGA
        for i in range(espera, 0, -1):
            actualizar_estado(f"Reintentando push en {i} segundos...", es_detalle=True)
            time.sleep(1)
        if intentos > REINTENTOS_CORTOS:
            actualizar_estado("Reiniciando ciclo de intentos...")

# --- Proceso Principal ---

def proceso_respaldo(actualizar_estado):
    try:
        if not esta_en_repositorio_git(actualizar_estado):
            return False

        # git add
        if not ejecutar_comando_git(["git", "add", "."], actualizar_estado):
            return False

        # git commit
        estado = ejecutar_comando_git(["git", "status", "--porcelain"], actualizar_estado, devolver_salida=True, silencioso=True)
        if not estado:
            actualizar_estado("No hay cambios para respaldar.")
        else:
            mensaje = f"Respaldo {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            if not ejecutar_comando_git(["git", "commit", "-m", mensaje], actualizar_estado):
                return False

        # verificación de remoto
        if not verificar_acceso_remoto(actualizar_estado):
            if not verificar_conectividad_github(actualizar_estado):
                actualizar_estado("Problema general de red.")
            else:
                actualizar_estado("Problema con el acceso al remoto. Verifica permisos.")
        
        # push
        return hacer_push_con_reintentos(actualizar_estado)

    except Exception as e:
        actualizar_estado(f"Error inesperado: {e}")
        return False

# --- Interfaz Gráfica ---

class AplicacionRespaldo:
    def __init__(self, raiz):
        self.raiz = raiz
        raiz.title("Respaldo a GitHub")
        raiz.geometry("600x500")

        self.estado_var = tk.StringVar()
        self.detalle_var = tk.StringVar()

        tk.Button(raiz, text="Iniciar Respaldo", command=self.iniciar_hilo, width=20, height=2).pack(pady=10)
        tk.Label(raiz, textvariable=self.estado_var, fg='blue').pack()
        tk.Label(raiz, textvariable=self.detalle_var, fg='gray').pack()

        self.log = scrolledtext.ScrolledText(raiz, state='disabled', wrap=tk.WORD)
        self.log.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    def iniciar_hilo(self):
        threading.Thread(target=self.ejecutar_respaldo, daemon=True).start()

    def actualizar_estado(self, mensaje, es_detalle=False):
        def _actualizar():
            if es_detalle:
                self.detalle_var.set(mensaje)
            else:
                self.estado_var.set(mensaje)
                self.detalle_var.set("")
            self._registrar_log(mensaje)
        self.raiz.after_idle(_actualizar)

    def _registrar_log(self, mensaje):
        marca_tiempo = datetime.now().strftime("[%H:%M:%S]")
        self.log.configure(state='normal')
        self.log.insert(tk.END, f"{marca_tiempo} {mensaje}\n")
        self.log.configure(state='disabled')
        self.log.see(tk.END)

    def ejecutar_respaldo(self):
        self.actualizar_estado("Iniciando proceso de respaldo...")
        exito = proceso_respaldo(self.actualizar_estado)
        mensaje = "Respaldo completado con éxito." if exito else "El respaldo falló."
        self.actualizar_estado(mensaje)
        if exito:
            messagebox.showinfo("Éxito", mensaje)
        else:
            messagebox.showerror("Error", mensaje)

# --- Inicio del programa ---

if __name__ == "__main__":
    raiz = tk.Tk()
    app = AplicacionRespaldo(raiz)
    raiz.mainloop()
