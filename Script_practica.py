import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import time
import subprocess
import os
import urllib.request
from datetime import datetime


Reintentos_cortos = 3
Tiempo_espera_corto = 60
Tiempo_espera_largo = 300
Tiempo_Espera= {
   'por_defecto' : 30,
   'ls_remoto' : 45,
   'push' : 120,
}

# Esta función se encarga de actualizar el estado de la aplicación
def ejecutar_comando_git(comando,actualizar_estado,silenciar=False,devolver_salida=False,tiempo_espera=None):
    tiempo_espera = tiempo_espera or Tiempo_Espera['por_defecto']
    actualizar_estado(f"Ejecutando: {" ".join(comando) }")
    try:
        resultado = subprocess.run(comando,capture_output=True,text=True,timeout=tiempo_espera,cwd=os.getcwd()) 
        if resultado.returncode == 0:
            if not silenciar and resultado.stdout.strip():
                actualizar_estado(resultado.stdout.strip(), es_detalle=True)   
            return resultado.stdout.strip() if devolver_salida else True
        else:
            actualizar_estado(f"Error al ejecutar comando:{' '.join(comando)}")
            if resultado.stderr.strip():
                actualizar_estado(resultado.stderr.strip(), es_detalle=True)
                return None if devolver_salida else False
    except FileNotFoundError:
        actualizar_estado("Git no está instalando o no se encuentra en el PATH", es_detalle=True)
    except subprocess.TimeoutExpired:
        actualizar_estado(f"El tiempo de espera a excedido ({tiempo_espera}s) en comando: {' '.join(comando)}")  
    except Exception as e:
        actualizar_estado(f"Exepción ejecutando Git: {e}")
        return None if devolver_salida else False 
    

    
# Esta función comprueba si el directorio actual es un repositorio Git    
def entra_en_repositorio(actualizar_estado):
    if not os.path.isdir('.git'):
        actualizar_estado("No se encuentra un repositorio Git en el directorio actual")
        messagebox.showerror("Error", "No se encuentra un repositorio Git en el directorio actual")
        return False
    return True


#Con la siguiente función se obtiene la URL del repositorio remoto
def url_remota(actualizar_estado,remoto="origin"):
    return  ejecutar_comando_git(["git", "remote", "get-url", remoto], actualizar_estado, devolver_salida=True,silenciar=True)


#Esta función se encarga de decir si se conecta o no se conecta y que le pasa 
def se_conecta(actualizar_estado, url="https://github.com"):
    try:
        urllib.request.urlopen(url, timeout=5)
        actualizar_estado("Conexion general a Github: Bien")
        return True
    except Exception as e:
        actualizar_estado(f"Error de conexión a {url}: {e}")
        return False
    
#Esta función se encarga de comprobar el estado del repositorio remoto
def estado_remoto(actualizar_estado, remoto="origin"):
    url= url_remota(actualizar_estado, remoto)
    if not url:
        return False
    actualizar_estado(f"Probadondo estado remoto: {url}")
    return ejecutar_comando_git(["git", "ls-remoto", "--exit-code", "--heads", url],actualizar_estado,silenciar=True,tiempo_espera=Tiempo_Espera['ls_remoto'])


# Esta función se encarga de hacer push persistente al repositorio remoto
def push_persistente(actualizar_estado,remoto="origin"):
    intentos = 0
    while True:
        actualizar_estado(f"intentando git push (intento #{intentos + 1})...")
        if ejecutar_comando_git(["git", "push",remoto], actualizar_estado,tiempo_espera=Tiempo_Espera['push']):
            actualizar_estado("Push realizado correctamente")
            return True
        intentos += 1
        espera =  Tiempo_espera_corto if intentos < Reintentos_cortos else Tiempo_espera_largo
        for i in range(espera,0,-1):
            actualizar_estado(f"Reintentando en {i} segundos...",es_detalle=True)
            time.sleep(1)
        if intentos >= Reintentos_cortos:
            actualizar_estado("Se ha alcanzado el número máximo de reintentos")



def proceso_respaldo(actualizar_estado):
    try:
        if not entra_en_repositorio(actualizar_estado):
            return False

        #git add
        if not ejecutar_comando_git(["git", "add","."], actualizar_estado):
            return False
        
        #Esto es el commit
        estado = ejecutar_comando_git(["git", "status", "--porcelain"], actualizar_estado, devolver_salida=True, silenciar=True)
        if not estado:
            actualizar_estado("No hay cambios para respaldar.")
        else:
            mensaje = f"Respaldo realizado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            if not ejecutar_comando_git(["git", "commit", "-m", mensaje], actualizar_estado):
                return False
            
         #verificación de Remoto   
        if not estado_remoto(actualizar_estado):
            if not se_conecta(actualizar_estado):
                actualizar_estado("No se puede conectar a Internet, no se puede hacer push")
            else:
                  actualizar_estado("Problema con el acceso al remoto. Verifica permisos.")

        #Este es el Push
        return push_persistente(actualizar_estado)
    

    except Exception as e:
        actualizar_estado(f"Error inesperado: {e}")
        return False
    

 # --- Interfaz Gráfica ---
class AplicacionRespaldo:
    def __init__(self, raiz):
        self.raiz=raiz
        raiz.title("")
        raiz.title("Respaldo a GitHub")
        raiz.geometry("600x500")

            
        self.estado_var = tk.StringVar()
        self.detalle_var = tk.StringVar()

        tk.Button(raiz,text="Iniciar Respaldo",command=self.iniciar_hilo, width=20, height=2).pack(pady=10)
        tk.Label(raiz,textvariable=self.estado_var, fg='blue').pack()
        tk.Label(raiz,textvariable=self.estado_var, fg='gray').pack()

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

    def _registrar_log(self,mensaje):
        marcado_tiempo = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log.configure(state='normal')
        self.log.insert(tk.END, f"[{marcado_tiempo} {mensaje}\n]")
        self.log.configure(state='disabled')
        self.log.see(tk.END)

    def ejecutar_respaldo(self):
        self.actualizar_estado("Iniciando respaldo...")
        exito= proceso_respaldo(self.actualizar_estado)
        mensaje = "Respaldo completado con éxito." if exito else "Error al realizar el respaldo."
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
