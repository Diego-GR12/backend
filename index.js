// --- Imports ---
import { GoogleGenerativeAI } from "@google/generative-ai";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import pdfParse from "pdf-parse/lib/pdf-parse.js";
import path from "path";
import fs from "fs/promises";
import { existsSync, mkdirSync } from "fs";
import { fileURLToPath } from "url";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { createClient } from "@supabase/supabase-js";
import FormData from "form-data";
import axios from 'axios'; // <--- AÑADIDO PARA AXIOS

// --- Definiciones de Directorio ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const directorioSubidas = path.join(__dirname, "uploads");
const directorioImagenesGeneradas = path.join(__dirname, "generated_images");

// --- Carga de Variables de Entorno ---
dotenv.config();
const {
  PORT: PUERTO = 3001,
  API_KEY,
  JWT_SECRET,
  NODE_ENV = "development",
  SUPABASE_URL,
  SUPABASE_KEY,
  CLIPDROP_API_KEY,
} = process.env;

const isDev = NODE_ENV !== "production";

// --- Constantes y Configuraciones ---
const COOKIE_OPTIONS = { httpOnly: true, secure: !isDev, sameSite: isDev ? "lax" : "none", maxAge: 3600 * 1000, path: "/" };
const TAMANO_MAX_ARCHIVO_MB = 20;
const MAX_CARACTERES_POR_PDF = 10000;
const MAX_LONGITUD_CONTEXTO = 30000;
const MODELOS_PERMITIDOS = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash", "gemini-2.5-pro-exp-03-25"];
const MODELO_POR_DEFECTO = "gemini-1.5-flash";
const TEMP_POR_DEFECTO = 0.7;
const TOPP_POR_DEFECTO = 0.9;
const IDIOMA_POR_DEFECTO = "es";
const JWT_OPTIONS = { expiresIn: "1h" };

// --- Verificaciones de Startup ---
console.log("[Startup] JWT_SECRET cargado:", JWT_SECRET ? `${JWT_SECRET.substring(0, 3)}... (long: ${JWT_SECRET.length})` : "NO CARGADO!");
if (!JWT_SECRET || JWT_SECRET.length < 32) console.warn("⚠️ JWT_SECRET no definido o inseguro!");
if (!API_KEY) console.warn("⚠️ API_KEY (Google GenAI) no configurada.");
if (!SUPABASE_URL) console.warn("⚠️ SUPABASE_URL no configurada.");
if (!SUPABASE_KEY) console.warn("⚠️ SUPABASE_KEY no configurada.");
if (!CLIPDROP_API_KEY) console.warn("⚠️ CLIPDROP_API_KEY (para imágenes) no configurada.");

const app = express();

// --- Inicialización de Clientes ---
let clienteIA;
try {
  if (API_KEY) { clienteIA = new GoogleGenerativeAI(API_KEY); console.log("✅ GoogleGenerativeAI creado."); }
  else { clienteIA = null; console.warn("⚠️ GoogleGenerativeAI NO inicializado (sin API_KEY)."); }
} catch (e) { console.error("🚨 Error GoogleGenerativeAI:", e.message); clienteIA = null; }

let supabase;
try {
  if (SUPABASE_URL && SUPABASE_KEY) { supabase = createClient(SUPABASE_URL, SUPABASE_KEY); console.log("✅ Supabase client creado."); }
  else { supabase = null; console.warn("⚠️ Supabase NO inicializado (sin URL/KEY)."); }
} catch (e) { console.error("🚨 Error Supabase client:", e.message); supabase = null; }

// --- Middlewares ---
app.use(cors({ origin: (o, cb) => cb(null, o || true), credentials: true }));
app.use(cookieParser());
app.use(express.json());

// --- Autenticación ---
const autenticarToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: "Token no proporcionado" });
    if (!JWT_SECRET) { console.error("[Auth] JWT_SECRET falta!"); return res.status(500).json({ error: "Error auth server." }); }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            if (err.name === "TokenExpiredError") res.clearCookie("token", COOKIE_OPTIONS);
            return res.status(err.name === "TokenExpiredError" ? 401 : 403).json({ error: err.name === "TokenExpiredError" ? "Token expirado" : "Token inválido" });
        }
        req.usuario = user;
        next();
    });
};

// --- Multer ---
const almacenamiento = multer.diskStorage({
    destination: directorioSubidas,
    filename: (req, file, cb) => {
        const sufijo = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
        const nombre = file.originalname.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9.\-_]/gi, '_');
        cb(null, `${sufijo}-${nombre}`);
    },
});
const subir = multer({ // Este es tu 'subir' de /api/generateText
  storage: almacenamiento,
  limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const isPdf = file.mimetype === "application/pdf";
    if (!isPdf){
      console.warn( `⚠️ Rechazado archivo no PDF: ${file.originalname} (${file.mimetype})`);
      cb(null, false);
    } else {
        cb(null, true);
    }
  },
}).array("archivosPdf");

const upload = multer({ storage: almacenamiento }); // Tu 'upload' de /api/files

// --- Crear Directorios ---
[directorioSubidas, directorioImagenesGeneradas].forEach(dir => {
    if (!existsSync(dir)) {
        try { mkdirSync(dir, { recursive: true }); console.log(`✅ Dir creado: ${dir}`); }
        catch (e) { console.error(`🚨 No se pudo crear dir ${dir}:`, e); }
    } else console.log(`➡️ Dir existe: ${dir}`);
});

// --- Funciones Auxiliares (PDF, IA Texto - Tu código original sin cambios) ---

async function extraerTextoDePDF(rutaArchivo) {
  const nombreArchivoLog = path.basename(rutaArchivo);
  try {
    await fs.access(rutaArchivo);
    const bufferDatos = await fs.readFile(rutaArchivo);
    const datos = await pdfParse(bufferDatos);
    const textoExtraido = datos?.text?.trim() || null;
    return { texto: textoExtraido, error: null };
  } catch (error) {
    if (error.code === "ENOENT") {
      console.error(`❌ [PDF Extract] Archivo NO ENCONTRADO: ${rutaArchivo}`);
      return {
        texto: null,
        error: `Archivo no encontrado: ${nombreArchivoLog}`,
      };
    }
    console.error(
      `❌ [PDF Extract] Error procesando ${nombreArchivoLog}:`,
      error.message
    );
    return {
      texto: null,
      error: `Error al parsear ${nombreArchivoLog}: ${
        error.message || "desconocido"
      }`,
    };
  }
}

async function generarContextoPDF(idUsuario, nombresArchivosUnicos) {
  if (!nombresArchivosUnicos || nombresArchivosUnicos.length === 0) return "";
  if (!supabase) { console.warn("[Context PDF] Supabase no disponible."); return "[Error: Base de datos no disponible]";}

  try {
    const { data: archivosDB, error } = await supabase
      .from("archivos_usuario")
      .select("nombre_archivo_unico, nombre_archivo_original")
      .eq("usuario_id", idUsuario)
      .in("nombre_archivo_unico", nombresArchivosUnicos);

    if (error) {
      console.error("[Context PDF] ❌ Error Supabase:", error.message);
      return "[Error al recuperar archivos PDF del usuario]";
    }
     if (!archivosDB || archivosDB.length === 0) {
      console.warn(`[Context PDF] No se encontraron archivos en DB para usuario ${idUsuario} y nombres: ${nombresArchivosUnicos.join(', ')}`);
      return "";
    }

    const archivosMap = new Map(
      archivosDB.map((f) => [f.nombre_archivo_unico, f.nombre_archivo_original])
    );

    let textoCompleto = "";
    for (const nombreArchivoUnico of nombresArchivosUnicos) {
      const nombreOriginal = archivosMap.get(nombreArchivoUnico);
      if (!nombreOriginal) {
          console.warn(`[Context PDF] Archivo ${nombreArchivoUnico} no encontrado en los metadatos del usuario.`);
          continue;
      }
      const ruta = path.join(directorioSubidas, nombreArchivoUnico);

      try {
        const buffer = await fs.readFile(ruta);
        const datos = await pdfParse(buffer);
        textoCompleto += `\n\n[${nombreOriginal}]\n${(datos.text || "").trim()}`;
      } catch (err) {
        console.warn(
          `[Context PDF] ⚠️ No se pudo leer o parsear ${nombreArchivoUnico} (Original: ${nombreOriginal}):`,
          err.message
        );
      }
    }
    return textoCompleto.trim();
  } catch (err) {
    console.error("[Context PDF] ❌ Excepción:", err);
    return "[Error al generar contexto desde archivos PDF]";
  }
}
async function generarRespuestaIA( prompt, historialDB, textoPDF, modeloReq, temp, topP, lang) {
  if (!clienteIA) throw new Error("Servicio IA (Google) no disponible.");
  const nombreModelo = MODELOS_PERMITIDOS.includes(modeloReq) ? modeloReq : MODELO_POR_DEFECTO;
  if (modeloReq && nombreModelo !== modeloReq) console.warn(`[Gen IA] Modelo no válido ('${modeloReq}'), usando: ${MODELO_POR_DEFECTO}`);
  const configGeneracion = { temperature: !isNaN(temp) ? Math.max(0, Math.min(1, temp)) : TEMP_POR_DEFECTO, topP: !isNaN(topP) ? Math.max(0, Math.min(1, topP)) : TOPP_POR_DEFECTO, };
  const idioma = ["es", "en"].includes(lang) ? lang : IDIOMA_POR_DEFECTO;
  const langStrings = idioma === "en" ? { systemBase: "You are a helpful conversational assistant. Answer clearly and concisely in Markdown format.", systemPdf: `You are an assistant that answers *based solely* on the provided text. If the answer isn't in the text, state that clearly. Use Markdown format.\n\nReference Text (Context):\n"""\n{CONTEXT}\n"""\n\n`, label: "Question", error: "I'm sorry, there was a problem contacting the AI" } : { systemBase: "Eres un asistente conversacional útil. Responde de forma clara y concisa en formato Markdown.", systemPdf: `Eres un asistente que responde *basándose únicamente* en el texto proporcionado. Si la respuesta no está en el texto, indícalo claramente. Usa formato Markdown.\n\nTexto de Referencia (Contexto):\n"""\n{CONTEXT}\n"""\n\n`, label: "Pregunta", error: "Lo siento, hubo un problema al contactar la IA" };

  let instruccionSistema;
  if (textoPDF) {
    const contextoTruncado = textoPDF.length > MAX_LONGITUD_CONTEXTO ? textoPDF.substring(0, MAX_LONGITUD_CONTEXTO) + "... (context truncated)" : textoPDF;
    if (textoPDF.length > MAX_LONGITUD_CONTEXTO) console.warn(`[Gen IA] ✂️ Contexto PDF truncado.`);
    instruccionSistema = langStrings.systemPdf.replace("{CONTEXT}", contextoTruncado);
  } else {
    instruccionSistema = langStrings.systemBase;
  }
  const promptCompletoUsuario = `${instruccionSistema}${langStrings.label}: ${prompt}`;
  const contenidoGemini = [ ...(historialDB || []).filter((m) => m.texto?.trim()).map((m) => ({ role: m.rol === "user" ? "user" : "model", parts: [{ text: m.texto }], })), { role: "user", parts: [{ text: promptCompletoUsuario }] }, ];
  console.log( `[Gen IA] ➡️ Enviando ${contenidoGemini.length} partes a Gemini (${nombreModelo}).` );
  try {
    const modeloGemini = clienteIA.getGenerativeModel({ model: nombreModelo });
    const resultado = await modeloGemini.generateContent({ contents: contenidoGemini, generationConfig: configGeneracion, });
    const response = resultado?.response;
    const textoRespuestaIA = response?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (textoRespuestaIA) { console.log("[Gen IA] ✅ Respuesta recibida."); return textoRespuestaIA.trim(); }
    const blockReason = response?.promptFeedback?.blockReason;
    const finishReason = response?.candidates?.[0]?.finishReason;
    const errorDetail = blockReason ? `Bloqueo: ${blockReason}` : finishReason ? `Finalización: ${finishReason}` : "Respuesta inválida";
    console.warn(`[Gen IA] ⚠️ Respuesta vacía/bloqueada. ${errorDetail}`);
    throw new Error(`${langStrings.error}. (${errorDetail})`);
  } catch (error) {
    console.error(`[Gen IA] ❌ Error API (${nombreModelo}):`, error.message);
    throw new Error(`${langStrings.error}. (Detalle: ${error.message || "Desconocido"})`);
  }
}

// --- Función para Generar Imágenes con CLIPDROP usando AXIOS ---
async function generarImagenClipdrop(promptTexto) {
    if (!CLIPDROP_API_KEY) throw new Error("Servicio de imágenes (Clipdrop) no disponible (sin API key).");
    if (!promptTexto?.trim()) throw new Error("Prompt inválido para Clipdrop.");

    const CLIPDROP_API_URL = "https://clipdrop-api.co/text-to-image/v1";
    console.log(`[Img Gen Clipdrop Axios] Solicitando para: "${promptTexto}"`);

    const form = new FormData();
    form.append('prompt', promptTexto.trim());
    // Log para verificar el contenido del FormData antes de enviarlo con Axios
    console.log(`[Img Gen Clipdrop Axios Debug] Contenido de FormData para prompt: '${promptTexto.trim()}'`);

    try {
        const response = await axios.post(CLIPDROP_API_URL, form, {
            headers: {
                'x-api-key': CLIPDROP_API_KEY,
                ...form.getHeaders(), // axios usa los headers de FormData
            },
            responseType: 'arraybuffer' // Para recibir la imagen como buffer
        });

        const bufferImagen = Buffer.from(response.data); 
        const tipoMime = response.headers['content-type'] || 'image/png';
        const extension = tipoMime.includes('png') ? 'png' : (tipoMime.includes('jpeg') ? 'jpeg' : 'out');
        const nombreArchivo = `${Date.now()}-clipdrop-axios-${promptTexto.substring(0,15).replace(/[^a-z0-9]/gi, '_')}.${extension}`;
        const rutaArchivo = path.join(directorioImagenesGeneradas, nombreArchivo);

        await fs.writeFile(rutaArchivo, bufferImagen);
        console.log(`[Img Gen Clipdrop Axios] Guardada: ${rutaArchivo}`);

        return { fileName: nombreArchivo, url: `/generated_images/${nombreArchivo}` };

    } catch (error) {
        let status = 500;
        let errorMsgParaUsuario = "Error desconocido generando imagen con Clipdrop.";

        if (error.response) {
            status = error.response.status;
            const responseData = error.response.data;
            let clipdropError = "Error de Clipdrop.";
            
            if (responseData) {
                if (Buffer.isBuffer(responseData)) { 
                    try {
                        const errObj = JSON.parse(responseData.toString('utf-8'));
                        clipdropError = errObj.error || responseData.toString('utf-8');
                    } catch (e) { clipdropError = responseData.toString('utf-8'); }
                } else if (typeof responseData === 'object' && responseData.error) {
                    clipdropError = responseData.error;
                } else if (typeof responseData === 'string') { clipdropError = responseData; }
            }
            console.error(`[Img Gen Clipdrop Axios] Error API (${status}):`, clipdropError);

            if (status === 400 && clipdropError.toLowerCase().includes("prompt")) errorMsgParaUsuario = "El prompt es requerido o inválido para Clipdrop.";
            else if (status === 401 || status === 403) errorMsgParaUsuario = "API Key de Clipdrop inválida o sin permisos.";
            else if (status === 402) errorMsgParaUsuario = "Límite de créditos/pago de Clipdrop alcanzado.";
            else if (status === 429) errorMsgParaUsuario = "Límite de tasa de Clipdrop alcanzado. Intente más tarde.";
            else errorMsgParaUsuario = `Error del servicio de imágenes: ${clipdropError.substring(0,150)}`;

        } else if (error.request) {
            console.error("[Img Gen Clipdrop Axios] Sin respuesta de Clipdrop:", error.message);
            errorMsgParaUsuario = "No se pudo contactar el servicio de imágenes (sin respuesta).";
        } else {
            console.error("[Img Gen Clipdrop Axios] Error de configuración:", error.message);
            errorMsgParaUsuario = "Error interno configurando la solicitud de imagen.";
        }
        const errToThrow = new Error(errorMsgParaUsuario);
        errToThrow.status = status; 
        throw errToThrow;
    }
}


// --- Rutas API (Tu código original, con correcciones mínimas a Supabase donde es crítico) ---

app.post("/api/register", async (req, res, next) => {
  if (!supabase) return res.status(503).json({error: "BD no disponible"});
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });
  try {
    const contrasenaHasheada = await bcrypt.hash(password, 10);
    const { data, error } = await supabase.from("usuarios").insert([{ nombre_usuario: username, contrasena_hash: contrasenaHasheada }]).select("id").single();
    if (error) {
      if (error.code === "23505") return res.status(409).json({ error: "Nombre de usuario ya existe." });
      throw error;
    }
    res.status(201).json({ message: "Registro exitoso.", userId: data.id });
  } catch (error) { next(error); }
});

app.post("/api/login", async (req, res, next) => {
  if (!supabase) return res.status(503).json({error: "BD no disponible"});
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });
  try {
    const { data: usuarios, error } = await supabase.from("usuarios").select("id, nombre_usuario, contrasena_hash").eq("nombre_usuario", username).limit(1).single();
    if (error || !usuarios) return res.status(401).json({ error: "Credenciales inválidas." });
    const passwordCorrecta = await bcrypt.compare(password, usuarios.contrasena_hash);
    if (!passwordCorrecta) return res.status(401).json({ error: "Credenciales inválidas." });
    const payload = { id: usuarios.id, username: usuarios.nombre_usuario };
    if(!JWT_SECRET) throw new Error("JWT_SECRET no configurado");
    const token = jwt.sign(payload, JWT_SECRET, JWT_OPTIONS);
    res.cookie("token", token, COOKIE_OPTIONS);
    res.json({ message: "Login exitoso.", user: payload });
  } catch (error) { next(error); }
});

app.post("/api/logout", (req, res) => { res.clearCookie("token", COOKIE_OPTIONS); res.status(200).json({ message: "Logout exitoso." }); });
app.get("/api/verify-auth", autenticarToken, (req, res) => { res.json({ user: req.usuario }); });

app.post("/api/files", autenticarToken, upload.array("archivosPdf"), async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    try {
      const usuarioId = req.usuario.id;
      const archivos = req.files;
      if (!archivos || archivos.length === 0) return res.status(400).json({ error: "No se subieron archivos."});
      const registros = archivos.map((file) => ({ usuario_id: usuarioId, nombre_archivo_unico: file.filename, nombre_archivo_original: file.originalname, }));
      const { error } = await supabase.from("archivos_usuario").insert(registros);
      if (error) {
        archivos.forEach(async f => {try{await fs.unlink(f.path)}catch(e){}});
        throw error;
      }
      res.status(200).json({ mensaje: "Archivos subidos correctamente." });
    } catch (error) { next(error); }
  }
);

app.get("/api/files", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    try {
      const { data: archivos, error } = await supabase.from("archivos_usuario").select("nombre_archivo_unico, nombre_archivo_original").eq("usuario_id", req.usuario.id).order("fecha_subida", { ascending: false });
      if (error) throw error;
      res.json( (archivos || []).map((a) => ({ name: a.nombre_archivo_unico, originalName: a.nombre_archivo_original, })) );
    } catch (error) { next(error); }
  }
);

app.delete( "/api/files/:nombreArchivoUnico", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const idUsuario = req.usuario.id;
    const nombreArchivoUnico = req.params.nombreArchivoUnico;
    if(!nombreArchivoUnico) return res.status(400).json({error: "Nombre de archivo no especificado."});
    try {
      const { data: archivo, error } = await supabase.from("archivos_usuario").select("id").eq("usuario_id", idUsuario).eq("nombre_archivo_unico", nombreArchivoUnico).single();
      if (error || !archivo) return res.status(404).json({ error: "Archivo no encontrado." });
      const { error: deleteError } = await supabase.from("archivos_usuario").delete().eq("id", archivo.id);
      if (deleteError) throw new Error("Error eliminando de la base de datos: " + deleteError.message);
      try { await fs.unlink(path.join(directorioSubidas, nombreArchivoUnico)); } catch (fsError) { if (fsError.code !== "ENOENT") console.error("[Delete File FS Error]", fsError.message); }
      res.json({ message: "Archivo eliminado correctamente." });
    } catch (err) { next(err); }
  }
);
app.get("/api/conversations", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    try {
      const { data: conversaciones, error } = await supabase.from("conversaciones").select("id, titulo").eq("usuario_id", req.usuario.id).order("fecha_actualizacion", { ascending: false });
      if (error) throw error;
      res.json(conversaciones || []);
    } catch (error) { next(error); }
  }
);

app.get( "/api/conversations/:id/messages", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const { id } = req.params; // Este es el conversationId
    // Es buena práctica validar y parsear el ID si tu columna es numérica
    const conversationIdInt = parseInt(id);
    if (isNaN(conversationIdInt)) return res.status(400).json({error:"ID de conversación inválido."});

    try {
      const { data: convOwner, error: ownerError } = await supabase
        .from("conversaciones")
        .select("id")
        .eq("id", conversationIdInt) // Usar el ID parseado
        .eq("usuario_id", req.usuario.id) // req.usuario.id debe ser el ID numérico del usuario
        .maybeSingle();

      if(ownerError) throw ownerError;
      if (!convOwner) return res.status(404).json({ error: "Conversación no encontrada o no autorizada." });

      // ***** MODIFICACIÓN CLAVE AQUÍ *****
      const { data: mensajes, error } = await supabase
        .from("mensajes")
        // Selecciona las columnas que tu frontend necesite, incluyendo tipo_mensaje
        .select("id, rol, texto, fecha_envio, es_error, tipo_mensaje")
        .eq("conversacion_id", conversationIdInt) // Usar el ID parseado
        .order("fecha_envio", { ascending: true });
      // ***** FIN DE MODIFICACIÓN CLAVE *****

      if (error) throw error;
      res.json(mensajes || []);
    } catch (error) { next(error); }
  }
);

app.delete( "/api/conversations/:idConv", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const idConv = req.params.idConv;
    if (!idConv) return res.status(400).json({error:"ID de conversación requerido."})
    const idUsuario = req.usuario.id;
    try {
      const { error } = await supabase.from("conversaciones").delete().eq("id", idConv).eq("usuario_id", idUsuario);
      if (error) throw error;
      res.json({ message: "Conversación eliminada correctamente." });
    } catch (err) { next(err); }
  }
);

app.put( "/api/conversations/:id/title", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const { id } = req.params;
    if (!id) return res.status(400).json({error:"ID de conversación requerido."})
    const { nuevoTitulo } = req.body;
    if (!nuevoTitulo || typeof nuevoTitulo !== "string" || !nuevoTitulo.trim()) return res.status(400).json({ error: "Título no válido." });
    const tituloLimpio = nuevoTitulo.trim().substring(0,100);
    try {
      const { error } = await supabase.from("conversaciones").update({ titulo: tituloLimpio, fecha_actualizacion: new Date().toISOString() }).eq("id", id).eq("usuario_id", req.usuario.id);
      if (error) throw error;
      res.status(200).json({ message: "Título actualizado correctamente." });
    } catch (err) { next(err); }
  }
);

// --- RUTAS PRINCIPALES DE IA ---

app.post("/api/generateText", autenticarToken, subir, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    if (!clienteIA) return res.status(503).json({ error: "Servicio IA (Google) no disponible."});

    const usuarioId = req.usuario.id; // Asumiendo que req.usuario.id es el ID numérico
    const {
        prompt,
        conversationId: inputConversationId, // Puede ser string o undefined
        modeloSeleccionado,
        temperatura,
        topP,
        idioma,
        archivosSeleccionados, // Esperado como un array de strings (nombres de archivo únicos) o un string JSON de dicho array
    } = req.body;

    let archivosSeleccionadosArray = [];
    if (archivosSeleccionados) {
        try {
            archivosSeleccionadosArray = typeof archivosSeleccionados === 'string'
                ? JSON.parse(archivosSeleccionados)
                : archivosSeleccionados;
            if (!Array.isArray(archivosSeleccionadosArray)) {
                console.warn("[GenerateText] archivosSeleccionados procesado no es un array, usando array vacío.");
                archivosSeleccionadosArray = [];
            }
        } catch(e) {
            console.error("[GenerateText] Error parseando archivosSeleccionados:", e.message);
            // Devuelve un error si el parseo falla y era un string
            if (typeof archivosSeleccionados === 'string') {
                 return res.status(400).json({ error: "Formato de archivosSeleccionados inválido (debe ser un array JSON de strings)." });
            }
            archivosSeleccionadosArray = []; // Si no era string y falló, usa vacío.
        }
    }


    let conversationId = inputConversationId ? parseInt(inputConversationId) : null;
    let isNewConversation = false;

    try {
        if (!conversationId) { // Crear nueva conversación
            const { data, error } = await supabase
                .from("conversaciones")
                .insert([{
                    usuario_id: usuarioId,
                    titulo: (prompt?.trim().split(/\s+/).slice(0, 5).join(" ") || "Conversación nueva"),
                }])
                .select("id")
                .single(); // .single() espera una sola fila o error
            if (error) throw new Error(`Error creando conversación: ${error.message} (Detalles: ${error.details || ''})`);
            conversationId = data.id;
            isNewConversation = true;
        } else { // Usar conversación existente (validar pertenencia)
            const { data: convCheck, error: convCheckError } = await supabase
                .from("conversaciones")
                .select("id")
                .eq("id", conversationId)
                .eq("usuario_id", usuarioId)
                .maybeSingle();
            if (convCheckError) throw convCheckError;
            if (!convCheck) return res.status(404).json({error: "Conversación no encontrada o no pertenece al usuario."});
        }

        // Guardar mensaje del usuario si existe
        if (prompt && prompt.trim() !== "") {
            // ***** MODIFICACIÓN CLAVE AQUÍ *****
            const { error: msgInsertError } = await supabase.from("mensajes").insert([{
                conversacion_id: conversationId,
                rol: "user", // Asegúrate que 'user' es un valor de tu rol_enum
                texto: prompt,
                tipo_mensaje: "text" // Especificar tipo de mensaje
            }]);
            // ***** FIN DE MODIFICACIÓN CLAVE *****
            if (msgInsertError) {
                // Loggear el error pero no necesariamente detener el flujo si el resto puede continuar
                console.error("[GenerateText] Error guardando mensaje de usuario en DB:", msgInsertError.message);
            }
        }

        // Manejo de archivos PDF subidos (tu lógica original)
        const archivosNuevosSubidos = (req.files || []).filter(f => f.mimetype === 'application/pdf');
        if (archivosNuevosSubidos.length > 0) {
            const registrosArchivos = archivosNuevosSubidos.map((file) => ({
                usuario_id: usuarioId,
                nombre_archivo_unico: file.filename,
                nombre_archivo_original: file.originalname,
            }));
            const { error: errorInsertarArchivos } = await supabase.from("archivos_usuario").insert(registrosArchivos);
            if (errorInsertarArchivos) {
                archivosNuevosSubidos.forEach(async f => {try{await fs.unlink(f.path)}catch(e_fs){ console.error(`Error borrando archivo ${f.filename} tras fallo DB:`,e_fs) }});
                throw new Error("No se pudieron guardar los metadatos de los archivos PDF.");
            }
        }

        // Combinar archivos seleccionados existentes y nuevos
        const nombresArchivosUnicosParaContexto = [
            ...archivosSeleccionadosArray,
            ...archivosNuevosSubidos.map((f) => f.filename),
        ].filter(Boolean); // Eliminar nulos o undefined

        const contextoPDF = await generarContextoPDF(usuarioId, nombresArchivosUnicosParaContexto);

        if ((!prompt || prompt.trim() === "") && (!contextoPDF || contextoPDF.startsWith("[Error"))) {
             return res.status(400).json({error:"Se requiere un prompt o archivos PDF válidos para generar una respuesta."});
        }

        // Obtener historial de la conversación (sin cambios aquí, asume que generarRespuestaIA no necesita tipo_mensaje)
        const { data: historial, error: errorHist } = await supabase
            .from("mensajes")
            .select("rol, texto") // Solo lo que necesite generarRespuestaIA
            .eq("conversacion_id", conversationId)
            .eq("es_error", false) // Podrías querer filtrar mensajes de error
            .order("fecha_envio", { ascending: true });
        if (errorHist) throw new Error("Error cargando historial: " + errorHist.message);

        const promptParaIA = prompt || (idioma === 'es' ? "Resume el contenido de los archivos." : "Summarize the content of the files.");
        const respuestaIA = await generarRespuestaIA(promptParaIA, (historial || []), contextoPDF, modeloSeleccionado, parseFloat(temperatura), parseFloat(topP), idioma);

        // Guardar respuesta del modelo
        // ***** MODIFICACIÓN CLAVE AQUÍ *****
        const { error: modelMsgError } = await supabase.from("mensajes").insert([{
            conversacion_id: conversationId,
            rol: "model", // Asegúrate que 'model' es un valor de tu rol_enum
            texto: respuestaIA,
            tipo_mensaje: "text" // Especificar tipo de mensaje
        }]);
        // ***** FIN DE MODIFICACIÓN CLAVE *****
        if (modelMsgError) {
             console.error("[GenerateText] Error guardando mensaje del modelo en DB:", modelMsgError.message);
        }

        res.status(200).json({ respuesta: respuestaIA, isNewConversation, conversationId });
    } catch (error) {
        // Si se creó una nueva conversación pero algo falló después, podrías considerar eliminarla
        // if (isNewConversation && conversationId) { ... supabase.from("conversaciones").delete().eq("id", conversationId) ... }
        next(error);
    }
});
// Generar Imagen (con Clipdrop usando AXIOS)
app.post("/api/generateImage", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });

    // ***** MODIFICACIÓN CLAVE AQUÍ (obtener conversationId) *****
    const { prompt, conversationId: inputConversationId } = req.body;
    // ***** FIN DE MODIFICACIÓN CLAVE *****

    if (!prompt?.trim()) return res.status(400).json({ error: "Prompt inválido." });
    if (!CLIPDROP_API_KEY) return res.status(503).json({ error: "Servicio de imágenes (Clipdrop) no configurado." });

    // ***** MODIFICACIÓN CLAVE AQUÍ (validar y parsear conversationId) *****
    if (!inputConversationId) return res.status(400).json({ error: "ID de conversación requerido para guardar la imagen." });
    const conversationId = parseInt(inputConversationId);
    if (isNaN(conversationId)) return res.status(400).json({ error: "ID de conversación inválido." });
    // ***** FIN DE MODIFICACIÓN CLAVE *****

    try {
        // Verificar que la conversación pertenece al usuario autenticado
        const { data: convOwner, error: ownerError } = await supabase
            .from("conversaciones")
            .select("id")
            .eq("id", conversationId)
            .eq("usuario_id", req.usuario.id) // req.usuario.id debe ser el ID numérico
            .maybeSingle();

        if (ownerError) throw ownerError;
        if (!convOwner) return res.status(404).json({ error: "Conversación no encontrada o no autorizada." });

        const resultadoImagen = await generarImagenClipdrop(prompt.trim()); // Tu función original

        // ***** MODIFICACIÓN CLAVE AQUÍ (guardar mensaje de imagen en DB) *****
        const { data: mensajeGuardado, error: msgInsertError } = await supabase.from("mensajes").insert([{
            conversacion_id: conversationId,
            rol: "model", // La imagen es una respuesta del "modelo"
            texto: resultadoImagen.url, // Guardamos la URL relativa de la imagen
            tipo_mensaje: "image"    // Marcamos como tipo imagen
            // es_error se mantendrá en su valor DEFAULT (FALSE) que definiste en la tabla
        }]).select("id").single(); // Opcional: .select() si necesitas el ID del mensaje guardado
        // ***** FIN DE MODIFICACIÓN CLAVE *****

        if (msgInsertError) {
            console.error("[GenerateImage] Error guardando mensaje de imagen en DB:", msgInsertError.message);
            // Considera si eliminar el archivo de imagen del disco si falla el guardado en DB
            // await fs.unlink(path.join(directorioImagenesGeneradas, resultadoImagen.fileName));
            return res.status(207).json({ // 207 Multi-Status
                message: "Imagen generada pero ocurrió un error al guardarla en la conversación.",
                fileName: resultadoImagen.fileName,
                imageUrl: resultadoImagen.url,
                errorDB: msgInsertError.message
            });
        }

        res.json({
            message: "Imagen generada y guardada en conversación.",
            fileName: resultadoImagen.fileName,
            imageUrl: resultadoImagen.url,
            conversationId: conversationId, // Devolver conversationId es útil para el frontend
            messageId: mensajeGuardado?.id // Opcional: el ID del mensaje guardado
        });
    } catch (error) {
        // Asegúrate de que los errores de generarImagenClipdrop también se manejen bien
        if (error.status && error.message.includes("Clipdrop")) { // Errores personalizados de generarImagenClipdrop
             return res.status(error.status).json({error: error.message});
        }
        next(error);
    }
});

// --- Servir Archivos Estáticos ---
app.use('/generated_images', express.static(directorioImagenesGeneradas, { maxAge: '1h' }));

// --- Manejador de Errores Global (Original con ajustes) ---
app.use((err, req, res, next) => {
  console.error("‼️ Global Error:", err.message, ...(isDev && err.stack ? [err.stack] : [])); // Mejor log
  if (res.headersSent) { return next(err); }

  let statusCode = err.status || (err instanceof multer.MulterError ? 400 : 500);
  let mensajeUsuario = err.message || "Error interno del servidor.";
  const errorLang = req?.body?.idioma === "en" ? "en" : "es";

  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      statusCode = 413;
      mensajeUsuario = errorLang === "en" ? `File large (Max: ${TAMANO_MAX_ARCHIVO_MB}MB).` : `Archivo grande (Máx: ${TAMANO_MAX_ARCHIVO_MB}MB).`;
    } else if (err.message === 'Solo se permiten archivos PDF.') {
        // statusCode ya es 400 desde el filtro
        // mensajeUsuario ya es bueno
    } else {
      // statusCode ya es 400
      mensajeUsuario = errorLang === "en" ? `Upload error: ${err.message}.` : `Error subida: ${err.message}.`;
    }
  } else if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    statusCode = 400;
    mensajeUsuario = errorLang === "en" ? "Malformed JSON." : "JSON mal formado.";
  } else if (err.message.includes("no disponible") || err.message.includes("no configurado")) {
    statusCode = 503;
  } else if (err.message.includes("inválid") || err.message.includes("requerido")) {
    statusCode = 400;
  } else if (err.message.includes("autenticación") || err.message.includes("permisos") || err.message.includes("API Key inválida")) {
    statusCode = 401;
  } else if (err.message.includes("Límite") || err.message.includes("pago") || err.message.includes("créditos")) {
    statusCode = 402;
    mensajeUsuario = "Límite de uso gratuito alcanzado.";
  } else if (err.message.includes("Demasiadas solicitudes") || err.message.includes("sobrecargado") || err.message.includes("Too Many Requests")) {
    statusCode = 429;
    mensajeUsuario = "Servicio externo ocupado. Intente más tarde.";
  } else if (statusCode === 500 && (err.message.toLowerCase().includes("fetch") || err.message.toLowerCase().includes("network") || err.message.toLowerCase().includes("socket"))) {
     mensajeUsuario = "Error de red externa.";
  } else if (err.message.includes("404") || err.message.includes("no encontrado")) {
      statusCode = 404;
      mensajeUsuario = "Recurso no encontrado.";
  } else if (err.code && typeof err.code === 'string' && (err.code.startsWith('2') || err.code.startsWith('PGR')) ) { // Errores Supabase/Postgres
      console.warn("Error DB (Supabase/Postgres):", err.code, err.detail || err.hint);
      // Mantenemos el mensaje de Supabase si es específico, o uno genérico
      mensajeUsuario = err.message.includes("constraint") ? "Conflicto de datos." : "Error en base de datos.";
      if (err.code === '23505') statusCode = 409; // Unique violation
      else statusCode = 500; // Otros errores de DB como 500
  }

  res.status(statusCode).json({ error: mensajeUsuario });
});

// --- Iniciar Servidor ---
const PORT = PUERTO || 3001;
app.listen(PORT, () => {
    console.log(`\n🚀 Servidor en puerto ${PORT} | ${isDev ? 'DEV' : 'PROD'}`);
    console.log(`🔗 Local: http://localhost:${PORT}`);
    console.log(`\n--- Estado Servicios ---`);
    console.log(` Supabase: ${supabase ? '✅ OK' : '❌ NO OK (Verificar URL/KEY)'}`);
    console.log(` Google GenAI: ${clienteIA ? '✅ OK' : '❌ NO OK (Verificar API_KEY)'}`);
    console.log(` Clipdrop Imagen: ${CLIPDROP_API_KEY ? '✅ OK (Key presente)' : '❌ NO OK (Verificar CLIPDROP_API_KEY)'}`);
    console.log(`----------------------\n`);
});