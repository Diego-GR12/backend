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
import FormData from "form-data"; // <--- Necesario para Clipdrop

// --- Definiciones de Directorio ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const directorioSubidas = path.join(__dirname, "uploads");
const directorioImagenesGeneradas = path.join(__dirname, "generated_images");

// --- Carga de Variables de Entorno ---
dotenv.config();
const {
  PORT: PUERTO = 3001,
  // DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, // Comentados, ya que usas Supabase
  API_KEY, // Google GenAI
  JWT_SECRET,
  NODE_ENV = "development",
  SUPABASE_URL,
  SUPABASE_KEY,
  CLIPDROP_API_KEY, // <--- Variable para Clipdrop
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
console.log("[Startup] JWT_SECRET cargado:", JWT_SECRET ? `${JWT_SECRET.substring(0, 3)}... (longitud: ${JWT_SECRET.length})` : "¡NO CARGADO!");
if (!JWT_SECRET || JWT_SECRET.length < 32) console.warn("⚠️ [Startup] ADVERTENCIA: JWT_SECRET no definido o inseguro!");
if (!API_KEY) console.warn("⚠️ [Startup] ADVERTENCIA: API_KEY (Google) no configurada.");
if (!SUPABASE_URL) console.warn("⚠️ [Startup] ADVERTENCIA: SUPABASE_URL no configurada.");
if (!SUPABASE_KEY) console.warn("⚠️ [Startup] ADVERTENCIA: SUPABASE_KEY no configurada.");
if (!CLIPDROP_API_KEY) console.warn("⚠️ [Startup] ADVERTENCIA: CLIPDROP_API_KEY no configurada."); // Verificación para Clipdrop

const app = express();

// --- Inicialización de Clientes (Google AI, Supabase) ---
let clienteIA;
try {
  if (API_KEY) { clienteIA = new GoogleGenerativeAI(API_KEY); console.log("✅ Instancia de GoogleGenerativeAI creada."); }
  else { clienteIA = null; console.warn("⚠️ GoogleGenerativeAI NO inicializado (falta API_KEY)."); }
} catch (error) { console.error("🚨 FATAL: Error inicializando GoogleGenerativeAI:", error.message); clienteIA = null; }

let supabase;
try {
  if (SUPABASE_URL && SUPABASE_KEY) { supabase = createClient(SUPABASE_URL, SUPABASE_KEY); console.log("✅ Cliente Supabase inicializado."); }
  else { supabase = null; console.warn("⚠️ Supabase NO inicializado (faltan SUPABASE_URL o SUPABASE_KEY)."); }
} catch (error) { console.error("🚨 FATAL: Error inicializando Supabase:", error.message); supabase = null; }

// --- Middlewares ---
app.use(cors({ origin: (origin, callback) => { callback(null, origin || true); }, credentials: true, }));
app.use(cookieParser());
app.use(express.json());

// --- Middleware de Autenticación ---
const autenticarToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) { return res.status(401).json({ error: "Token no proporcionado" }); }
    if (!JWT_SECRET) { console.error("[Auth Error] JWT_SECRET Missing!"); return res.status(500).json({ error: "Error de configuración del servidor."}); }
    jwt.verify(token, JWT_SECRET, (err, usuarioToken) => {
        if (err) {
            const isExpired = err.name === "TokenExpiredError";
            console.error(`[Auth Error] Token (${err.name})`);
            if (isExpired) res.clearCookie("token", COOKIE_OPTIONS);
            return res.status(isExpired ? 401 : 403).json({ error: isExpired ? "Token expirado" : "Token inválido" });
        }
        req.usuario = usuarioToken;
        next();
    });
};

// --- Configuración de Multer (Original sin cambios) ---
const almacenamiento = multer.diskStorage({
  destination: directorioSubidas,
  filename: (req, file, cb) => {
    const sufijoUnico = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const nombreOriginalLimpio = file.originalname
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-zA-Z0-9.\-_]/g, "_")
      .replace(/_{2,}/g, "_");
    const extension = path.extname(nombreOriginalLimpio) || ".pdf";
    const nombreBase = path.basename(nombreOriginalLimpio, extension);
    cb(null, `${sufijoUnico}-${nombreBase}${extension}`);
  },
});
const subir = multer({ // Renombrado a 'subir' para coincidir con tu uso original en /api/generateText
  storage: almacenamiento,
  limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const isPdf = file.mimetype === "application/pdf";
    if (!isPdf){
      console.warn( `⚠️ Rechazado archivo no PDF: ${file.originalname} (${file.mimetype})`);
      // Para mantener el comportamiento original lo más cercano, solo hacemos cb(null, false)
      // y la ruta debe manejar que `req.files` pueda estar vacío o filtrar.
      // Si queremos que falle aquí, usaríamos:
      // return cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', 'Solo se permiten archivos PDF.'), false);
      return cb(null, false);
    }
    cb(null, true);
  },
}).array("archivosPdf");

const upload = multer({ storage }); // Para /api/files, tu uso original

// --- Crear directorios necesarios al inicio ---
[directorioSubidas, directorioImagenesGeneradas].forEach(dir => {
    if (!existsSync(dir)) {
        try { mkdirSync(dir, { recursive: true }); console.log(`✅ Directorio creado: ${dir}`); }
        catch (error) { console.error(`🚨 FATAL: No se pudo crear directorio ${dir}:`, error); }
    } else { console.log(`➡️ Directorio ya existe: ${dir}`); }
});

// --- Funciones Auxiliares (PDF, IA Texto - Lógica original sin cambios) ---

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
      return ""; // Devuelve vacío si no se encontraron archivos para evitar errores posteriores
    }

    const archivosMap = new Map(
      archivosDB.map((f) => [f.nombre_archivo_unico, f.nombre_archivo_original])
    );

    let textoCompleto = "";
    for (const nombreArchivoUnico of nombresArchivosUnicos) {
      const nombreOriginal = archivosMap.get(nombreArchivoUnico);
      // Si el archivo no está en el map (porque no pertenece al usuario o no existe en DB), saltarlo
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
        // No añadir nada al contexto si falla, tal como en tu original
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
  const langStrings = idioma === "en" ? { systemBase: "You are a helpful conversational assistant...", systemPdf: `You are an assistant that answers *based solely*...`, label: "Question", error: "I'm sorry..." } : { systemBase: "Eres un asistente conversacional útil...", systemPdf: `Eres un asistente que responde *basándose únicamente*...`, label: "Pregunta", error: "Lo siento..." };
  Object.assign(langStrings, idioma === "en" ? { systemPdf: `You are an assistant that answers *based solely* on the provided text. If the answer isn't in the text, state that clearly. Use Markdown format.\n\nReference Text (Context):\n"""\n{CONTEXT}\n"""\n\n`} : {systemPdf: `Eres un asistente que responde *basándose únicamente* en el texto proporcionado. Si la respuesta no está en el texto, indícalo claramente. Usa formato Markdown.\n\nTexto de Referencia (Contexto):\n"""\n{CONTEXT}\n"""\n\n`});


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

// --- Función para Generar Imágenes con CLIPDROP ---
async function generarImagenClipdrop(promptTexto) {
    if (!CLIPDROP_API_KEY) throw new Error("Servicio de imágenes (Clipdrop) no disponible (sin API key).");
    if (!promptTexto?.trim()) throw new Error("Prompt inválido para Clipdrop.");

    const CLIPDROP_API_URL = "https://clipdrop-api.co/text-to-image/v1";
    console.log(`[Img Gen Clipdrop] Solicitando para: "${promptTexto}"`);

    const form = new FormData();
    form.append('prompt', promptTexto.trim());
    console.log(`[Img Gen Clipdrop Debug] FormData a enviar: prompt = '${promptTexto.trim()}'`);

    try {
        const response = await fetch(CLIPDROP_API_URL, {
            method: 'POST',
            headers: { 'x-api-key': CLIPDROP_API_KEY, ...form.getHeaders() },
            body: form
        });

        if (!response.ok) {
            const status = response.status;
            let errorBody = "Error desconocido de API Clipdrop.";
            try { const errJson = await response.json(); errorBody = errJson.error || JSON.stringify(errJson); }
            catch (e) { try { errorBody = await response.text(); } catch (e2) {} }
            console.error(`[Img Gen Clipdrop] Error API (${status}):`, errorBody);
            
            let userMsg = `Error ${status} del servicio de imágenes.`;
            if (status === 400 && errorBody.toLowerCase().includes("prompt")) userMsg = "El prompt es requerido o inválido para Clipdrop.";
            else if (status === 401 || status === 403) userMsg = "API Key de Clipdrop inválida o sin permisos.";
            else if (status === 402) userMsg = "Límite de uso gratuito de Clipdrop alcanzado.";
            else if (status === 429) userMsg = "Servicio Clipdrop sobrecargado. Intente más tarde.";
            
            throw new Error(userMsg);
        }

        const bufferImagen = Buffer.from(await response.arrayBuffer());
        const tipoMime = response.headers.get('content-type') || 'image/png';
        const extension = tipoMime.includes('png') ? 'png' : (tipoMime.includes('jpeg') ? 'jpeg' : 'out');
        const nombreArchivo = `${Date.now()}-clipdrop-${promptTexto.substring(0,15).replace(/[^a-z0-9]/gi, '_')}.${extension}`;
        const rutaArchivo = path.join(directorioImagenesGeneradas, nombreArchivo);

        await fs.writeFile(rutaArchivo, bufferImagen);
        console.log(`[Img Gen Clipdrop] Guardada: ${rutaArchivo}`);

        return { fileName: nombreArchivo, url: `/generated_images/${nombreArchivo}` };

    } catch (error) {
        console.error("[Img Gen Clipdrop] Catch Error:", error.message);
        throw new Error(error.message || "Error desconocido generando imagen con Clipdrop.");
    }
}


// --- Rutas API (Auth, Files, Conversations - lógica original con mínimas correcciones Supabase) ---

app.post("/api/register", async (req, res, next) => {
  if (!supabase) return res.status(503).json({error: "BD no disponible."});
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });
  try {
    const contrasenaHasheada = await bcrypt.hash(password, 10);
    const { data, error } = await supabase.from("usuarios").insert([{ nombre_usuario: username, contrasena_hash: contrasenaHasheada }]).select("id").single();
    if (error) {
      if (error.code === "23505") return res.status(409).json({ error: "Nombre de usuario ya existe." });
      console.error(`[Register] Error DB: User ${username}`, error.message);
      throw error; // Relanzar para handler global
    }
    res.status(201).json({ message: "Registro exitoso.", userId: data.id });
  } catch (error) { console.error(`[Register Catch] User ${username}`, error.message); next(error); }
});

app.post("/api/login", async (req, res, next) => {
  if (!supabase) return res.status(503).json({error: "BD no disponible."});
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });
  try {
    const { data: usuario, error } = await supabase.from("usuarios").select("id, nombre_usuario, contrasena_hash").eq("nombre_usuario", username).single();
    if (error || !usuario) return res.status(401).json({ error: "Credenciales inválidas." });
    const passwordCorrecta = await bcrypt.compare(password, usuario.contrasena_hash);
    if (!passwordCorrecta) return res.status(401).json({ error: "Credenciales inválidas." });
    const payload = { id: usuario.id, username: usuario.nombre_usuario };
    if (!JWT_SECRET) throw new Error("JWT_SECRET no configurado");
    const token = jwt.sign(payload, JWT_SECRET, JWT_OPTIONS);
    res.cookie("token", token, COOKIE_OPTIONS);
    res.json({ message: "Login exitoso.", user: payload });
  } catch (error) { console.error(`[Login Catch] User ${username}`, error.message); next(error); }
});

app.post("/api/logout", (req, res) => { res.clearCookie("token", COOKIE_OPTIONS); res.status(200).json({ message: "Logout exitoso." }); });
app.get("/api/verify-auth", autenticarToken, (req, res) => { res.json({ user: req.usuario }); });

app.post("/api/files", autenticarToken, upload.array("archivosPdf"), async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible."});
    try {
      const usuarioId = req.usuario.id;
      const archivos = req.files;
      if (!archivos || archivos.length === 0) return res.status(400).json({ error: "No se subieron archivos." });
      const registros = archivos.map((file) => ({ usuario_id: usuarioId, nombre_archivo_unico: file.filename, nombre_archivo_original: file.originalname, }));
      const { error } = await supabase.from("archivos_usuario").insert(registros);
      if (error) {
        console.error("[Upload Files] Error Supabase:", error.message);
        // Intento de limpiar archivos subidos si falla la BD
        archivos.forEach(async f => { try { await fs.unlink(f.path); } catch(e) {/*ignorar*/} });
        throw error;
      }
      res.status(200).json({ mensaje: "Archivos subidos correctamente." });
    } catch (error) { console.error("[Upload Files Catch]", error.message); next(error); }
  }
);

app.get("/api/files", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible."});
    try {
      const { data: archivos, error } = await supabase.from("archivos_usuario").select("nombre_archivo_unico, nombre_archivo_original").eq("usuario_id", req.usuario.id).order("fecha_subida", { ascending: false });
      if (error) throw error;
      res.json(archivos.map((a) => ({ name: a.nombre_archivo_unico, originalName: a.nombre_archivo_original, })) || []);
    } catch (error) { console.error("[Get Files Catch]", error.message); next(error); }
  }
);

app.delete("/api/files/:nombreArchivoUnico", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible."});
    const idUsuario = req.usuario.id;
    const nombreArchivoUnico = req.params.nombreArchivoUnico;
    if(!nombreArchivoUnico) return res.status(400).json({error: "Nombre de archivo requerido."});
    try {
      const { data: archivo, error } = await supabase.from("archivos_usuario").select("id").eq("usuario_id", idUsuario).eq("nombre_archivo_unico", nombreArchivoUnico).single();
      if (error || !archivo) return res.status(404).json({ error: "Archivo no encontrado o no autorizado." });
      const { error: deleteError } = await supabase.from("archivos_usuario").delete().eq("id", archivo.id);
      if (deleteError) throw new Error("Error eliminando de la base de datos: " + deleteError.message);
      try { await fs.unlink(path.join(directorioSubidas, nombreArchivoUnico)); } catch (fsError) { if (fsError.code !== "ENOENT") console.error("Error borrando físico:", fsError.message); }
      res.json({ message: "Archivo eliminado correctamente." });
    } catch (err) { console.error("[Delete File Catch]", err.message); next(err); }
  }
);

app.get("/api/conversations", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible."});
    try {
      const { data: conversaciones, error } = await supabase.from("conversaciones").select("id, titulo").eq("usuario_id", req.usuario.id).order("fecha_actualizacion", { ascending: false });
      if (error) throw error;
      res.json(conversaciones || []);
    } catch (error) { console.error("[Get Convs Catch]", error.message); next(error); }
  }
);

app.get("/api/conversations/:id/messages", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible."});
    const { id } = req.params;
    if(!id) return res.status(400).json({error: "ID de conversación requerido."});
    try {
      const { data: convOwner, error: ownerError } = await supabase.from("conversaciones").select("id").eq("id", id).eq("usuario_id", req.usuario.id).maybeSingle();
      if (ownerError) throw ownerError;
      if (!convOwner) return res.status(404).json({ error: "Conversación no encontrada o no autorizada." });
      const { data: mensajes, error } = await supabase.from("mensajes").select("rol, texto, fecha_envio").eq("conversacion_id", id).order("fecha_envio", { ascending: true });
      if (error) throw error;
      res.json(mensajes || []);
    } catch (error) { console.error("[Get Msgs Catch]", error.message); next(error); }
  }
);

app.delete("/api/conversations/:idConv", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible."});
    const idConv = req.params.idConv;
    if(!idConv) return res.status(400).json({error: "ID de conversación requerido."});
    const idUsuario = req.usuario.id;
    try {
      const { error } = await supabase.from("conversaciones").delete().eq("id", idConv).eq("usuario_id", idUsuario);
      if (error) throw error;
      res.json({ message: "Conversación eliminada correctamente." }); // Podríamos verificar 'count' si delete lo devuelve
    } catch (err) { console.error("[Delete Conv Catch]", err.message); next(err); }
  }
);

app.put("/api/conversations/:id/title", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible."});
    const { id } = req.params;
    if(!id) return res.status(400).json({error: "ID de conversación requerido."});
    const { nuevoTitulo } = req.body;
    if (!nuevoTitulo || typeof nuevoTitulo !== "string" || !nuevoTitulo.trim()) return res.status(400).json({ error: "Título no válido." });
    const tituloLimpio = nuevoTitulo.trim().substring(0,100);
    try {
      const { error } = await supabase.from("conversaciones").update({ titulo: tituloLimpio }).eq("id", id).eq("usuario_id", req.usuario.id);
      if (error) throw error;
      // Podríamos usar .select().single() para verificar que realmente se actualizó, si es necesario.
      res.status(200).json({ message: "Título actualizado correctamente." });
    } catch (err) { console.error("[Update Title Catch]", err.message); next(err); }
  }
);


// --- RUTAS PRINCIPALES DE IA ---

// Generar Texto (Chat)
app.post("/api/generateText", autenticarToken, subir, async (req, res, next) => { // Usar 'subir' original
    if (!supabase || !clienteIA) return res.status(503).json({ error: "Servicio BD o IA no disponible." });
    const usuarioId = req.usuario.id;
    const { prompt, conversationId: inputConvId, modeloSeleccionado, temperatura, topP, idioma, archivosSeleccionados } = req.body;
    let archivosSelArr = [];
    try { if (archivosSeleccionados) archivosSelArr = JSON.parse(archivosSeleccionados || "[]"); if(!Array.isArray(archivosSelArr)) throw new Error(); }
    catch(e){return res.status(400).json({error: "Formato archivosSeleccionados inválido."})}

    let conversationId = inputConvId;
    let isNewConversation = false;

    try {
        if (!conversationId) {
            const titulo = (prompt||"Conversación").trim().split(/\s+/).slice(0,5).join(" ") || "Nueva";
            const {data:cData,error:cErr} = await supabase.from("conversaciones").insert([{usuario_id:usuarioId,titulo}]).select("id").single();
            if(cErr) throw cErr; conversationId=cData.id; isNewConversation=true;
        }

        // Guardar mensaje del usuario, si existe un prompt.
        if (prompt && prompt.trim() !== "") {
             const { error: uMsgErr } = await supabase.from("mensajes").insert([{conversacion_id:conversationId, rol:"user", texto:prompt}]);
             if (uMsgErr) console.error("Error guardando msg user en BD:", uMsgErr.message); // No fatal para el flujo principal
        }

        const archivosNuevos = (req.files || []).filter(f => f.mimetype === 'application/pdf'); // Filtrar por si acaso el fileFilter de multer falló
        
        if (archivosNuevos.length > 0) {
            const records = archivosNuevos.map(f=>({usuario_id:usuarioId, nombre_archivo_unico:f.filename, nombre_archivo_original:f.originalname}));
            const {error:fErr} = await supabase.from("archivos_usuario").insert(records);
            if(fErr){ archivosNuevos.forEach(async f=>{try{await fs.unlink(f.path);}catch(e){/*ignorar*/}}); throw fErr;} // Limpiar
        }

        const archivosParaContexto = [...archivosSelArr, ...archivosNuevos.map(f=>f.filename)].filter(Boolean);
        let ctxPDF = ""; 
        if(archivosParaContexto.length > 0) {
            ctxPDF = await generarContextoPDF(usuarioId, archivosParaContexto);
        }
        
        // Si no hay prompt Y (no hay archivos para contexto O el contexto PDF resultó ser un error/vacío)
        if ((!prompt || prompt.trim() === "") && (archivosParaContexto.length === 0 || !ctxPDF || ctxPDF.startsWith("["))) {
             return res.status(400).json({error:"Se requiere un prompt o archivos PDF válidos para generar una respuesta."});
        }

        const {data:hist, error:histErr} = await supabase.from("mensajes").select("rol, texto").eq("conversacion_id",conversationId).order("fecha_envio",{ascending:true});
        if(histErr) throw histErr;

        const iaPrompt = prompt || (idioma==='es'?"Resume el contenido de los archivos.":"Summarize the content of the files.");
        const respIA = await generarRespuestaIA(iaPrompt, hist||[], ctxPDF, modeloSeleccionado, parseFloat(temperatura), parseFloat(topP), idioma);
        
        const {error:mMsgErr} = await supabase.from("mensajes").insert([{conversacion_id:conversationId, rol:"model", texto:respIA}]);
        if(mMsgErr) console.error("Error guardando msg model en BD:", mMsgErr.message); // No fatal
        
        res.json({respuesta:respIA, isNewConversation, conversationId});
    } catch (error) { next(error); } // Dejar al handler global
});

// Generar Imagen (con Clipdrop)
app.post("/api/generateImage", autenticarToken, async (req, res, next) => {
    const { prompt } = req.body;
    if (!prompt?.trim()) return res.status(400).json({ error: "Prompt inválido." });
    if (!CLIPDROP_API_KEY) return res.status(503).json({ error: "Servicio de imágenes (Clipdrop) no configurado." });

    try {
        const resultado = await generarImagenClipdrop(prompt.trim());
        res.json({ message: "Imagen generada con Clipdrop.", fileName: resultado.fileName, imageUrl: resultado.url });
    } catch (error) { next(error); }
});


// --- Servir Archivos Estáticos ---
app.use('/generated_images', express.static(directorioImagenesGeneradas, { maxAge: '1h' }));

// --- Manejador de Errores Global (original sin cambios significativos) ---
app.use((err, req, res, next) => {
  console.error("‼️ Global Error:", err.message);
  if (NODE_ENV !== "production" && err.stack) console.error(err.stack);
  let statusCode = typeof err.status === "number" ? err.status : 500;
  let mensajeUsuario = "Error interno del servidor.";
  const errorLang = req?.body?.idioma === "en" ? "en" : "es"; // Intenta obtener idioma del body

  if (err instanceof multer.MulterError) {
    statusCode = 400;
    if (err.code === "LIMIT_FILE_SIZE") {
      statusCode = 413;
      mensajeUsuario = errorLang === "en" ? `File too large (Max: ${TAMANO_MAX_ARCHIVO_MB} MB).` : `Archivo muy grande (Máx: ${TAMANO_MAX_ARCHIVO_MB} MB).`;
    } else if (err.message === 'Solo se permiten archivos PDF.') { // Error específico de tu filtro
        mensajeUsuario = err.message;
    } else {
      mensajeUsuario = errorLang === "en" ? `File upload error: ${err.message}.` : `Error subida archivo: ${err.message}.`;
    }
  } else if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    statusCode = 400;
    mensajeUsuario = errorLang === "en" ? "Malformed request (Invalid JSON)." : "Petición mal formada (JSON inválido).";
  } else if (err.message.includes("no disponible") || err.message.includes("no configurado") ) { // Errores de servicio/configuración
    statusCode = 503;
    mensajeUsuario = err.message; // El mensaje del error ya es bueno
  } else if (err.message.includes("inválid") || err.message.includes("requerido")) { // Errores de validación
    statusCode = 400;
    mensajeUsuario = err.message;
  } else if (err.message.includes("autenticación") || err.message.includes("permisos") || err.message.includes("API Key inválida")) {
    statusCode = 401; // O 403
    mensajeUsuario = err.message;
  } else if (err.message.includes("Límite") || err.message.includes("pago") || err.message.includes("créditos") ) {
    statusCode = 402;
    mensajeUsuario = "Límite de uso gratuito alcanzado.";
  } else if (err.message.includes("Demasiadas solicitudes") || err.message.includes("sobrecargado") || err.message.includes("Too Many Requests")) {
    statusCode = 429;
    mensajeUsuario = "Servicio externo ocupado. Intente más tarde.";
  } else if (statusCode === 500 && (err.message.toLowerCase().includes("fetch") || err.message.toLowerCase().includes("network error") || err.message.toLowerCase().includes("socket hang up")) ) {
     mensajeUsuario = "Error de red contactando servicio externo."; // Más genérico
  }
   // Mantener mensaje original para otros errores si es descriptivo
  else if (statusCode < 500 && err.message) {
    mensajeUsuario = err.message;
  }
  // Si el error tiene un 'code' de Supabase (ej. '23505'), podría mapearse a un mensaje más amigable aquí.
  // Por ahora, si es un error de Supabase relanzado, se usará su `err.message`.


  if (res.headersSent) {
    console.error("‼️ Error caught AFTER headers were sent!");
    return next(err); // Muy importante para evitar crashes
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