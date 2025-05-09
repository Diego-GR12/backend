// --- START OF FILE index.js (CORS MEJORADO, LOGS DEBUG HF) ---

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
import axios from 'axios';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const directorioSubidas = path.join(__dirname, "uploads");

dotenv.config(); 

const {
  PORT: PUERTO = 3001,
  API_KEY, 
  JWT_SECRET,
  NODE_ENV = "development", 
  SUPABASE_URL,
  SUPABASE_KEY,
  HUGGING_FACE_API_KEY,
  FRONTEND_URL, // MUY IMPORTANTE: Configurar en Render SIN la barra final (ej: https://chat-bot-jwpc.onrender.com)
} = process.env;

const isDev = NODE_ENV !== "production";

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: !isDev,
  sameSite: !isDev ? "none" : "lax",
  maxAge: 3600 * 1000 * 24, 
  path: "/",
};

const TAMANO_MAX_ARCHIVO_MB = 20;
const MAX_LONGITUD_CONTEXTO = 30000; 
const MODELOS_GEMINI_PERMITIDOS = ["gemini-1.5-flash", "gemini-1.5-pro"];
const MODELO_GEMINI_POR_DEFECTO = "gemini-1.5-flash";
const MODELO_IMAGEN_HF_POR_DEFECTO = "CompVis/stable-diffusion-v1-4"; // Para diagnóstico inicial
const TEMP_POR_DEFECTO = 0.7;
const TOPP_POR_DEFECTO = 0.9;
const IDIOMA_POR_DEFECTO = "es";
const JWT_OPTIONS = { expiresIn: "24h" };

console.log("[Startup] Verificando variables de entorno...");
const requiredEnvVars = { JWT_SECRET, API_KEY, SUPABASE_URL, SUPABASE_KEY, HUGGING_FACE_API_KEY, FRONTEND_URL };
for (const [key, value] of Object.entries(requiredEnvVars)) {
  if (!value) {
    console.warn(`⚠️ [Startup] ADVERTENCIA: Variable de entorno ${key} no configurada.`);
  } else {
    const valPreview = (key === 'JWT_SECRET' || key.includes('_KEY')) && value.length > 10 ? `${value.substring(0, 3)}...${value.substring(value.length - 3)}` : value;
    console.log(`[Startup] ✅ ${key} cargada: ${key.includes('_KEY') && key !== 'API_KEY' ? valPreview + ` (longitud: ${value.length})` : valPreview}`);
  }
}
if (JWT_SECRET && JWT_SECRET.length < 32) console.warn("⚠️ [Startup] ADVERTENCIA: JWT_SECRET es corto, considera usar uno más largo y seguro.");
if (NODE_ENV === "production" && !FRONTEND_URL) console.warn("⚠️ [Startup] ADVERTENCIA CRÍTICA: FRONTEND_URL no configurada para producción. ¡CORS FALLARÁ!");


const app = express();

let clienteIA; 
if (API_KEY) {
  try { clienteIA = new GoogleGenerativeAI(API_KEY); console.log("✅ Instancia de GoogleGenerativeAI creada."); }
  catch (error) { console.error("🚨 Error al inicializar GoogleGenerativeAI:", error.message); }
} else { console.warn("⚠️ API_KEY de Google no provista. Funcionalidad de texto IA (Google) deshabilitada."); }

let supabase; 
if (SUPABASE_URL && SUPABASE_KEY) {
  try { supabase = createClient(SUPABASE_URL, SUPABASE_KEY); console.log("✅ Cliente Supabase inicializado."); }
  catch (error) { console.error("🚨 Error al inicializar Supabase:", error.message); }
} else { console.warn("⚠️ SUPABASE_URL o SUPABASE_KEY no provistas. Funcionalidad de BD (Supabase) deshabilitada."); }

// --- CONFIGURACIÓN CORS MEJORADA ---
app.use(
  cors({
    origin: (origin, callback) => {
      // Función para normalizar URLs: quitar barra final y convertir a minúsculas para la comparación.
      const normalizeUrl = (url) => {
        if (url) {
          let normalized = url.toLowerCase();
          if (normalized.endsWith('/')) {
            normalized = normalized.slice(0, -1);
          }
          return normalized;
        }
        return undefined; // Si url es undefined, devuelve undefined
      };

      const normalizedOrigin = normalizeUrl(origin);
      
      const allowedOrigins = [
        FRONTEND_URL, 
        'http://localhost:5173', 
        'http://localhost:3000'
      ]
      .filter(Boolean) // Quitar undefineds/nulls/vacíos
      .map(normalizeUrl); // Normalizar todas las URLs permitidas

      // Log para depuración de CORS
      // console.log(`[CORS DEBUG] Request Origin: ${origin}, Normalized Origin: ${normalizedOrigin}`);
      // console.log(`[CORS DEBUG] Allowed Origins (raw): ${[FRONTEND_URL, 'http://localhost:5173', 'http://localhost:3000']}`);
      // console.log(`[CORS DEBUG] Allowed Origins (normalized): ${allowedOrigins}`);

      if (isDev && !origin) { // Permitir Postman/curl en desarrollo sin origin
        console.log("🌍 Solicitud CORS (sin origen, modo dev - permitido)");
        return callback(null, true);
      }
      
      if (allowedOrigins.includes(normalizedOrigin)) {
        console.log("🌍 Solicitud CORS desde (permitido):", origin);
        callback(null, true);
      } else {
        console.warn("🚫 Solicitud CORS bloqueada desde:", origin, `(Normalizado: ${normalizedOrigin})`);
        console.warn("   Orígenes permitidos (normalizados):", allowedOrigins);
        console.warn(`   Verifica que FRONTEND_URL ('${FRONTEND_URL}') en el backend coincida EXACTAMENTE (sin / final) con el origen del frontend y que esté configurada en Render.`);
        callback(new Error('Origen no permitido por la política CORS del servidor.'));
      }
    },
    credentials: true,
  })
);
// --- FIN CONFIGURACIÓN CORS MEJORADA ---

app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const autenticarToken = (req, res, next) => {
  // ... (código de autenticarToken sin cambios, ya está bien)
  const token = req.cookies.token;
  const requestPath = req.path; 
  if (!token) {
      console.log(`[Auth] Fail: No token cookie para path: ${requestPath}`);
      return res.status(401).json({ error: "Acceso no autorizado: Token no proporcionado." });
  }
  if (!JWT_SECRET) {
    console.error(`CRITICAL: JWT_SECRET no está definido. No se puede verificar token para path: ${requestPath}`);
    return res.status(500).json({ error: "Error de configuración del servidor (autenticación)." });
  }
  jwt.verify(token, JWT_SECRET, (err, usuarioToken) => {
    if (err) {
      const isExpired = err.name === "TokenExpiredError";
      console.warn(`[Auth] Fallo verificación token (${err.name})${isExpired ? " - Expirado." : "."} para path: ${requestPath}`);
      if (isExpired) {
        res.clearCookie("token", COOKIE_OPTIONS);
        return res.status(401).json({ error: "Sesión expirada, por favor inicia sesión de nuevo." }); 
      }
      return res.status(403).json({ error: "Token inválido o corrupto." }); 
    }
    // console.log(`[Auth] OK: Token verificado para ${usuarioToken.username} (ID: ${usuarioToken.id}) para path: ${requestPath}`); // Loguear esto puede ser muy verboso
    req.usuario = usuarioToken;
    next();
  });
};

if (!existsSync(directorioSubidas)) {
  try { mkdirSync(directorioSubidas, { recursive: true }); console.log(`📂 Directorio de subidas creado: ${directorioSubidas}`); }
  catch (error) { console.error(`🚨 Error creando directorio de subidas ${directorioSubidas}:`, error); }
}

const almacenamiento = multer.diskStorage({
  destination: directorioSubidas,
  filename: (req, file, cb) => {
    const sufijoUnico = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const nombreOriginalLimpio = file.originalname.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^\w.-]/g, "_").replace(/_{2,}/g, "_");
    const extension = path.extname(nombreOriginalLimpio) || ".pdf";
    const nombreBase = path.basename(nombreOriginalLimpio, extension);
    cb(null, `${sufijoUnico}-${nombreBase}${extension}`);
  },
});
const subirPDFs = multer({
  storage: almacenamiento,
  limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "application/pdf") {
      cb(null, true);
    } else {
      cb(new multer.MulterError("LIMIT_UNEXPECTED_FILE", "Solo se permiten archivos PDF."), false);
    }
  },
}).array("archivosPdf");


async function extraerTextoDePDF(rutaArchivo) {
  // ... (código como antes)
  const nombreArchivoLog = path.basename(rutaArchivo);
  try {
    await fs.access(rutaArchivo); 
    const bufferDatos = await fs.readFile(rutaArchivo);
    const datos = await pdfParse(bufferDatos);
    return { texto: datos?.text?.trim() || "", error: null };
  } catch (error) {
    console.error(`❌ [PDF Extract] Error procesando ${nombreArchivoLog}:`, error.message);
    return { texto: null, error: `Error al procesar PDF ${nombreArchivoLog}: ${error.code === 'ENOENT' ? 'no encontrado' : error.message}` };
  }
}

async function generarContextoPDF(idUsuario, nombresArchivosUnicos) {
  // ... (código como antes)
  if (!supabase) return "[Error: Servicio de BD no disponible para contexto PDF]";
  if (!nombresArchivosUnicos || nombresArchivosUnicos.length === 0) return "";
  try {
    const { data: archivosDB, error: dbError } = await supabase
      .from("archivos_usuario")
      .select("nombre_archivo_unico, nombre_archivo_original")
      .eq("usuario_id", idUsuario)
      .in("nombre_archivo_unico", nombresArchivosUnicos);

    if (dbError) {
      console.error("[Context PDF] ❌ Error Supabase al obtener archivos:", dbError.message);
      return "[Error al recuperar metadatos de archivos PDF]";
    }
    if (!archivosDB || archivosDB.length === 0) {
        console.warn(`[Context PDF] No se encontraron archivos en DB para IDs: ${nombresArchivosUnicos.join(', ')} (Usuario ${idUsuario})`);
        return "[No se encontraron archivos PDF para el contexto especificado]";
    }

    const archivosMap = new Map(archivosDB.map((f) => [f.nombre_archivo_unico, f.nombre_archivo_original]));
    let textoCompleto = "";
    for (const nombreArchivoUnico of nombresArchivosUnicos) {
      const nombreOriginal = archivosMap.get(nombreArchivoUnico) || nombreArchivoUnico;
      const ruta = path.join(directorioSubidas, nombreArchivoUnico);
      const { texto, error: extractError } = await extraerTextoDePDF(ruta);
      if (extractError) {
        console.warn(`[Context PDF] ⚠️ No se pudo procesar ${nombreArchivoUnico}: ${extractError}`);
        continue;
      }
      if (texto) textoCompleto += `\n\n--- Inicio Archivo: ${nombreOriginal} ---\n${texto}\n--- Fin Archivo: ${nombreOriginal} ---`;
    }
    return textoCompleto.trim();
  } catch (err) {
    console.error("[Context PDF] ❌ Excepción general:", err);
    return "[Error crítico al generar contexto desde PDF]";
  }
}

async function generarRespuestaIA(prompt, historialDB, textoPDF, modeloReq, temp, topP, lang) {
  // ... (código como antes)
  if (!clienteIA) throw new Error("Servicio IA (Google Gemini) no disponible.");
  
  const nombreModelo = MODELOS_GEMINI_PERMITIDOS.includes(modeloReq) ? modeloReq : MODELO_GEMINI_POR_DEFECTO;
  if (modeloReq && nombreModelo !== modeloReq) console.warn(`[Gen IA Texto] ⚠️ Modelo Gemini no válido ('${modeloReq}'), usando por defecto: ${nombreModelo}`);
  
  const configGeneracion = {
    temperature: !isNaN(temp) ? Math.max(0, Math.min(1, temp)) : TEMP_POR_DEFECTO,
    topP: !isNaN(topP) ? Math.max(0, Math.min(1, topP)) : TOPP_POR_DEFECTO,
  };
  const idioma = ["es", "en"].includes(lang) ? lang : IDIOMA_POR_DEFECTO;
  
  const langStrings = idioma === "es"
      ? { systemBase: "Eres un asistente conversacional útil y amigable. Responde de forma clara, concisa y siempre en formato Markdown.", systemPdf: `Eres un asistente experto que responde preguntas *basándose únicamente* en el texto de los archivos PDF proporcionados. Si la respuesta no se encuentra en el texto, indícalo claramente. Formatea tus respuestas en Markdown.\n\nTextos de Referencia (Contexto):\n"""\n{CONTEXT}\n"""\n\n`, label: "Pregunta del usuario", error: "Lo siento, no pude procesar tu solicitud en este momento." }
      : { systemBase: "You are a helpful and friendly conversational assistant. Answer clearly, concisely, and always in Markdown format.", systemPdf: `You are an expert assistant that answers questions *based solely* on the text from the provided PDF files. If the answer is not in the text, state that clearly. Format your responses in Markdown.\n\nReference Texts (Context):\n"""\n{CONTEXT}\n"""\n\n`, label: "User question", error: "I'm sorry, I couldn't process your request at this time." };

  let systemInstruction = textoPDF ? langStrings.systemPdf.replace("{CONTEXT}", textoPDF.substring(0, MAX_LONGITUD_CONTEXTO)) : langStrings.systemBase;
  if (textoPDF && textoPDF.length > MAX_LONGITUD_CONTEXTO) console.warn(`[Gen IA Texto] ✂️ Contexto PDF truncado a ${MAX_LONGITUD_CONTEXTO} caracteres.`);
  
  const contenidoGemini = [
    { role: "user", parts: [{ text: systemInstruction }] }, 
    { role: "model", parts: [{ text: "Entendido. ¿Cuál es tu pregunta?" }] }, 
    ...historialDB.filter(m => m.texto?.trim()).map(m => ({ role: m.rol === "user" ? "user" : "model", parts: [{ text: m.texto }] })),
    { role: "user", parts: [{ text: `${langStrings.label}: ${prompt}` }] },
  ];

  console.log(`[Gen IA Texto] ➡️  Enviando ${contenidoGemini.length} partes a Gemini (${nombreModelo}). Prompt: ${prompt.substring(0,50)}...`);
  try {
    const modeloGemini = clienteIA.getGenerativeModel({ model: nombreModelo });
    const resultado = await modeloGemini.generateContent({ contents: contenidoGemini, generationConfig: configGeneracion });
    const response = resultado?.response;
    const textoRespuestaIA = response?.candidates?.[0]?.content?.parts?.[0]?.text;

    if (textoRespuestaIA) {
      console.log("[Gen IA Texto] ✅ Respuesta recibida de Gemini.");
      return textoRespuestaIA.trim();
    }
    
    const blockReason = response?.promptFeedback?.blockReason;
    const finishReason = response?.candidates?.[0]?.finishReason;
    console.warn(`[Gen IA Texto] ⚠️ Respuesta vacía/bloqueada de Gemini. BlockReason: ${blockReason}, FinishReason: ${finishReason}`);
    let errorMsg = langStrings.error;
    if (blockReason) errorMsg += (idioma === "es" ? `. Razón del bloqueo: ${blockReason}` : `. Block reason: ${blockReason}`);
    else if (finishReason && finishReason !== "STOP") errorMsg += (idioma === "es" ? `. Razón de finalización: ${finishReason}` : `. Finish reason: ${finishReason}`);
    else errorMsg += (idioma === "es" ? ". (Respuesta inválida o vacía)" : ". (Invalid or empty response)");
    return errorMsg;
  } catch (error) {
    console.error(`[Gen IA Texto] ❌ Error API Gemini (${nombreModelo}):`, error.message, error.stack);
    return `${langStrings.error} (Detalle del error del servicio de IA: ${error.message || "desconocido"})`;
  }
}

// ---- TODAS TUS RUTAS API (AUTH, FILES, CONVERSATIONS, generateText) VAN AQUÍ ----
// ---- (Las omito para brevedad, pero asegúrate de que están como antes) ----

app.post("/api/register", async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio no disponible (BD)." });
  const { username, password } = req.body;
  if (!username || !password || password.length < 6) return res.status(400).json({ error: "Usuario y contraseña (mín. 6 caracteres) son requeridos." });
  try {
    const contrasenaHasheada = await bcrypt.hash(password, 10);
    const { data, error } = await supabase.from("usuarios").insert([{ nombre_usuario: username, contrasena_hash: contrasenaHasheada }]).select("id").single();
    if (error) {
      if (error.code === "23505") return res.status(409).json({ error: "Este nombre de usuario ya está en uso." });
      throw error;
    }
    console.log(`[Register] OK: User ${username} (ID: ${data.id})`);
    res.status(201).json({ message: "Registro exitoso.", userId: data.id });
  } catch (error) { next(error); }
});

app.post("/api/login", async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio no disponible (BD)." });
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Usuario y contraseña son requeridos." });
  try {
    const { data: usuario, error } = await supabase.from("usuarios").select("id, nombre_usuario, contrasena_hash").eq("nombre_usuario", username).limit(1).single();
    if (error || !usuario) return res.status(401).json({ error: "Credenciales incorrectas." });
    const passwordCorrecta = await bcrypt.compare(password, usuario.contrasena_hash);
    if (!passwordCorrecta) return res.status(401).json({ error: "Credenciales incorrectas." });
    const payload = { id: usuario.id, username: usuario.nombre_usuario };
    const token = jwt.sign(payload, JWT_SECRET, JWT_OPTIONS);
    res.cookie("token", token, COOKIE_OPTIONS);
    console.log(`[Login] OK: User ${username} (ID: ${usuario.id}), cookie sent.`);
    res.json({ message: "Inicio de sesión exitoso.", user: payload });
  } catch (error) { next(error); }
});

app.post("/api/logout", (_req, res) => {
  console.log(`[Logout] Solicitud de cierre de sesión.`);
  res.clearCookie("token", COOKIE_OPTIONS);
  res.status(200).json({ message: "Cierre de sesión exitoso." });
});

app.get("/api/verify-auth", autenticarToken, (req, res) => {
  // El log ya está en autenticarToken
  res.json({ user: req.usuario });
});

app.post("/api/files", autenticarToken, subirPDFs, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio no disponible (BD)." });
  try {
    const usuarioId = req.usuario.id;
    const archivos = req.files;
    if (!archivos || archivos.length === 0) return res.status(400).json({ error: "No se subieron archivos PDF válidos." });
    
    const registros = archivos.map((file) => ({
      usuario_id: usuarioId,
      nombre_archivo_unico: file.filename,
      nombre_archivo_original: file.originalname,
    }));
    const { error } = await supabase.from("archivos_usuario").insert(registros);
    if (error) throw error;
    
    console.log(`[Upload Files] ✅ ${archivos.length} archivo(s) guardado(s) para usuario ${usuarioId}.`);
    res.status(200).json({ mensaje: `${archivos.length} archivo(s) subido(s) correctamente.` });
  } catch (error) {
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        try { await fs.unlink(path.join(directorioSubidas, file.filename)); }
        catch (unlinkError) { console.warn(`Error eliminando archivo ${file.filename} tras fallo en /api/files: ${unlinkError.message}`); }
      }
    }
    next(error);
  }
});

app.get("/api/files", autenticarToken, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio no disponible (BD)." });
  try {
    const { data: archivos, error } = await supabase.from("archivos_usuario").select("nombre_archivo_unico, nombre_archivo_original").eq("usuario_id", req.usuario.id).order("fecha_subida", { ascending: false });
    if (error) throw error;
    res.json(archivos.map((a) => ({ name: a.nombre_archivo_unico, originalName: a.nombre_archivo_original })));
  } catch (error) { next(error); }
});

app.delete("/api/files/:nombreArchivoUnico", autenticarToken, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio no disponible (BD)." });
  const idUsuario = req.usuario.id;
  const { nombreArchivoUnico } = req.params;
  try {
    const { data: archivoDB, error: findError } = await supabase.from("archivos_usuario").select("id").eq("usuario_id", idUsuario).eq("nombre_archivo_unico", nombreArchivoUnico).single();
    if (findError || !archivoDB) return res.status(404).json({ error: "Archivo no encontrado o no autorizado." });
    
    const { error: deleteDBError } = await supabase.from("archivos_usuario").delete().eq("id", archivoDB.id);
    if (deleteDBError) throw deleteDBError;
    
    const rutaArchivo = path.join(directorioSubidas, nombreArchivoUnico);
    try { await fs.unlink(rutaArchivo); } 
    catch (fsError) { if (fsError.code !== "ENOENT") console.warn(`[File Delete] Error eliminando archivo del disco (puede que ya no exista): ${fsError.message}`);}
    
    console.log(`[File Delete] ✅ Archivo ${nombreArchivoUnico} eliminado por usuario ${idUsuario}`);
    res.json({ message: "Archivo eliminado correctamente." });
  } catch (err) { next(err); }
});

app.get("/api/conversations", autenticarToken, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio no disponible (BD)." });
  try {
    const { data: conversaciones, error } = await supabase.from("conversaciones").select("id, titulo").eq("usuario_id", req.usuario.id).order("fecha_actualizacion", { ascending: false });
    if (error) throw error;
    res.json(conversaciones);
  } catch (error) { next(error); }
});

app.get("/api/conversations/:id/messages", autenticarToken, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio no disponible (BD)." });
  const { id } = req.params;
  try {
    const { data: conv, error: convError } = await supabase.from("conversaciones").select("id").eq("id", id).eq("usuario_id", req.usuario.id).single();
    if (convError || !conv) return res.status(404).json({ error: "Conversación no encontrada o no autorizada." });

    const { data: mensajes, error } = await supabase.from("mensajes").select("rol, texto, fecha_envio").eq("conversacion_id", id).order("fecha_envio", { ascending: true });
    if (error) throw error;
    res.json(mensajes);
  } catch (error) { next(error); }
});

app.delete("/api/conversations/:idConv", autenticarToken, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio no disponible (BD)." });
  const { idConv } = req.params;
  const idUsuario = req.usuario.id;
  try {
    const { error } = await supabase.from("conversaciones").delete().eq("id", idConv).eq("usuario_id", idUsuario);
    if (error) throw error;
    console.log(`[Conv Delete] ✅ Conversación ${idConv} eliminada por usuario ${idUsuario}`);
    res.json({ message: "Conversación eliminada correctamente." });
  } catch (err) { next(err); }
});

app.put("/api/conversations/:id/title", autenticarToken, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio no disponible (BD)." });
  const { id } = req.params;
  const { nuevoTitulo } = req.body;
  const usuarioId = req.usuario.id;
  if (!nuevoTitulo || typeof nuevoTitulo !== "string" || nuevoTitulo.trim().length === 0 || nuevoTitulo.trim().length > 100) {
    return res.status(400).json({ error: "Título no válido (máx 100 caracteres)." });
  }
  try {
    const { error } = await supabase.from("conversaciones").update({ titulo: nuevoTitulo.trim() }).eq("id", id).eq("usuario_id", usuarioId);
    if (error) throw error;
    console.log(`[Conv Title] ✅ Título actualizado para conv ${id} por user ${usuarioId}`);
    res.status(200).json({ message: "Título actualizado correctamente." });
  } catch (err) { next(err); }
});

app.post("/api/generateText", autenticarToken, subirPDFs, async (req, res, next) => {
  if (!supabase || !clienteIA) return res.status(503).json({ error: "Servicio IA o BD no disponible." });
  
  const usuarioId = req.usuario.id;
  const { prompt, conversationId: inputConversationId, modeloSeleccionado, temperatura, topP, idioma, archivosSeleccionados } = req.body;
  const archivosNuevosSubidos = req.files || [];

  const archivosSeleccionadosPreviamente = archivosSeleccionados ? JSON.parse(archivosSeleccionados) : [];
  let conversationId = inputConversationId;
  let isNewConversation = false;

  try {
    if (!prompt && archivosNuevosSubidos.length === 0 && archivosSeleccionadosPreviamente.length === 0) {
      return res.status(400).json({ error: "Se requiere un prompt o al menos un archivo." });
    }

    if (!conversationId) {
      const tituloConv = (prompt || "Conversación con archivos").trim().substring(0, 50);
      const { data, error } = await supabase.from("conversaciones").insert([{ usuario_id: usuarioId, titulo: tituloConv }]).select("id").single();
      if (error) throw new Error(`Error creando conversación: ${error.message}`);
      conversationId = data.id;
      isNewConversation = true;
    }

    if (prompt) {
        await supabase.from("mensajes").insert([{ conversacion_id: conversationId, rol: "user", texto: prompt }]);
    }
    
    if (archivosNuevosSubidos.length > 0) {
        const registrosArchivos = archivosNuevosSubidos.map((file) => ({
            usuario_id: usuarioId,
            nombre_archivo_unico: file.filename,
            nombre_archivo_original: file.originalname,
        }));
        const { error: errorInsertarArchivos } = await supabase.from("archivos_usuario").insert(registrosArchivos);
        if (errorInsertarArchivos) throw new Error(`No se pudieron guardar los metadatos de los archivos PDF: ${errorInsertarArchivos.message}`);
        console.log(`[GenerateText] ✅ ${archivosNuevosSubidos.length} nuevo(s) archivo(s) registrado(s) para usuario ${usuarioId}.`);
    }

    const todosLosNombresDeArchivoParaContexto = [ ...new Set([ ...archivosSeleccionadosPreviamente, ...archivosNuevosSubidos.map(f => f.filename) ]) ];
    
    const contextoPDF = todosLosNombresDeArchivoParaContexto.length > 0
        ? await generarContextoPDF(usuarioId, todosLosNombresDeArchivoParaContexto)
        : "";

    const { data: historial, error: errorHist } = await supabase.from("mensajes").select("rol, texto").eq("conversacion_id", conversationId).order("fecha_envio", { ascending: true });
    if (errorHist) throw new Error(`Error cargando historial: ${errorHist.message}`);

    const promptParaIA = prompt || (idioma === "es" ? "Resume o comenta sobre el contenido de los archivos adjuntos." : "Summarize or comment on the content of the attached files.");
    const respuestaIA = await generarRespuestaIA(promptParaIA, historial || [], contextoPDF, modeloSeleccionado, parseFloat(temperatura), parseFloat(topP), idioma);
    
    await supabase.from("mensajes").insert([{ conversacion_id: conversationId, rol: "model", texto: respuestaIA }]);
    
    res.status(200).json({ respuesta: respuestaIA, isNewConversation, conversationId });
  } catch (error) { next(error); }
});


// --- RUTA PARA GENERACIÓN DE IMÁGENES CON LOGS DE DEBUG ---
app.post("/api/generate-image", autenticarToken, async (req, res, next) => {
    const { prompt, modelId, idioma: langRequest } = req.body;
    const lang = ["es", "en"].includes(langRequest) ? langRequest : IDIOMA_POR_DEFECTO;

    // Inicio Bloque de Logs DEBUG
    console.log("--------------------------------------------------");
    console.log("[Img Gen DEBUG] INICIO PETICIÓN A HUGGING FACE");
    console.log(`[Img Gen DEBUG] Usuario ID: ${req.usuario.id}`);
    console.log(`[Img Gen DEBUG] Prompt recibido: ${prompt}`);
    console.log(`[Img Gen DEBUG] ModelId (desde frontend, si se envió): ${modelId}`);

    if (!prompt || prompt.trim().length === 0) {
        console.log("[Img Gen DEBUG] Prompt vacío o solo espacios.");
        return res.status(400).json({ error: lang === 'es' ? "El prompt para la imagen no puede estar vacío." : "Image prompt cannot be empty." });
    }
    if (!HUGGING_FACE_API_KEY) { // Esta verificación es importante
        console.error("[Img Gen DEBUG] CRITICAL: HUGGING_FACE_API_KEY no configurada en el servidor (verificado en ruta).");
        return res.status(500).json({ error: lang === 'es' ? "Servicio de generación de imágenes no disponible (error de configuración interna)." : "Image generation service unavailable (internal config error)." });
    }

    const HUGGING_FACE_MODEL_ID_ACTUAL = modelId || MODELO_IMAGEN_HF_POR_DEFECTO; // Usa la constante definida arriba
    const API_URL_ACTUAL = `https://api-inference.huggingface.co/models/${HUGGING_FACE_MODEL_ID_ACTUAL}`;
    
    console.log(`[Img Gen DEBUG] HUGGING_FACE_MODEL_ID_ACTUAL a usar: ${HUGGING_FACE_MODEL_ID_ACTUAL}`);
    console.log(`[Img Gen DEBUG] API_URL_ACTUAL a usar: ${API_URL_ACTUAL}`);
    // Ya no necesitamos verificar si HUGGING_FACE_API_KEY existe aquí porque lo hicimos arriba
    console.log(`[Img Gen DEBUG] HF Key (primeros 5): ${HUGGING_FACE_API_KEY.substring(0, 5)}`);
    console.log(`[Img Gen DEBUG] HF Key (últimos 5): ${HUGGING_FACE_API_KEY.substring(HUGGING_FACE_API_KEY.length - 5)}`);
    console.log(`[Img Gen DEBUG] Cuerpo de la solicitud a HF (inputs): ${JSON.stringify({ inputs: prompt })}`);
    
    const headersParaHF = {
        "Authorization": `Bearer ${HUGGING_FACE_API_KEY}`,
        "Content-Type": "application/json",
        "Accept": "image/jpeg" 
    };
    const safeHeadersForLogging = {...headersParaHF}; 
    if (HUGGING_FACE_API_KEY) { 
        safeHeadersForLogging.Authorization = `Bearer hf_...${HUGGING_FACE_API_KEY.substring(HUGGING_FACE_API_KEY.length - 4)}`;
    }
    console.log(`[Img Gen DEBUG] Cabeceras para HF (token ofuscado): ${JSON.stringify(safeHeadersForLogging)}`);
    console.log("--------------------------------------------------"); 
    // Fin Bloque de Logs DEBUG

    try {
        const hfResponse = await axios.post(
            API_URL_ACTUAL,
            { inputs: prompt },
            {
                headers: headersParaHF,
                responseType: 'arraybuffer',
                timeout: 60000 
            }
        );
        console.log(`[Img Gen DEBUG] Respuesta de HF Status: ${hfResponse.status}, Content-Type: ${hfResponse.headers['content-type']}`);

        if (hfResponse.status === 200 && hfResponse.data && hfResponse.data.byteLength > 0) {
            const contentType = hfResponse.headers['content-type'] || 'image/jpeg'; 
            const imageBase64 = Buffer.from(hfResponse.data, 'binary').toString('base64');
            const imageSrc = `data:${contentType};base64,${imageBase64}`;
            console.log(`[Img Gen] ✅ Imagen generada para user ${req.usuario.id}. Tamaño: ${hfResponse.data.byteLength} bytes.`);
            res.json({ imageUrl: imageSrc, originalPrompt: prompt });
        } else {
            let errorMessage = lang === 'es' ? `Respuesta inesperada del servicio de imágenes (status ${hfResponse.status}).` : `Unexpected response from image service (status ${hfResponse.status}).`;
            let errorBodyPreview = "Sin datos en la respuesta o datos vacíos.";
            if (hfResponse.data) {
                 errorBodyPreview = Buffer.from(hfResponse.data,'binary').toString().substring(0,100);
                 try {
                    const errorData = JSON.parse(errorBodyPreview); 
                    if (errorData.error) errorMessage = errorData.error;
                 } catch(e){ /* Ignorar si no es JSON */ }
            }
            console.error(`[Img Gen] ❌ Respuesta inesperada de HF (status ${hfResponse.status}) para user ${req.usuario.id}: ${errorMessage}. Cuerpo: ${errorBodyPreview}`);
            const serviceError = new Error(errorMessage);
            serviceError.status = hfResponse.status || 500;
            next(serviceError);
        }
    } catch (error) {
      console.log("[Img Gen DEBUG] ERROR EN BLOQUE CATCH DE AXIOS para HF");
      let statusCode = 500;
      let message = lang === 'es' ? "Error generando imagen." : "Error generating image.";

      if (error.code === 'ECONNABORTED' || error.message.toLowerCase().includes('timeout')) {
          statusCode = 504; 
          message = lang === 'es' ? `El servicio de generación de imágenes tardó demasiado. Intenta con un prompt más simple o más tarde.` : `Image generation service timed out. Try a simpler prompt or try again later.`;
          console.error(`[Img Gen] ❌ Timeout llamando a HF API para user ${req.usuario.id}: ${error.message}`);
      } else if (error.response) { 
          statusCode = error.response.status;
          const responseData = error.response.data; 
          let errorTextFromHF = `Error del servidor de imágenes (${statusCode}).`;
          if(responseData){
              try {
                  errorTextFromHF = Buffer.from(responseData).toString(); 
                  const errorData = JSON.parse(errorTextFromHF); 
                  message = errorData.error || (lang === 'es' ? `Error API Hugging Face (${statusCode})` : `Hugging Face API Error (${statusCode})`);
                  if (errorData.estimated_time) {
                      message = lang === 'es' ? `El modelo de imagen (${HUGGING_FACE_MODEL_ID_ACTUAL}) está cargando (aprox. ${errorData.estimated_time.toFixed(0)}s). Intenta de nuevo.` : `Image model (${HUGGING_FACE_MODEL_ID_ACTUAL}) is loading (approx. ${errorData.estimated_time.toFixed(0)}s). Please try again.`;
                      statusCode = 503;
                  }
              } catch (parseError) { 
                   message = lang === 'es' ? `Error (${statusCode}) del servicio de imágenes. Respuesta no reconocible.` : `Image service error (${statusCode}). Unrecognized response.`;
                   console.error("[Img Gen] Cuerpo del error (no JSON o buffer inválido):", errorTextFromHF ? errorTextFromHF.substring(0,200) : "Sin cuerpo de respuesta");
              }
          } else {
              message = error.message; // Usar el mensaje del error de axios si no hay response.data
          }
          console.error(`[Img Gen] ❌ Catch con error.response - User ${req.usuario.id} - Status: ${statusCode} - Mensaje devuelto: ${message}`);
      } else if (error.request) { 
          message = lang === 'es' ? "No se pudo conectar con el servicio de generación de imágenes (sin respuesta)." : "Could not connect to the image generation service (no response).";
          console.error(`[Img Gen] ❌ Sin respuesta de HF API para user ${req.usuario.id}:`, error.message);
      } else { 
          message = lang === 'es' ? "Ocurrió un error inesperado al generar la imagen." : "An unexpected error occurred while generating the image.";
          console.error(`[Img Gen] ❌ Error desconocido para user ${req.usuario.id}:`, error.message, error.stack);
      }
      
      const errToPass = new Error(message); 
      errToPass.status = statusCode;
      next(errToPass); 
    }
});

// Manejador de Errores Global
app.use((err, req, res, next) => {
  console.error("‼️ Global Error Handler:", err.message);
  if (NODE_ENV !== "production" && err.stack) console.error("Stack:", err.stack);

  let statusCode = err.status || (err.response && err.response.status) || 500;
  let clientMessage = err.message || "Error interno del servidor.";
  const errorLang = req?.body?.idioma || req?.query?.idioma || IDIOMA_POR_DEFECTO;

  if (err.message.includes("Token no proporcionado") || err.message.includes("Token expirado") || err.message.includes("Token inválido") || err.message.includes("Acceso no autorizado")) {
      statusCode = 401; 
      clientMessage = errorLang === 'es' ? "Tu sesión ha expirado o no es válida. Por favor, inicia sesión de nuevo." : "Your session has expired or is invalid. Please log in again.";
  } else if (err instanceof multer.MulterError) {
    statusCode = 400;
    if (err.code === "LIMIT_FILE_SIZE") {
      statusCode = 413;
      clientMessage = errorLang === "en" ? `File too large (Max: ${TAMANO_MAX_ARCHIVO_MB} MB).` : `Archivo muy grande (Máx: ${TAMANO_MAX_ARCHIVO_MB} MB).`;
    } else if (err.message === "Solo se permiten archivos PDF." || err.code === "LIMIT_UNEXPECTED_FILE") { 
        clientMessage = errorLang === "en" ? "Only PDF files are allowed." : "Solo se permiten archivos PDF.";
    } else {
      clientMessage = errorLang === "en" ? `File upload error: ${err.field ? err.field+': ' : ''}${err.message}.` : `Error subida archivo: ${err.field ? err.field+': ' : ''}${err.message}.`;
    }
  } else if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    statusCode = 400;
    clientMessage = errorLang === "en" ? "Malformed request (Invalid JSON)." : "Petición mal formada (JSON inválido).";
  } else if (err.message.toLowerCase().includes("servicio") && (err.message.toLowerCase().includes("ia") || err.message.toLowerCase().includes("bd") || err.message.toLowerCase().includes("no disponible"))) {
    statusCode = 503;
    clientMessage = errorLang === "en" ? "Service temporarily unavailable. Please try again later." : "Servicio no disponible temporalmente. Por favor, inténtalo más tarde.";
  } else if (err.message.toLowerCase().includes("origen no permitido por") && err.message.toLowerCase().includes("cors")) { // Específico para el error CORS
    statusCode = 403; // Forbidden es más apropiado para CORS que 500
    clientMessage = errorLang === "en" ? "Access to the API from your origin has been blocked by CORS policy." : "El acceso a la API desde tu origen ha sido bloqueado por la política CORS.";
  } else if (statusCode >= 500 || !err.status) {
    clientMessage = errorLang === "en" ? "An internal server error occurred. Please try again later." : "Ocurrió un error interno en el servidor. Por favor, inténtalo más tarde.";
  }
  
  if (res.headersSent) {
    console.error("‼️ Error Handler: Headers already sent.");
    return next(err); 
  }
  res.status(statusCode).json({ error: clientMessage });
});

const PUERTO_ACTUAL = PUERTO || 3001;
app.listen(PUERTO_ACTUAL, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PUERTO_ACTUAL} en modo ${NODE_ENV}`);
});

// --- END OF FILE index.js ---