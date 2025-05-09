// --- START OF FILE index.js ---

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
import axios from 'axios'; // Asegúrate de que esta línea esté

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const directorioSubidas = path.join(__dirname, "uploads");

dotenv.config();

const {
  PORT: PUERTO = 3001,
  DB_HOST,
  DB_USER,
  DB_PASSWORD,
  DB_NAME,
  API_KEY, // Para Google Gemini
  JWT_SECRET,
  NODE_ENV = "development",
  SUPABASE_URL,
  SUPABASE_KEY,
  HUGGING_FACE_API_KEY, // Para Hugging Face
} = process.env;

const isDev = NODE_ENV !== "production";

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: !isDev,
  sameSite: isDev ? "lax" : "none", // 'lax' para dev, 'none' para prod (cross-site)
  maxAge: 3600 * 1000, // 1 hora
  path: "/",
};

const TAMANO_MAX_ARCHIVO_MB = 20;
const MAX_CARACTERES_POR_PDF = 10000; // Considera si es necesario o si Gemini lo maneja
const MAX_LONGITUD_CONTEXTO = 30000; // Límite para el contexto de Gemini
const MODELOS_PERMITIDOS = [
  "gemini-1.5-flash",
  "gemini-1.5-pro",
  // "gemini-2.0-flash", // Revisa disponibilidad
  // "gemini-2.5-pro-exp-03-25", // Revisa disponibilidad
];
const MODELO_POR_DEFECTO = "gemini-1.5-flash";
const TEMP_POR_DEFECTO = 0.7;
const TOPP_POR_DEFECTO = 0.9;
const IDIOMA_POR_DEFECTO = "es";
const JWT_OPTIONS = { expiresIn: "1h" };

// Verificaciones de variables de entorno
console.log(
  "[Startup] JWT_SECRET cargado:",
  JWT_SECRET
    ? `${JWT_SECRET.substring(0, 3)}... (longitud: ${JWT_SECRET.length})`
    : "¡NO CARGADO!"
);
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.warn("⚠️ [Startup] ADVERTENCIA: JWT_SECRET no definido o inseguro!");
}
if (!API_KEY)
  console.warn("⚠️ [Startup] ADVERTENCIA: API_KEY (Google) no configurada.");
if (!SUPABASE_URL)
  console.warn("⚠️ [Startup] ADVERTENCIA: SUPABASE_URL no configurada.");
if (!SUPABASE_KEY)
  console.warn("⚠️ [Startup] ADVERTENCIA: SUPABASE_KEY no configurada.");
if (!HUGGING_FACE_API_KEY)
  console.warn("⚠️ [Startup] ADVERTENCIA: HUGGING_FACE_API_KEY no configurada.");


const app = express();

let clienteIA; // Google Gemini AI Client
if (API_KEY) {
  try {
    clienteIA = new GoogleGenerativeAI(API_KEY);
    console.log("✅ Instancia de GoogleGenerativeAI creada.");
  } catch (error) {
    console.error("🚨 FATAL: Error al inicializar GoogleGenerativeAI:", error.message);
    clienteIA = null;
  }
} else {
  console.warn("⚠️ ADVERTENCIA: API_KEY de Google no proporcionada. Funcionalidad de texto IA deshabilitada.");
  clienteIA = null;
}


let supabase; // Supabase Client
if (SUPABASE_URL && SUPABASE_KEY) {
  try {
    supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
    console.log("✅ Cliente Supabase inicializado.");
  } catch (error) {
    console.error("🚨 FATAL: Error al inicializar Supabase:", error.message);
    supabase = null;
  }
} else {
   console.warn("⚠️ ADVERTENCIA: SUPABASE_URL o SUPABASE_KEY no proporcionadas. Funcionalidad de BD deshabilitada.");
   supabase = null;
}


// Configuración de Middlewares
app.use(
  cors({
    origin: (origin, callback) => {
      // Permite solicitudes sin 'origin' (ej. Postman, curl) o desde orígenes específicos
      // Para producción, considera una lista blanca de orígenes.
      // Ejemplo: const allowedOrigins = ['https://tu-frontend.onrender.com', 'http://localhost:5173'];
      // if (!origin || allowedOrigins.includes(origin)) {
      if (origin) { // Para desarrollo, esto es más permisivo
        console.log("🌍 Solicitado desde:", origin);
        callback(null, origin);
      } else {
        callback(null, true); // Aceptar sin origen
      }
    },
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json());

// Middleware de Autenticación
const autenticarToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: "Token no proporcionado" });
  }
  jwt.verify(token, JWT_SECRET, (err, usuarioToken) => {
    if (err) {
      const isExpired = err.name === "TokenExpiredError";
      if (isExpired) res.clearCookie("token", COOKIE_OPTIONS);
      return res.status(isExpired ? 401 : 403).json({ error: isExpired ? "Token expirado" : "Token inválido" });
    }
    req.usuario = usuarioToken;
    next();
  });
};

// Configuración de Multer para subida de archivos
if (!existsSync(directorioSubidas)) {
  mkdirSync(directorioSubidas, { recursive: true });
  console.log(`📂 Directorio de subidas creado: ${directorioSubidas}`);
}

const almacenamiento = multer.diskStorage({
  destination: directorioSubidas,
  filename: (req, file, cb) => {
    const sufijoUnico = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const nombreOriginalLimpio = file.originalname.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9.\-_]/g, "_").replace(/_{2,}/g, "_");
    const extension = path.extname(nombreOriginalLimpio) || ".pdf"; // Asegurar extensión
    const nombreBase = path.basename(nombreOriginalLimpio, extension);
    cb(null, `${sufijoUnico}-${nombreBase}${extension}`);
  },
});

const subir = multer({
  storage: almacenamiento,
  limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "application/pdf") {
      cb(null, true);
    } else {
      cb(new Error("Solo se permiten archivos PDF."), false);
    }
  },
}).array("archivosPdf"); // 'archivosPdf' debe coincidir con el nombre del campo en FormData

// Funciones Auxiliares (extracción de PDF, generación de contexto, IA)
async function extraerTextoDePDF(rutaArchivo) {
  // ... (tu código existente, asegúrate que maneja errores de archivo no encontrado) ...
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
      return { texto: null, error: `Archivo no encontrado: ${nombreArchivoLog}` };
    }
    console.error(`❌ [PDF Extract] Error procesando ${nombreArchivoLog}:`, error.message);
    return { texto: null, error: `Error al parsear ${nombreArchivoLog}: ${error.message || "desconocido"}`};
  }
}

async function generarContextoPDF(idUsuario, nombresArchivosUnicos) {
  if (!supabase) return "[Error: Servicio de base de datos no disponible para generar contexto PDF]";
  if (!nombresArchivosUnicos || nombresArchivosUnicos.length === 0) return "";
  // ... (tu código existente, asegúrate que maneja errores de Supabase y fs) ...
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
    const archivosMap = new Map(archivosDB.map((f) => [f.nombre_archivo_unico, f.nombre_archivo_original]));
    let textoCompleto = "";
    for (const nombreArchivoUnico of nombresArchivosUnicos) {
      const nombreOriginal = archivosMap.get(nombreArchivoUnico) || nombreArchivoUnico; // Fallback
      const ruta = path.join(directorioSubidas, nombreArchivoUnico);
      try {
        const buffer = await fs.readFile(ruta);
        const datos = await pdfParse(buffer);
        if(datos && datos.text) {
            textoCompleto += `\n\n[${nombreOriginal}]\n${datos.text.trim()}`;
        } else {
            console.warn(`[Context PDF] ⚠️ No se pudo extraer texto de ${nombreArchivoUnico}`);
        }
      } catch (err) {
        console.warn(`[Context PDF] ⚠️ No se pudo leer/parsear ${nombreArchivoUnico}:`, err.message);
      }
    }
    return textoCompleto.trim();
  } catch (err) {
    console.error("[Context PDF] ❌ Excepción general:", err);
    return "[Error al generar contexto desde archivos PDF]";
  }
}

async function generarRespuestaIA(prompt, historialDB, textoPDF, modeloReq, temp, topP, lang) {
  if (!clienteIA) throw new Error("Servicio IA (Google) no disponible.");
  // ... (tu código existente, asegúrate que maneja errores de la API de Gemini) ...
  const nombreModelo = MODELOS_PERMITIDOS.includes(modeloReq) ? modeloReq : MODELO_POR_DEFECTO;
  if (modeloReq && nombreModelo !== modeloReq) console.warn(`[Gen IA] ⚠️ Modelo no válido ('${modeloReq}'), usando por defecto: ${MODELO_POR_DEFECTO}`);
  const configGeneracion = {
    temperature: !isNaN(temp) ? Math.max(0, Math.min(1, temp)) : TEMP_POR_DEFECTO,
    topP: !isNaN(topP) ? Math.max(0, Math.min(1, topP)) : TOPP_POR_DEFECTO,
  };
  const idioma = ["es", "en"].includes(lang) ? lang : IDIOMA_POR_DEFECTO;
  const langStrings = idioma === "en" ? { /* ... */ } : { /* ... */ }; // Define tus strings
   // (Simplificado, asumiendo que ya tienes esto bien)
   langStrings.systemBase = "Eres un asistente útil.";
   langStrings.systemPdf = "Responde basado en: {CONTEXT}";
   langStrings.label = "Pregunta";
   langStrings.error = "Error IA";


  let instruccionSistema;
  if (textoPDF) {
    const contextoTruncado = textoPDF.length > MAX_LONGITUD_CONTEXTO ? textoPDF.substring(0, MAX_LONGITUD_CONTEXTO) + "... (contexto truncado)" : textoPDF;
    if (textoPDF.length > MAX_LONGITUD_CONTEXTO) console.warn(`[Gen IA] ✂️ Contexto PDF truncado.`);
    instruccionSistema = langStrings.systemPdf.replace("{CONTEXT}", contextoTruncado);
  } else {
    instruccionSistema = langStrings.systemBase;
  }
  const promptCompletoUsuario = `${instruccionSistema}\n${langStrings.label}: ${prompt}`;
  const contenidoGemini = [
    ...historialDB.filter((m) => m.texto?.trim()).map((m) => ({ role: m.rol === "user" ? "user" : "model", parts: [{ text: m.texto }] })),
    { role: "user", parts: [{ text: promptCompletoUsuario }] },
  ];

  console.log(`[Gen IA] ➡️ Enviando ${contenidoGemini.length} partes a Gemini (${nombreModelo}). Prompt: ${prompt.substring(0,50)}...`);
  try {
    const modeloGemini = clienteIA.getGenerativeModel({ model: nombreModelo });
    const resultado = await modeloGemini.generateContent({ contents: contenidoGemini, generationConfig: configGeneracion });
    const response = resultado?.response;
    const textoRespuestaIA = response?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (textoRespuestaIA) {
      console.log("[Gen IA] ✅ Respuesta recibida.");
      return textoRespuestaIA.trim();
    }
    const blockReason = response?.promptFeedback?.blockReason;
    const finishReason = response?.candidates?.[0]?.finishReason;
    console.warn(`[Gen IA] ⚠️ Respuesta vacía/bloqueada. Block: ${blockReason}, Finish: ${finishReason}`);
    let errorMsg = langStrings.error;
    if (blockReason) errorMsg += `. Razón bloqueo: ${blockReason}`;
    else if (finishReason && finishReason !== "STOP") errorMsg += `. Razón finalización: ${finishReason}`;
    else errorMsg += ". (Respuesta inválida)";
    return errorMsg;
  } catch (error) {
    console.error(`[Gen IA] ❌ Error API (${nombreModelo}):`, error.message);
    const detalleError = error.details || error.message || "Error no especificado";
    return `${langStrings.error}. (Detalle: ${detalleError})`;
  }
}

// Rutas API
app.post("/api/register", async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
  // ... (tu código existente) ...
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });
  try {
    const contrasenaHasheada = await bcrypt.hash(password, 10);
    const { data, error } = await supabase.from("usuarios").insert([{ nombre_usuario: username, contrasena_hash: contrasenaHasheada }]).select("id").single();
    if (error) {
      if (error.code === "23505") return res.status(409).json({ error: "Nombre de usuario ya existe." });
      throw error; // Dejar que el manejador global lo capture
    }
    res.status(201).json({ message: "Registro exitoso.", userId: data.id });
  } catch (error) { next(error); }
});

app.post("/api/login", async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
  // ... (tu código existente) ...
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });
  try {
    const { data: usuario, error } = await supabase.from("usuarios").select("id, nombre_usuario, contrasena_hash").eq("nombre_usuario", username).limit(1).single();
    if (error || !usuario) return res.status(401).json({ error: "Credenciales inválidas." });
    const passwordCorrecta = await bcrypt.compare(password, usuario.contrasena_hash);
    if (!passwordCorrecta) return res.status(401).json({ error: "Credenciales inválidas." });
    const payload = { id: usuario.id, username: usuario.nombre_usuario };
    const token = jwt.sign(payload, JWT_SECRET, JWT_OPTIONS);
    res.cookie("token", token, COOKIE_OPTIONS);
    res.json({ message: "Login exitoso.", user: payload });
  } catch (error) { next(error); }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token", COOKIE_OPTIONS);
  res.status(200).json({ message: "Logout exitoso." });
});

app.get("/api/verify-auth", autenticarToken, (req, res) => {
  res.json({ user: req.usuario });
});

// Rutas para archivos
app.post("/api/files", autenticarToken, subir, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
  try {
    const usuarioId = req.usuario.id;
    const archivos = req.files;
    if (!archivos || archivos.length === 0) return res.status(400).json({ error: "No se subieron archivos." });
    const registros = archivos.map((file) => ({ usuario_id: usuarioId, nombre_archivo_unico: file.filename, nombre_archivo_original: file.originalname }));
    const { error } = await supabase.from("archivos_usuario").insert(registros);
    if (error) throw error;
    res.status(200).json({ mensaje: `${archivos.length} archivo(s) subido(s) correctamente.` });
  } catch (error) { next(error); }
});

app.get("/api/files", autenticarToken, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
  // ... (tu código existente) ...
  try {
    const { data: archivos, error } = await supabase.from("archivos_usuario").select("nombre_archivo_unico, nombre_archivo_original").eq("usuario_id", req.usuario.id).order("fecha_subida", { ascending: false });
    if (error) throw error;
    res.json(archivos.map((a) => ({ name: a.nombre_archivo_unico, originalName: a.nombre_archivo_original })));
  } catch (error) { next(error); }
});

app.delete("/api/files/:nombreArchivoUnico", autenticarToken, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
  // ... (tu código existente, con manejo de errores mejorado) ...
  const idUsuario = req.usuario.id;
  const { nombreArchivoUnico } = req.params;
  try {
    const { data: archivoDB, error: findError } = await supabase.from("archivos_usuario").select("id").eq("usuario_id", idUsuario).eq("nombre_archivo_unico", nombreArchivoUnico).single();
    if (findError || !archivoDB) return res.status(404).json({ error: "Archivo no encontrado o no autorizado." });
    const { error: deleteDBError } = await supabase.from("archivos_usuario").delete().eq("id", archivoDB.id);
    if (deleteDBError) throw deleteDBError;
    const rutaArchivo = path.join(directorioSubidas, nombreArchivoUnico);
    try { await fs.unlink(rutaArchivo); } catch (fsError) { if (fsError.code !== "ENOENT") console.warn(`[File Delete] Error eliminando archivo del disco (puede que ya no exista): ${fsError.message}`); }
    res.json({ message: "Archivo eliminado correctamente." });
  } catch (err) { next(err); }
});

// Rutas para conversaciones
app.get("/api/conversations", autenticarToken, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
  // ... (tu código existente) ...
  try {
    const { data: conversaciones, error } = await supabase.from("conversaciones").select("id, titulo").eq("usuario_id", req.usuario.id).order("fecha_actualizacion", { ascending: false });
    if (error) throw error;
    res.json(conversaciones);
  } catch (error) { next(error); }
});

app.get("/api/conversations/:id/messages", autenticarToken, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
  // ... (tu código existente) ...
  const { id } = req.params;
  try {
    // Primero, verificar que la conversación pertenece al usuario
    const { data: conv, error: convError } = await supabase.from("conversaciones").select("id").eq("id", id).eq("usuario_id", req.usuario.id).single();
    if (convError || !conv) return res.status(404).json({ error: "Conversación no encontrada o no autorizada." });

    const { data: mensajes, error } = await supabase.from("mensajes").select("rol, texto, fecha_envio").eq("conversacion_id", id).order("fecha_envio", { ascending: true });
    if (error) throw error;
    res.json(mensajes);
  } catch (error) { next(error); }
});

app.delete("/api/conversations/:idConv", autenticarToken, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
  // ... (tu código existente) ...
  const { idConv } = req.params;
  const idUsuario = req.usuario.id;
  try {
    const { error } = await supabase.from("conversaciones").delete().eq("id", idConv).eq("usuario_id", idUsuario);
    if (error) throw error;
    res.json({ message: "Conversación eliminada correctamente." });
  } catch (err) { next(err); }
});

app.put("/api/conversations/:id/title", autenticarToken, async (req, res, next) => {
  if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
  // ... (tu código existente) ...
  const { id } = req.params;
  const { nuevoTitulo } = req.body;
  const usuarioId = req.usuario.id;
  if (!nuevoTitulo || typeof nuevoTitulo !== "string" || nuevoTitulo.trim().length === 0) return res.status(400).json({ error: "Título no válido." });
  try {
    const { error } = await supabase.from("conversaciones").update({ titulo: nuevoTitulo.trim() }).eq("id", id).eq("usuario_id", usuarioId);
    if (error) throw error;
    res.status(200).json({ message: "Título actualizado correctamente." });
  } catch (err) { next(err); }
});

// Ruta principal para generar texto
app.post("/api/generateText", autenticarToken, subir, async (req, res, next) => {
  if (!supabase || !clienteIA) return res.status(503).json({ error: "Servicio IA o BD no disponible." });
  const usuarioId = req.usuario.id;
  const { prompt, conversationId: inputConversationId, modeloSeleccionado, temperatura, topP, idioma, archivosSeleccionados } = req.body;
  let { archivosPdf } = req; // archivos subidos por multer

  const archivosSeleccionadosArray = archivosSeleccionados ? JSON.parse(archivosSeleccionados) : [];
  archivosPdf = archivosPdf || []; // Asegurar que sea un array

  let conversationId = inputConversationId;
  let isNewConversation = false;

  try {
    if (!prompt && archivosPdf.length === 0 && archivosSeleccionadosArray.length === 0) {
        return res.status(400).json({ error: "Se requiere un prompt o archivos." });
    }

    if (!conversationId) {
      const tituloConv = (prompt || "Conversación con PDF").trim().split(/\s+/).slice(0, 5).join(" ");
      const { data, error } = await supabase.from("conversaciones").insert([{ usuario_id: usuarioId, titulo: tituloConv }]).select("id").single();
      if (error) throw new Error("Error creando conversación: " + error.message);
      conversationId = data.id;
      isNewConversation = true;
    }

    if (prompt) {
        await supabase.from("mensajes").insert([{ conversacion_id: conversationId, rol: "user", texto: prompt }]);
    }

    // No es necesario guardar archivos PDF aquí de nuevo si `subir` es un middleware separado para /api/files
    // Si `subir` se usa aquí, entonces sí, pero parece que ya tienes /api/files para eso.
    // Para simplificar, asumiremos que los archivos nuevos ya están en `req.files` gracias al middleware `subir`
    // y que ya han sido registrados en la BD por una llamada previa a /api/files o se registran aquí
    // (tu código original los registraba en generateText, lo cual es válido)

    // Si req.files existe (subida directa a generateText), los guardamos
    if (req.files && req.files.length > 0) {
        const registrosArchivos = req.files.map((file) => ({
            usuario_id: usuarioId,
            nombre_archivo_unico: file.filename,
            nombre_archivo_original: file.originalname,
        }));
        const { error: errorInsertarArchivos } = await supabase.from("archivos_usuario").insert(registrosArchivos);
        if (errorInsertarArchivos) throw new Error("No se pudieron guardar los archivos PDF subidos: " + errorInsertarArchivos.message);
        console.log(`[Archivos en generateText] ✅ ${req.files.length} archivo(s) guardado(s) en la base de datos.`);
    }


    const nombresArchivosUnicosParaContexto = [
      ...new Set([ // Evitar duplicados
        ...archivosSeleccionadosArray,
        ...(req.files ? req.files.map(f => f.filename) : [])
      ])
    ];

    const contextoPDF = nombresArchivosUnicosParaContexto.length > 0
        ? await generarContextoPDF(usuarioId, nombresArchivosUnicosParaContexto)
        : "";

    const { data: historial, error: errorHist } = await supabase.from("mensajes").select("rol, texto").eq("conversacion_id", conversationId).order("fecha_envio", { ascending: true });
    if (errorHist) throw new Error("Error cargando historial: " + errorHist.message);

    const promptParaIA = prompt || (idioma === "es" ? "Resume el contenido de los PDF." : "Summarize the content of the PDFs.");

    const respuestaIA = await generarRespuestaIA(promptParaIA, historial || [], contextoPDF, modeloSeleccionado, parseFloat(temperatura), parseFloat(topP), idioma);
    await supabase.from("mensajes").insert([{ conversacion_id: conversationId, rol: "model", texto: respuestaIA }]);
    res.status(200).json({ respuesta: respuestaIA, isNewConversation, conversationId });
  } catch (error) {
    next(error); // Dejar que el manejador global lo capture
  }
});

// --- RUTA PARA GENERACIÓN DE IMÁGENES ---
app.post("/api/generate-image", autenticarToken, async (req, res, next) => {
    const { prompt, modelId, idioma: langRequest } = req.body;
    const lang = ["es", "en"].includes(langRequest) ? langRequest : IDIOMA_POR_DEFECTO;

    if (!prompt) {
        return res.status(400).json({ error: lang === 'es' ? "Prompt es requerido." : "Prompt is required." });
    }
    if (!HUGGING_FACE_API_KEY) {
        console.error("[Img Gen] ❌ HUGGING_FACE_API_KEY no está configurada en el servidor.");
        return res.status(500).json({ error: lang === 'es' ? "Servicio de generación de imágenes no configurado." : "Image generation service not configured." });
    }

    const HUGGING_FACE_MODEL_ID = modelId || "PrunaAI/runwayml-stable-diffusion-v1-5-turbo-tiny-green-smashed"; // Usando el modelo que mencionaste
    const API_URL = `https://api-inference.huggingface.co/models/${HUGGING_FACE_MODEL_ID}`;

    console.log(`[Img Gen] User ${req.usuario.id} solicitando imagen para prompt: "${prompt.substring(0,50)}..." usando modelo: ${HUGGING_FACE_MODEL_ID}`);

    try {
        const hfResponse = await axios.post(
            API_URL,
            { inputs: prompt },
            {
                headers: {
                    "Authorization": `Bearer ${HUGGING_FACE_API_KEY}`,
                    "Content-Type": "application/json",
                    "Accept": "image/png" // Solicitar PNG, ajusta si prefieres JPEG
                },
                responseType: 'arraybuffer'
            }
        );

        if (hfResponse.status === 200 && hfResponse.data) {
            const contentType = hfResponse.headers['content-type'] || 'image/png'; // Fallback a png
            const imageBase64 = Buffer.from(hfResponse.data, 'binary').toString('base64');
            const imageSrc = `data:${contentType};base64,${imageBase64}`;
            console.log(`[Img Gen] ✅ Imagen generada para: "${prompt.substring(0,50)}..."`);
            res.json({ imageUrl: imageSrc, originalPrompt: prompt });
        } else {
            let errorMessage = lang === 'es' ? `Error de Hugging Face: ${hfResponse.status}` : `Hugging Face Error: ${hfResponse.status}`;
             try {
                const errorText = Buffer.from(hfResponse.data, 'binary').toString(); // Intentar convertir aunque sea un buffer
                const errorData = JSON.parse(errorText);
                if (errorData.error) errorMessage += ` - ${errorData.error}`;
                if (errorData.estimated_time) errorMessage += lang === 'es' ? ` - Modelo cargando, tiempo estimado: ${errorData.estimated_time}s` : ` - Model loading, estimated time: ${errorData.estimated_time}s`;
             } catch (e) { /* No era JSON o no era texto útil */ }
            console.error(`[Img Gen] ❌ Error API Hugging Face (status ${hfResponse.status}):`, errorMessage);
            res.status(hfResponse.status || 500).json({ error: errorMessage });
        }
    } catch (error) {
        let statusCode = 500;
        let message = lang === 'es' ? "Error interno del servidor generando imagen." : "Internal server error generating image.";

        if (error.response) {
            statusCode = error.response.status;
            try {
                const errorText = Buffer.from(error.response.data).toString();
                const errorData = JSON.parse(errorText);
                message = errorData.error || (lang === 'es' ? `Error API Hugging Face (${statusCode})` : `Hugging Face API Error (${statusCode})`);
                if (errorData.estimated_time) {
                    message = lang === 'es' ?
                        `El modelo de imagen (${HUGGING_FACE_MODEL_ID}) está cargando. Intenta de nuevo en ${errorData.estimated_time.toFixed(0)} segundos.` :
                        `Image model (${HUGGING_FACE_MODEL_ID}) is loading. Try again in ${errorData.estimated_time.toFixed(0)} seconds.`;
                    statusCode = 503;
                }
            } catch (parseError) {
                 message = lang === 'es' ? `Error API Hugging Face (${statusCode}). Respuesta no es JSON.` : `Hugging Face API Error (${statusCode}). Response not JSON.`;
                 console.error("[Img Gen] Cuerpo del error (no JSON):", Buffer.from(error.response.data).toString());
            }
        } else if (error.request) {
            message = lang === 'es' ? "No se recibió respuesta del servicio de generación de imágenes." : "No response from image generation service.";
        } else {
            message = lang === 'es' ? "Error desconocido al generar la imagen." : "Unknown error generating image.";
        }
        console.error(`[Img Gen] ❌ Catch - User ${req.usuario.id} - Error:`, message, error.message);
        // Pasar al manejador de errores global
        const errToPass = new Error(message);
        errToPass.status = statusCode;
        next(errToPass);
    }
});

// Manejador de Errores Global (Debe ser el último middleware)
app.use((err, req, res, next) => {
  console.error("‼️ Global Error Handler:", err.message);
  if (NODE_ENV !== "production" && err.stack) console.error("Stack:", err.stack);

  let statusCode = err.status || (err.response && err.response.status) || 500;
  let clientMessage = err.message || "Error interno del servidor.";
  const errorLang = req?.body?.idioma || req?.query?.idioma || IDIOMA_POR_DEFECTO;

  if (err.message.includes("Token no proporcionado") || err.message.includes("Token expirado") || err.message.includes("Token inválido")) {
      statusCode = 401; // O 403 si es inválido pero no expirado
  } else if (err instanceof multer.MulterError) {
    statusCode = 400;
    if (err.code === "LIMIT_FILE_SIZE") {
      statusCode = 413; // Payload Too Large
      clientMessage = errorLang === "en" ? `File too large (Max: ${TAMANO_MAX_ARCHIVO_MB} MB).` : `Archivo muy grande (Máx: ${TAMANO_MAX_ARCHIVO_MB} MB).`;
    } else {
      clientMessage = errorLang === "en" ? `File upload error: ${err.message}.` : `Error subida archivo: ${err.message}.`;
    }
  } else if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    statusCode = 400; // Bad Request
    clientMessage = errorLang === "en" ? "Malformed request (Invalid JSON)." : "Petición mal formada (JSON inválido).";
  } else if (err.message.includes("Servicio IA") || err.message.includes("Servicio de base de datos")) {
    statusCode = 503; // Service Unavailable
    clientMessage = errorLang === "en" ? "Service temporarily unavailable. Please try again later." : "Servicio no disponible temporalmente. Por favor, inténtalo más tarde.";
  } else if (err.message === "Solo se permiten archivos PDF.") {
    statusCode = 400;
    clientMessage = err.message;
  } else if (statusCode >= 500) { // Errores del servidor genéricos
    clientMessage = errorLang === "en" ? "An internal server error occurred." : "Ocurrió un error interno en el servidor.";
  }
  // Si el error ya tiene un mensaje orientado al cliente y un status < 500, usarlo.
  // Pero si es un error 500, ocultamos los detalles por seguridad.

  if (res.headersSent) {
    console.error("‼️ Error Handler: Headers already sent, cannot send error response.");
    return next(err); // Dejar que Express lo maneje como pueda
  }
  res.status(statusCode).json({ error: clientMessage });
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT} en modo ${NODE_ENV}`);
});

// --- END OF FILE index.js ---