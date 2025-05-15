// --- START OF FILE index.js ---

// --- Imports ---
import { GoogleGenerativeAI } from "@google/generative-ai";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import pdfParse from "pdf-parse/lib/pdf-parse.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { createClient } from "@supabase/supabase-js";
import FormData from "form-data";
import axios from 'axios';

// --- Carga de Variables de Entorno ---
dotenv.config();
const {
  PORT: PUERTO = 3001,
  API_KEY, // API Key de Google Generative AI
  JWT_SECRET,
  NODE_ENV = "development",
  SUPABASE_URL,     // URL de tu proyecto Supabase (ej: https://qfhqjfpgyhmatyxIqpfl.supabase.co)
  SUPABASE_KEY,     // Clave de API (anon key o service_role key) de tu proyecto Supabase
  CLIPDROP_API_KEY,
} = process.env;

const isDev = NODE_ENV !== "production";

// --- Constantes y Configuraciones ---
const COOKIE_OPTIONS = { httpOnly: true, secure: !isDev, sameSite: isDev ? "lax" : "none", maxAge: 3600 * 1000, path: "/" };
const TAMANO_MAX_ARCHIVO_MB = 20;
const MAX_LONGITUD_CONTEXTO = 30000;
const MODELOS_PERMITIDOS = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash", "gemini-2.5-pro-exp-03-25"];
const MODELO_POR_DEFECTO = "gemini-1.5-flash";
const TEMP_POR_DEFECTO = 0.7;
const TOPP_POR_DEFECTO = 0.9;
const IDIOMA_POR_DEFECTO = "es";
const JWT_OPTIONS = { expiresIn: "1h" };

// Nombres de los buckets en Supabase Storage
const SUPABASE_PDF_BUCKET = "user-pdfs"; // Basado en tu URL del dashboard: qfhqjfpgyhmatyxIqpfl/.../user-pdfs

// IMPORTANTE: VERIFICA EL NOMBRE INTERNO EXACTO DE TU BUCKET DE IMÁGENES GENERADAS
// Ve a tu Dashboard de Supabase -> Storage -> Clic en tu bucket "imágenes generadas"
// -> Mira la URL del navegador. La parte después de /buckets/ es el nombre que necesitas.
// Ejemplos comunes: "generated-images", "imagenes-generadas".
// ¡¡ASEGÚRATE DE QUE ESTE BUCKET SEA PÚBLICO!!
const SUPABASE_IMAGES_BUCKET = "generated-images"; // <-- ¡¡REEMPLAZA ESTO SI ES DIFERENTE AL SLUG DE TU BUCKET!!

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
const almacenamientoEnMemoria = multer.memoryStorage();
const multerFileFilter = (req, file, cb) => {
    const isPdf = file.mimetype === "application/pdf";
    if (!isPdf){
      cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', 'Solo se permiten archivos PDF.'), false);
    } else {
        cb(null, true);
    }
};
const subirEnGenerateText = multer({ storage: almacenamientoEnMemoria, limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 }, fileFilter: multerFileFilter }).array("archivosPdf");
const uploadArchivosPdf = multer({ storage: almacenamientoEnMemoria, limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 }, fileFilter: multerFileFilter }).array("archivosPdf");

// --- Funciones Auxiliares ---
async function generarContextoPDF(idUsuario, rutasSupabaseArchivos) {
  if (!rutasSupabaseArchivos || rutasSupabaseArchivos.length === 0) return "";
  if (!supabase) { console.warn("[Context PDF] Supabase no disponible."); return "[Error: Base de datos no disponible]";}
  try {
    const { data: archivosDB, error: dbError } = await supabase
      .from("archivos_usuario").select("nombre_archivo_unico, nombre_archivo_original")
      .eq("usuario_id", idUsuario).in("nombre_archivo_unico", rutasSupabaseArchivos);
    if (dbError) { console.error("[Context PDF] Supabase error (meta):", dbError.message); return "[Error al recuperar metadatos PDF]"; }
    if (!archivosDB || archivosDB.length === 0) { return ""; }
    const archivosMap = new Map(archivosDB.map((f) => [f.nombre_archivo_unico, f.nombre_archivo_original]));
    let textoCompleto = "";
    for (const rutaSupabase of rutasSupabaseArchivos) {
      const nombreOriginal = archivosMap.get(rutaSupabase);
      if (!nombreOriginal) continue;
      const { data: fileData, error: downloadError } = await supabase.storage.from(SUPABASE_PDF_BUCKET).download(rutaSupabase);
      if (downloadError) { console.warn(`[Context PDF] Supabase download error ${rutaSupabase}:`, downloadError.message); continue; }
      try {
        const buffer = Buffer.from(await fileData.arrayBuffer());
        const datosParseados = await pdfParse(buffer);
        textoCompleto += `\n\n[${nombreOriginal}]\n${(datosParseados.text || "").trim()}`;
      } catch (parseError) { console.warn(`[Context PDF] Parse error ${rutaSupabase}:`, parseError.message); }
    }
    return textoCompleto.trim();
  } catch (err) { console.error("[Context PDF] Exception:", err); return "[Error al generar contexto PDF]"; }
}

async function generarRespuestaIA( prompt, historialDB, textoPDF, modeloReq, temp, topP, lang) {
  if (!clienteIA) throw new Error("Servicio IA (Google) no disponible.");
  const nombreModelo = MODELOS_PERMITIDOS.includes(modeloReq) ? modeloReq : MODELO_POR_DEFECTO;
  if (modeloReq && nombreModelo !== modeloReq) console.warn(`[Gen IA] Modelo no válido ('${modeloReq}'), usando: ${MODELO_POR_DEFECTO}`);
  const configGeneracion = { temperature: !isNaN(temp) ? Math.max(0, Math.min(1, temp)) : TEMP_POR_DEFECTO, topP: !isNaN(topP) ? Math.max(0, Math.min(1, topP)) : TOPP_POR_DEFECTO, };
  const idioma = ["es", "en"].includes(lang) ? lang : IDIOMA_POR_DEFECTO;
  const langStrings = idioma === "en" ? { systemBase: "You are a helpful conversational assistant. Answer clearly and concisely in Markdown format.", systemPdf: `You are an assistant that answers *based solely* on the provided text. If the answer isn't in the text, state that clearly. Use Markdown format.\n\nReference Text (Context):\n"""\n{CONTEXT}\n"""\n\n`, label: "Question", error: "I'm sorry, there was a problem contacting the AI" } : { systemBase: "Eres un asistente conversacional útil. Responde de forma clara y concisa en formato Markdown.", systemPdf: `Eres un asistente que responde *basándose únicamente* en el texto proporcionado. Si la respuesta no está en el texto, indícalo claramente. Usa formato Markdown.\n\nTexto de Referencia (Contexto):\n"""\n{CONTEXT}\n"""\n\n`, label: "Pregunta", error: "Lo siento, hubo un problema al contactar la IA" };
  let instruccionSistema = textoPDF ? langStrings.systemPdf.replace("{CONTEXT}", (textoPDF.length > MAX_LONGITUD_CONTEXTO ? textoPDF.substring(0, MAX_LONGITUD_CONTEXTO) + "... (context truncated)" : textoPDF)) : langStrings.systemBase;
  if (textoPDF && textoPDF.length > MAX_LONGITUD_CONTEXTO) console.warn(`[Gen IA] ✂️ Contexto PDF truncado.`);
  const promptCompletoUsuario = `${instruccionSistema}${langStrings.label}: ${prompt}`;
  const contenidoGemini = [ ...(historialDB || []).filter((m) => m.texto?.trim()).map((m) => ({ role: m.rol === "user" ? "user" : "model", parts: [{ text: m.texto }], })), { role: "user", parts: [{ text: promptCompletoUsuario }] }, ];
  console.log( `[Gen IA] ➡️ Enviando ${contenidoGemini.length} partes a Gemini (${nombreModelo}).` );
  try {
    const modeloGemini = clienteIA.getGenerativeModel({ model: nombreModelo });
    const resultado = await modeloGemini.generateContent({ contents: contenidoGemini, generationConfig: configGeneracion, });
    const response = resultado?.response;
    const textoRespuestaIA = response?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (textoRespuestaIA) { console.log("[Gen IA] ✅ Respuesta recibida."); return textoRespuestaIA.trim(); }
    const blockReason = response?.promptFeedback?.blockReason; const finishReason = response?.candidates?.[0]?.finishReason;
    const errorDetail = blockReason ? `Bloqueo: ${blockReason}` : finishReason ? `Finalización: ${finishReason}` : "Respuesta inválida";
    console.warn(`[Gen IA] ⚠️ Respuesta vacía/bloqueada. ${errorDetail}`); throw new Error(`${langStrings.error}. (${errorDetail})`);
  } catch (error) { console.error(`[Gen IA] ❌ Error API (${nombreModelo}):`, error.message); throw new Error(`${langStrings.error}. (Detalle: ${error.message || "Desconocido"})`); }
}

async function generarImagenClipdrop(promptTexto) {
    if (!CLIPDROP_API_KEY) throw new Error("Servicio de imágenes (Clipdrop) no disponible (sin API key).");
    if (!promptTexto?.trim()) throw new Error("Prompt inválido para Clipdrop.");
    if (!supabase) throw new Error("Supabase no disponible para guardar imagen.");
    const CLIPDROP_API_URL = "https://clipdrop-api.co/text-to-image/v1";
    console.log(`[Img Gen Clipdrop Axios] Solicitando para: "${promptTexto}"`);
    const form = new FormData();
    form.append('prompt', promptTexto.trim());
    try {
        const response = await axios.post(CLIPDROP_API_URL, form, { headers: { 'x-api-key': CLIPDROP_API_KEY, ...form.getHeaders() }, responseType: 'arraybuffer' });
        const bufferImagen = Buffer.from(response.data);
        const tipoMime = response.headers['content-type'] || 'image/png';
        const extension = tipoMime.includes('png') ? 'png' : (tipoMime.includes('jpeg') ? 'jpeg' : 'out');
        const nombreArchivoImagenOriginal = `${Date.now()}-clipdrop-${promptTexto.substring(0,15).replace(/[^a-z0-9]/gi, '_')}.${extension}`;
        const supabaseImagePath = nombreArchivoImagenOriginal;

        const { error: uploadError } = await supabase.storage
            .from(SUPABASE_IMAGES_BUCKET).upload(supabaseImagePath, bufferImagen, { contentType: tipoMime, upsert: true });
        if (uploadError) { console.error(`[Supabase Storage] Error subiendo imagen ${supabaseImagePath}:`, uploadError); throw new Error("Error al guardar la imagen generada en el almacenamiento.");}

        const { data: publicUrlData } = supabase.storage.from(SUPABASE_IMAGES_BUCKET).getPublicUrl(supabaseImagePath);
        if (!publicUrlData || !publicUrlData.publicUrl) { console.error(`[Supabase Storage] Error obteniendo URL pública para ${supabaseImagePath}`); throw new Error("Error al obtener la URL de la imagen generada.");}

        console.log(`[Img Gen Clipdrop Axios] Guardada en Supabase: ${publicUrlData.publicUrl}`);
        return { fileName: nombreArchivoImagenOriginal, url: publicUrlData.publicUrl };
    } catch (error) {
        let status = 500; let errorMsgParaUsuario = "Error desconocido generando imagen.";
        if (error.message.includes("almacenamiento") || error.message.includes("URL de la imagen")) { errorMsgParaUsuario = error.message; }
        else if (error.response) { status = error.response.status; const responseData = error.response.data; let clipdropError = "Error de Clipdrop."; if (responseData) { if (Buffer.isBuffer(responseData)) { try { const errObj = JSON.parse(responseData.toString('utf-8')); clipdropError = errObj.error || responseData.toString('utf-8'); } catch (e) { clipdropError = responseData.toString('utf-8'); } } else if (typeof responseData === 'object' && responseData.error) { clipdropError = responseData.error; } else if (typeof responseData === 'string') { clipdropError = responseData; } } console.error(`[Img Gen Clipdrop Axios] Error API Clipdrop (${status}):`, clipdropError); if (status === 400) errorMsgParaUsuario = "Prompt inválido para Clipdrop."; else if (status === 401 || status === 403) errorMsgParaUsuario = "API Key de Clipdrop inválida."; else if (status === 402) errorMsgParaUsuario = "Límite Clipdrop alcanzado."; else if (status === 429) errorMsgParaUsuario = "Límite de tasa Clipdrop. Intente más tarde."; else errorMsgParaUsuario = `Error servicio imágenes: ${clipdropError.substring(0,150)}`; }
        else if (error.request) { console.error("[Img Gen Clipdrop Axios] Sin respuesta de Clipdrop:", error.message); errorMsgParaUsuario = "No se pudo contactar el servicio de imágenes."; }
        else { console.error("[Img Gen Clipdrop Axios] Error interno:", error.message); errorMsgParaUsuario = error.message || "Error interno en solicitud de imagen."; }
        const errToThrow = new Error(errorMsgParaUsuario); errToThrow.status = status; throw errToThrow;
    }
}

// --- Rutas API (Usuarios, Login, Logout, Auth) ---
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

app.post("/api/logout", (req, res) => {
    res.clearCookie("token", COOKIE_OPTIONS);
    res.status(200).json({ message: "Logout exitoso." });
});

app.get("/api/verify-auth", autenticarToken, (req, res) => {
    res.json({ user: req.usuario });
});

// --- Rutas API (Archivos PDF) ---
app.post("/api/files", autenticarToken, uploadArchivosPdf, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    try {
      const usuarioId = req.usuario.id; const archivosRecibidos = req.files;
      if (!archivosRecibidos || archivosRecibidos.length === 0) return res.status(400).json({ error: "No se subieron archivos PDF."});
      const resultadosSubidaDB = []; const erroresSubidaStorage = [];
      for (const file of archivosRecibidos) {
          const nombreArchivoSupabase = `${usuarioId}/${Date.now()}-${file.originalname.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9.\-_]/gi, '_')}`;
          const { error: uploadError } = await supabase.storage.from(SUPABASE_PDF_BUCKET).upload(nombreArchivoSupabase, file.buffer, { contentType: file.mimetype, upsert: false });
          if (uploadError) { console.error(`[Supabase Storage PDF Upload] Error ${file.originalname}:`, uploadError); erroresSubidaStorage.push({ originalName: file.originalname, error: uploadError.message });
          } else { resultadosSubidaDB.push({ usuario_id: usuarioId, nombre_archivo_unico: nombreArchivoSupabase, nombre_archivo_original: file.originalname }); }
      }
      if (resultadosSubidaDB.length > 0) {
          const { error: dbInsertError } = await supabase.from("archivos_usuario").insert(resultadosSubidaDB);
          if (dbInsertError) { console.error("[DB Insert PDF Meta] Error:", dbInsertError); for (const subido of resultadosSubidaDB) { await supabase.storage.from(SUPABASE_PDF_BUCKET).remove([subido.nombre_archivo_unico]).catch(e => console.error("Error limpiando PDF de Storage tras fallo DB:", e)); } return next(new Error(`Error guardando metadatos en DB: ${dbInsertError.message}`)); }
      }
      if (erroresSubidaStorage.length > 0) { return res.status(resultadosSubidaDB.length > 0 ? 207:400).json({ mensaje: resultadosSubidaDB.length > 0 ? "Algunos PDF subidos, otros fallaron.":"No se pudo subir ningún PDF.", subidos: resultadosSubidaDB.map(r => r.nombre_archivo_original), errores: erroresSubidaStorage});}
      res.status(200).json({ mensaje: "PDFs subidos y registrados." });
    } catch (error) { next(error); }
});

app.get("/api/files", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    try {
      const { data: archivos, error } = await supabase.from("archivos_usuario").select("nombre_archivo_unico, nombre_archivo_original").eq("usuario_id", req.usuario.id).order("fecha_subida", { ascending: false });
      if (error) throw error;
      res.json( (archivos || []).map((a) => ({ name: a.nombre_archivo_unico, originalName: a.nombre_archivo_original, })) );
    } catch (error) { next(error); }
});

app.delete( "/api/files/:rutaSupabaseArchivo(.*)", autenticarToken, async (req, res, next) => { // (.*) para capturar rutas con /
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const idUsuario = req.usuario.id; const rutaSupabaseArchivo = req.params.rutaSupabaseArchivo;
    if(!rutaSupabaseArchivo) return res.status(400).json({error: "Ruta de archivo Supabase no especificada."});
    try {
      const { data: archivoMeta, error: metaError } = await supabase.from("archivos_usuario").select("id").eq("usuario_id", idUsuario).eq("nombre_archivo_unico", rutaSupabaseArchivo).single();
      if (metaError || !archivoMeta) { if (metaError && metaError.code !== 'PGRST116') { console.error("[Delete File Meta Error]", metaError); throw metaError; } return res.status(404).json({ error: "Archivo no encontrado o no pertenece al usuario." });}
      const { error: storageDeleteError } = await supabase.storage.from(SUPABASE_PDF_BUCKET).remove([rutaSupabaseArchivo]);
      if (storageDeleteError) { console.error("[Supabase Storage Delete Error]", storageDeleteError.message); throw new Error(`Error borrando PDF de Storage: ${storageDeleteError.message}`); }
      const { error: dbDeleteError } = await supabase.from("archivos_usuario").delete().eq("id", archivoMeta.id);
      if (dbDeleteError) { console.error("[DB Delete PDF Meta Error]", dbDeleteError.message); throw new Error(`Error eliminando metadato PDF de DB: ${dbDeleteError.message}.`); }
      res.json({ message: "Archivo PDF eliminado." });
    } catch (err) { next(err); }
});

// --- Rutas de Conversaciones y Mensajes ---
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
    const { id } = req.params;
    const conversationIdInt = parseInt(id);
    if (isNaN(conversationIdInt)) return res.status(400).json({error:"ID de conversación inválido."});

    try {
      const { data: convOwner, error: ownerError } = await supabase
        .from("conversaciones")
        .select("id")
        .eq("id", conversationIdInt)
        .eq("usuario_id", req.usuario.id)
        .maybeSingle();

      if(ownerError) throw ownerError;
      if (!convOwner) return res.status(404).json({ error: "Conversación no encontrada o no autorizada." });

      const { data: mensajes, error } = await supabase
        .from("mensajes")
        .select("id, rol, texto, fecha_envio, es_error, tipo_mensaje")
        .eq("conversacion_id", conversationIdInt)
        .order("fecha_envio", { ascending: true });

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
      res.json({ message: "Conversación eliminada." });
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
      res.status(200).json({ message: "Título actualizado." });
    } catch (err) { next(err); }
  }
);

// --- RUTAS PRINCIPALES DE IA ---
app.post("/api/generateText", autenticarToken, subirEnGenerateText, async (req, res, next) => {
    if (!supabase || !clienteIA) return res.status(503).json({ error: "Servicio(s) no disponible(s)." });
    const usuarioId = req.usuario.id; const { prompt, conversationId: inputConvId, modeloSeleccionado, temperatura, topP, idioma, archivosSeleccionados } = req.body;
    const archivosPdfNuevosSubidos = req.files || [];
    let archivosSelParseados = []; if (archivosSeleccionados) { try { archivosSelParseados = typeof archivosSeleccionados === 'string' ? JSON.parse(archivosSeleccionados) : archivosSeleccionados; if (!Array.isArray(archivosSelParseados)) archivosSelParseados = []; } catch(e) { if (typeof archivosSeleccionados === 'string') return res.status(400).json({ error: "Formato archivosSeleccionados inválido." }); archivosSelParseados = []; }}
    let conversationId = inputConvId ? parseInt(inputConvId) : null; let isNewConversation = false; const rutasSupabaseNuevosArchivos = [];
    try {
        if (!conversationId) { const { data, error } = await supabase.from("conversaciones").insert([{ usuario_id: usuarioId, titulo: (prompt?.trim().substring(0,50) || "Conversación") }]).select("id").single(); if (error) throw new Error(`Error creando conv: ${error.message}`); conversationId = data.id; isNewConversation = true;
        } else { const { data:c, error:ce } = await supabase.from("conversaciones").select("id").eq("id",conversationId).eq("usuario_id",usuarioId).maybeSingle(); if(ce) throw ce; if(!c) return res.status(404).json({error:"Conversación no encontrada."});}
        if (prompt?.trim()) { await supabase.from("mensajes").insert([{ conversacion_id: conversationId, rol: "user", texto: prompt, tipo_mensaje: "text" }]).catch(e => console.error("Error guardando msg usr:",e));}
        if (archivosPdfNuevosSubidos.length > 0) { const regDB = []; const errStor = []; for (const f of archivosPdfNuevosSubidos) { const nombreSupa = `${usuarioId}/${Date.now()}-${f.originalname.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9.\-_]/gi, '_')}`; const {error:uE} = await supabase.storage.from(SUPABASE_PDF_BUCKET).upload(nombreSupa, f.buffer, {contentType:f.mimetype}); if(uE){errStor.push(f.originalname)}else{rutasSupabaseNuevosArchivos.push(nombreSupa); regDB.push({usuario_id:usuarioId, nombre_archivo_unico:nombreSupa, nombre_archivo_original:f.originalname});}} if(regDB.length>0){const{error:iE}=await supabase.from("archivos_usuario").insert(regDB); if(iE){for(const r of rutasSupabaseNuevosArchivos){await supabase.storage.from(SUPABASE_PDF_BUCKET).remove([r]).catch(e=>console.error("Fallo limpieza S:",e))} throw new Error("Fallo guardado meta PDF nuevos.");}} if(errStor.length>0) console.warn("Fallaron en Storage:",errStor);}
        const todasRutasSupaCtx = [...archivosSelParseados, ...rutasSupabaseNuevosArchivos].filter(Boolean);
        const contextoPDF = await generarContextoPDF(usuarioId, todasRutasSupaCtx);
        if ((!prompt?.trim()) && (!contextoPDF || contextoPDF.startsWith("[Error"))) return res.status(400).json({error:"Prompt o PDF válidos requeridos."});
        const {data:hist, error:errH} = await supabase.from("mensajes").select("rol, texto").eq("conversacion_id",conversationId).eq("es_error",false).order("fecha_envio",{ascending:true}); if(errH) throw new Error("Error cargando historial: "+errH.message);
        const promptIA = prompt || (idioma==='es' ? "Resume archivos.":"Summarize files.");
        const respuestaIA = await generarRespuestaIA(promptIA, (hist||[]), contextoPDF, modeloSeleccionado, parseFloat(temperatura), parseFloat(topP), idioma);
        await supabase.from("mensajes").insert([{conversacion_id:conversationId, rol:"model", texto:respuestaIA, tipo_mensaje:"text"}]).catch(e=>console.error("Error guardando msg model:",e));
        res.status(200).json({ respuesta: respuestaIA, isNewConversation, conversationId });
    } catch (error) { next(error); }
});

app.post("/api/generateImage", autenticarToken, async (req, res, next) => {
    if (!supabase || !CLIPDROP_API_KEY) return res.status(503).json({ error: "Servicio(s) no disponible(s)." });
    const { prompt, conversationId: inputConvId } = req.body;
    if (!prompt?.trim()) return res.status(400).json({ error: "Prompt inválido." });
    if (!inputConvId) return res.status(400).json({ error: "ID de conversación requerido." });
    const conversationId = parseInt(inputConvId); if (isNaN(conversationId)) return res.status(400).json({ error: "ID de conversación inválido." });
    try {
        const { data:cO, error:oE } = await supabase.from("conversaciones").select("id").eq("id",conversationId).eq("usuario_id",req.usuario.id).maybeSingle(); if(oE) throw oE; if(!cO) return res.status(404).json({error:"Conversación no encontrada/autorizada."});
        const resultadoImagen = await generarImagenClipdrop(prompt.trim()); // Ya sube a Supabase y devuelve URL pública
        const { data:msgG, error:msgIE } = await supabase.from("mensajes").insert([{conversacion_id:conversationId, rol:"model", texto:resultadoImagen.url, tipo_mensaje:"image"}]).select("id").single();
        if(msgIE) { console.error("[GenerateImage] Error DB:",msgIE.message); return res.status(207).json({message:"Imagen generada pero error guardándola en conv.", fileName:resultadoImagen.fileName, imageUrl:resultadoImagen.url, errorDB:msgIE.message});}
        res.json({ message: "Imagen generada y guardada.", fileName:resultadoImagen.fileName, imageUrl:resultadoImagen.url, conversationId, messageId:msgG?.id });
    } catch (error) { next(error); }
});

// --- Manejador de Errores Global ---
app.use((err, req, res, next) => {
  console.error("‼️ Global Error:", err.message, ...(isDev && err.stack ? [err.stack] : []));
  if (res.headersSent) return next(err);
  let scode = err.status || (err instanceof multer.MulterError ? 400 : 500);
  let msgU = err.message || "Error interno servidor.";
  const errL = req?.body?.idioma==='en'?"en":"es";

  if(err instanceof multer.MulterError){
    if(err.code==="LIMIT_FILE_SIZE"){
        scode=413; // Payload Too Large
        msgU=errL==='en'?`File large (Max: ${TAMANO_MAX_ARCHIVO_MB}MB).`:`Archivo grande (Máx: ${TAMANO_MAX_ARCHIVO_MB}MB).`;
    } else if(err.code==="LIMIT_UNEXPECTED_FILE" && err.message==='Solo se permiten archivos PDF.'){
        scode=415; // Unsupported Media Type
        msgU=err.message;
    } else {
        scode=400; // Bad Request for other multer errors
        msgU=errL==='en'?`Upload error: ${err.message}.`:`Error subida: ${err.message}.`;
    }
  } else if(err instanceof SyntaxError && "body" in err){
    scode=err.status||400;
    msgU=errL==='en'?"Malformed JSON.":"JSON mal formado.";
  } else if (err.message.includes("no disponible")||err.message.includes("no configurado")) {
    scode=503;
  } else if (err.message.includes("inválid")||err.message.includes("requerido")) {
    scode=400;
  } else if (err.message.includes("autenticación")||err.message.includes("permisos")||err.message.includes("API Key inválida")) {
    scode=401;
  } else if (err.message.includes("Límite")||err.message.includes("pago")||err.message.includes("créditos")){
    scode=402;
    msgU="Límite de uso gratuito.";
  } else if(err.message.includes("Demasiadas solicitudes")||err.message.includes("sobrecargado")||err.message.includes("Too Many Requests")){
    scode=429;
    msgU="Servicio externo ocupado.";
  } else if(scode===500&&(err.message.toLowerCase().includes("fetch")||err.message.toLowerCase().includes("network")||err.message.toLowerCase().includes("socket"))){
    msgU="Error de red externa.";
  } else if(err.message.includes("404")||err.message.includes("no encontrado")){
    scode=404;
    msgU="Recurso no encontrado.";
  } else if(err.code && typeof err.code ==='string'&&(err.code.startsWith('2')||err.code.startsWith('PGR'))){ // Supabase/Postgres errors
    console.warn("Error DB (Supabase/Postgres):", err.code, err.detail||err.hint);
    msgU=err.message.includes("constraint")?"Conflicto de datos.":"Error en BD.";
    if(err.code==='23505')scode=409; // Unique violation
    else scode=500; // Other DB errors as 500
  }

  res.status(scode).json({ error: msgU });
});

// --- Iniciar Servidor ---
const PORT = PUERTO || 3001;
app.listen(PORT, () => {
    console.log(`\n🚀 Servidor en puerto ${PORT} | ${isDev ? 'DEV' : 'PROD'}`);
    console.log(`🔗 Local: http://localhost:${PORT}`);
    console.log(`\n--- Estado Servicios ---`);
    console.log(` Supabase: ${supabase ? `✅ OK (PDFs en '${SUPABASE_PDF_BUCKET}', Imágenes en '${SUPABASE_IMAGES_BUCKET}')` : '❌ NO OK (Verificar URL/KEY)'}`);
    console.log(` Google GenAI: ${clienteIA ? '✅ OK' : '❌ NO OK (Verificar API_KEY)'}`);
    console.log(` Clipdrop Imagen: ${CLIPDROP_API_KEY ? '✅ OK' : '❌ NO OK (Verificar CLIPDROP_API_KEY)'}`);
    console.log(`----------------------\n`);
});
// --- END OF FILE index.js ---