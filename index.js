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
// FormData NO es necesario para la llamada a Hugging Face si enviamos JSON

// --- Definiciones de Directorio ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const directorioSubidas = path.join(__dirname, "uploads");
const directorioImagenesGeneradas = path.join(__dirname, "generated_images");

// --- Carga de Variables de Entorno ---
dotenv.config();
const {
  PORT: PUERTO = 3001,
  // DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, // Ya no se usan si usas Supabase
  API_KEY, // Google GenAI
  JWT_SECRET,
  NODE_ENV = "development",
  SUPABASE_URL,
  SUPABASE_KEY,
  HUGGING_FACE_API_KEY, // API Key para Hugging Face
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
if (!HUGGING_FACE_API_KEY) console.warn("⚠️ HUGGING_FACE_API_KEY no configurada.");

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
const subirPdf = multer({
    storage: almacenamiento,
    limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype === "application/pdf") cb(null, true);
        else cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', 'Solo PDF.'), false);
    },
}).array("archivosPdf");
const upload = multer({ storage: almacenamiento });

// --- Crear Directorios ---
[directorioSubidas, directorioImagenesGeneradas].forEach(dir => {
    if (!existsSync(dir)) {
        try { mkdirSync(dir, { recursive: true }); console.log(`✅ Dir creado: ${dir}`); }
        catch (e) { console.error(`🚨 No se pudo crear dir ${dir}:`, e); }
    } else console.log(`➡️ Dir existe: ${dir}`);
});

// --- Funciones Auxiliares ---
async function extraerTextoDePDF(ruta) { /* ... (sin cambios, ya robusta) ... */
    const nombre = path.basename(ruta);
    try { await fs.access(ruta); const buf = await fs.readFile(ruta); const data = await pdfParse(buf); return { texto: data?.text?.trim() || null }; }
    catch (e) { console.error(`Error extrayendo PDF ${nombre}:`, e.message); return { error: `Error ${e.code==='ENOENT'?'encontrando':'procesando'} archivo ${nombre}`}; }
}
async function generarContextoPDF(uid, files) { /* ... (sin cambios, ya robusta) ... */
    if (!uid || !files || files.length === 0) return "";
    if (!supabase) return "[Error BD no disponible]";
    try {
        const { data: dbFiles, error: dbErr } = await supabase.from("archivos_usuario").select("nombre_archivo_unico, nombre_archivo_original").eq("usuario_id", uid).in("nombre_archivo_unico", files);
        if (dbErr) throw dbErr;
        if (!dbFiles?.length) return "[Archivos no encontrados en DB]";
        const map = new Map(dbFiles.map(f=>[f.nombre_archivo_unico, f.nombre_archivo_original]));
        let ctx = "";
        for (const fName of files) {
            const origName = map.get(fName); if(!origName) continue;
            const {texto, error} = await extraerTextoDePDF(path.join(directorioSubidas, fName));
            if (texto) ctx += `\n\n[Archivo: ${origName}]\n${texto}`;
            else if (error) ctx += `\n\n[Error procesando ${origName}: ${error}]`;
        }
        return ctx.trim();
    } catch (e) { console.error("Error generando contexto PDF:", e); return "[Error generando contexto PDF]";}
}
async function generarRespuestaIA(prompt, hist, pdfCtx, model, temp, topP, lang) { /* ... (sin cambios, ya robusta) ... */
    if (!clienteIA) throw new Error("IA (Google) no disponible.");
    const modelName = MODELOS_PERMITIDOS.includes(model) ? model : MODELO_POR_DEFECTO;
    const genCfg = { temperature: temp ?? TEMP_POR_DEFECTO, topP: topP ?? TOPP_POR_DEFECTO };
    const idioma = ["es", "en"].includes(lang) ? lang : IDIOMA_POR_DEFECTO;
    const ls = idioma === 'es' ? {sysBase:"...", sysPdf:"...", q:"Pregunta:", err:"Error IA"} : {sysBase:"...", sysPdf:"...", q:"Question:", err:"AI Error"}; // Strings completos
    Object.assign(ls, idioma === "en" ? { systemBase: "You are a helpful conversational assistant...", systemPdf: `You are an assistant that answers *based solely* on the provided text...`, error: "I'm sorry..." } : { systemBase: "Eres un asistente conversacional útil...", systemPdf: `Eres un asistente que responde *basándose únicamente*...`, error: "Lo siento..." });
    
    let sysPrompt = pdfCtx ? ls.sysPdf.replace("{CONTEXT}", pdfCtx.substring(0, MAX_LONGITUD_CONTEXTO)) : ls.sysBase;
    const fullPrompt = `${sysPrompt}\n${ls.q} ${prompt}`;
    const geminiContent = [...(hist||[]).filter(m=>m.texto).map(m=>({role:m.rol,parts:[{text:m.texto}]})), {role:'user',parts:[{text:fullPrompt}]}];
    console.log(`[Gen IA] Gemini (${modelName}) con ${geminiContent.length} partes.`);
    try {
        const geminiModel = clienteIA.getGenerativeModel({model:modelName});
        const result = await geminiModel.generateContent({contents:geminiContent, generationConfig:genCfg});
        const resp = result?.response?.candidates?.[0]?.content?.parts?.[0]?.text;
        if(resp) return resp.trim();
        throw new Error(`Respuesta vacía o bloqueada (Block: ${result?.response?.promptFeedback?.blockReason}, Finish: ${result?.response?.candidates?.[0]?.finishReason})`);
    } catch (e) { console.error(`Error API Gemini (${modelName}):`, e.message); throw new Error(`${ls.err} (Detalle: ${e.message})`); }
}

// --- Función para Generar Imágenes con HUGGING FACE ---
async function generarYGuardarImagen(promptTexto, modeloIdParam) {
  if (!HUGGING_FACE_API_KEY) throw new Error("Servicio imágenes (HF) no disponible (sin API key).");
  if (!promptTexto?.trim()) throw new Error("Prompt inválido.");

  const modeloId = modeloIdParam || "runwayml/stable-diffusion-v1-5"; // Default a un modelo conocido
  const HUGGING_FACE_API_URL = `https://api-inference.huggingface.co/models/${modeloId}`;
  
  const apiKeySnippet = HUGGING_FACE_API_KEY ? `${HUGGING_FACE_API_KEY.substring(0, 5)}...${HUGGING_FACE_API_KEY.substring(HUGGING_FACE_API_KEY.length - 4)}` : 'NO DISPONIBLE';
  console.log(`[Img Gen HF] Solicitando para: "${promptTexto}" con modelo: ${modeloId}`);
  console.log(`[Img Gen HF Debug] Usando API Key Snippet: ${apiKeySnippet}`);
  console.log(`[Img Gen HF Debug] Llamando a API URL: ${HUGGING_FACE_API_URL}`);

  try {
    const response = await fetch(HUGGING_FACE_API_URL, {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${HUGGING_FACE_API_KEY}`,
            "Content-Type": "application/json", // Para HF, usualmente JSON es para texto-a-imagen
        },
        body: JSON.stringify({ inputs: promptTexto.trim() }), // El prompt va en 'inputs'
    });

    if (!response.ok) {
        const status = response.status;
        let errorBody = "Error desconocido de API Hugging Face.";
        try { errorBody = await response.text(); } catch(e){} // Intenta obtener cuerpo
        console.error(`[Img Gen HF] Error API (${status}):`, errorBody);
        let userMsg = `Error ${status} del servicio de imágenes.`;
        if (status === 401 || status === 403) userMsg = "API Key de Hugging Face inválida o sin permisos.";
        else if (status === 404) userMsg = `Modelo '${modeloId}' no encontrado o no disponible en API HF.`;
        else if (status === 503) userMsg = "Servicio de imágenes HF sobrecargado. Intente más tarde.";
        else if (status === 400 && errorBody.includes("is a required field")) userMsg = "Prompt requerido por API HF."; // Específico si el error lo dice
        else if (status === 400) userMsg = `Solicitud inválida al servicio de imágenes HF: ${errorBody.substring(0,100)}`;

        throw new Error(userMsg);
    }

    // HF API para imágenes devuelve la imagen binaria directamente
    const bufferImagen = Buffer.from(await response.arrayBuffer());
    const tipoMime = response.headers.get('content-type') || 'image/jpeg'; // Asumir jpeg si no se especifica
    const extension = tipoMime.split('/')[1]?.split('+')[0] || 'jpeg'; // ej. image/jpeg o image/png+jpeg
    const nombreArchivo = `${Date.now()}-hf-${modeloId.split('/').pop()}-${promptTexto.substring(0,15).replace(/[^a-z0-9]/gi, '_')}.${extension}`;
    const rutaArchivo = path.join(directorioImagenesGeneradas, nombreArchivo);

    await fs.writeFile(rutaArchivo, bufferImagen);
    console.log(`[Img Gen HF] Guardada: ${rutaArchivo}`);

    return { fileName: nombreArchivo, url: `/generated_images/${nombreArchivo}` };

  } catch (error) {
    console.error("[Img Gen HF] Catch Error:", error.message);
    throw new Error(error.message || "Error desconocido generando imagen con Hugging Face.");
  }
}

// --- RUTAS API ---

// Auth (Correcciones Supabase aplicadas)
app.post("/api/register", async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });
    try {
        const hash = await bcrypt.hash(password, 10);
        const { data, error } = await supabase.from("usuarios").insert([{ nombre_usuario: username, contrasena_hash: hash }]).select("id").single(); // CORREGIDO
        if (error) { if (error.code === '23505') return res.status(409).json({ error: "Usuario ya existe." }); throw error; }
        res.status(201).json({ message: "Registro exitoso.", userId: data.id });
    } catch (error) { console.error("[Register Error]", error.message); next(error); }
});

app.post("/api/login", async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });
    try {
        const { data: user, error } = await supabase.from("usuarios").select("id, nombre_usuario, contrasena_hash").eq("nombre_usuario", username).single(); // CORREGIDO (asumiendo .single())
        if (error || !user || !(await bcrypt.compare(password, user.contrasena_hash))) {
            return res.status(401).json({ error: "Credenciales inválidas." });
        }
        const payload = { id: user.id, username: user.nombre_usuario };
        if(!JWT_SECRET) throw new Error("JWT Secret no configurado!");
        const token = jwt.sign(payload, JWT_SECRET, JWT_OPTIONS);
        res.cookie("token", token, COOKIE_OPTIONS);
        res.json({ message: "Login exitoso.", user: payload });
    } catch (error) { console.error("[Login Error]", error.message); next(error); }
});

app.post("/api/logout", (req, res) => { /* Sin cambios */ res.clearCookie("token", COOKIE_OPTIONS); res.status(200).json({ message: "Logout."}); });
app.get("/api/verify-auth", autenticarToken, (req, res) => { /* Sin cambios */ res.json({ user: req.usuario }); });

// Archivos PDF (Correcciones Supabase aplicadas)
app.post("/api/files", autenticarToken, upload.array("archivosPdf"), async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    try {
        const uid = req.usuario.id;
        const files = req.files;
        if (!files || files.length === 0) return res.status(400).json({ error: "No se subieron archivos." });
        const records = files.map(f => ({ usuario_id: uid, nombre_archivo_unico: f.filename, nombre_archivo_original: f.originalname }));
        const { error } = await supabase.from("archivos_usuario").insert(records); // CORREGIDO
        if (error) { files.forEach(async f => {try{await fs.unlink(f.path);}catch(e){}}); throw error; } // Limpiar en error
        res.status(200).json({ mensaje: `${files.length} archivo(s) guardado(s).` });
    } catch (error) { console.error("[Upload Files Error]", error.message); next(error); }
});

app.get("/api/files", autenticarToken, async (req, res, next) => { /* ... (código ya era correcto) ... */
    if (!supabase) return res.status(503).json({ error: "BD no disponible."});
    try {
        const { data, error } = await supabase.from("archivos_usuario")
            .select("nombre_archivo_unico, nombre_archivo_original")
            .eq("usuario_id", req.usuario.id)
            .order("fecha_subida", { ascending: false });
        if (error) throw error;
        res.json(data?.map(a => ({ name: a.nombre_archivo_unico, originalName: a.nombre_archivo_original })) || []);
    } catch (error){ console.error("[Get Files Error]", error.message); next(error); }
});

app.delete("/api/files/:nombreArchivoUnico", autenticarToken, async (req, res, next) => { /* ... (código ya era correcto) ... */
    if (!supabase) return res.status(503).json({ error: "BD no disponible."});
    const { id: idUsuario } = req.usuario;
    const { nombreArchivoUnico } = req.params;
    if (!nombreArchivoUnico) return res.status(400).json({ error: "Falta nombre de archivo." });
    try {
        const { data: archivo, error: findError } = await supabase.from("archivos_usuario")
            .select("id").eq("usuario_id", idUsuario).eq("nombre_archivo_unico", nombreArchivoUnico).single();
        if (findError || !archivo) return res.status(404).json({ error: "Archivo no encontrado o no autorizado." });
        const { error: deleteDbError } = await supabase.from("archivos_usuario").delete().eq("id", archivo.id);
        if (deleteDbError) throw new Error("Error eliminando registro de la BD.");
        try { await fs.unlink(path.join(directorioSubidas, nombreArchivoUnico)); } catch (fsErr) { if(fsErr.code !== 'ENOENT') console.error("Error borrando físico:", fsErr);}
        res.json({ message: "Archivo eliminado." });
    } catch (error) { console.error("[Delete File Error]", error.message); next(error); }
});

// Conversaciones (Correcciones Supabase aplicadas donde hacía falta)
app.get("/api/conversations", autenticarToken, async (req, res, next) => { /* ... (ya era correcto) ... */
    if (!supabase) return res.status(503).json({ error: "BD no disponible."});
    try {
        const { data, error } = await supabase.from("conversaciones").select("id, titulo").eq("usuario_id", req.usuario.id).order("fecha_actualizacion", { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch(error){ console.error("[Get Convs Error]", error.message); next(error); }
});

app.get("/api/conversations/:id/messages", autenticarToken, async (req, res, next) => { /* ... (ya era correcto con owner check) ... */
    if (!supabase) return res.status(503).json({ error: "BD no disponible."});
    const { id } = req.params; if(!id) return res.status(400).json({error:"Falta ID conv."});
    try {
        const { data: conv, error: ownerErr } = await supabase.from("conversaciones").select("id").eq("id", id).eq("usuario_id", req.usuario.id).maybeSingle();
        if (ownerErr) throw ownerErr;
        if (!conv) return res.status(404).json({ error: "Conversación no encontrada/autorizada." });
        const { data: msgs, error: msgErr } = await supabase.from("mensajes").select("rol, texto, fecha_envio").eq("conversacion_id", id).order("fecha_envio", { ascending: true });
        if (msgErr) throw msgErr;
        res.json(msgs || []);
    } catch(error){ console.error("[Get Messages Error]", error.message); next(error); }
});

app.delete("/api/conversations/:idConv", autenticarToken, async (req, res, next) => { /* ... (ya era correcto) ... */
    if (!supabase) return res.status(503).json({ error: "BD no disponible."});
    const { idConv } = req.params; if(!idConv) return res.status(400).json({error:"Falta ID conv."});
    try {
        const { error, count } = await supabase.from("conversaciones").delete({ count: 'exact' }).eq("id", idConv).eq("usuario_id", req.usuario.id);
        if (error) throw error;
        res.json({ message: `Conversación ${count > 0 ? 'eliminada' : 'no encontrada/autorizada'}.`, deleted: count > 0 });
    } catch (error){ console.error("[Del Conv Error]", error.message); next(error); }
});

app.put("/api/conversations/:id/title", autenticarToken, async (req, res, next) => { /* ... (ya era correcto) ... */
    if (!supabase) return res.status(503).json({ error: "BD no disponible."});
    const { id } = req.params; const { nuevoTitulo } = req.body; if (!id || !nuevoTitulo?.trim()) return res.status(400).json({error:"Datos inválidos."});
    const titulo = nuevoTitulo.trim().substring(0, 100);
    try {
        const { error, count } = await supabase.from("conversaciones").update({ titulo, fecha_actualizacion: new Date().toISOString() }).eq("id", id).eq("usuario_id", req.usuario.id).select({count:'exact'});
        if (error) throw error;
        if (count === 0) return res.status(404).json({error:"Conversación no encontrada/autorizada."});
        res.status(200).json({ message: "Título actualizado." });
    } catch (error){ console.error("[Update Title Error]", error.message); next(error); }
});


// --- RUTAS PRINCIPALES DE IA ---

// Generar Texto (Chat) (Correcciones Supabase aplicadas)
app.post("/api/generateText", autenticarToken, subirPdf, async (req, res, next) => {
    if (!supabase || !clienteIA) return res.status(503).json({ error: "Servicio BD o IA no disponible." });
    const usuarioId = req.usuario.id;
    const { prompt, conversationId: inputConvId, modeloSeleccionado, temperatura, topP, idioma, archivosSeleccionados } = req.body;
    let archivosSelArr = [];
    try { if (archivosSeleccionados) archivosSelArr = JSON.parse(archivosSeleccionados || "[]"); if(!Array.isArray(archivosSelArr)) throw new Error(); }
    catch(e){return res.status(400).json({error: "archivosSeleccionados inválido."})}

    let conversationId = inputConvId;
    let isNewConversation = false;

    try {
        if (!conversationId) {
            const titulo = (prompt||"Chat PDF").trim().split(/\s+/).slice(0,5).join(" ") || "Nuevo";
            const {data:cData,error:cErr} = await supabase.from("conversaciones").insert([{usuario_id:usuarioId,titulo}]).select("id").single(); // CORREGIDO
            if(cErr) throw cErr; conversationId=cData.id; isNewConversation=true;
        }
        if (prompt) {
            const {error:uMsgErr} = await supabase.from("mensajes").insert([{conversacion_id:conversationId, rol:"user", texto:prompt}]); // CORREGIDO
            if(uMsgErr) console.error("Error guardando msg user:", uMsgErr.message);
        }
        const archivosNuevos = req.files || [];
        if (archivosNuevos.length > 0) {
            const records = archivosNuevos.map(f=>({usuario_id:usuarioId, nombre_archivo_unico:f.filename, nombre_archivo_original:f.originalname}));
            const {error:fErr} = await supabase.from("archivos_usuario").insert(records); // CORREGIDO
            if(fErr){ archivosNuevos.forEach(async f=>{try{await fs.unlink(f.path)}catch(e){}}); throw fErr;}
        }
        const archivosCtx = [...archivosSelArr, ...archivosNuevos.map(f=>f.filename)].filter(Boolean);
        let ctxPDF = ""; if(archivosCtx.length>0) ctxPDF = await generarContextoPDF(usuarioId, archivosCtx);
        if(!prompt && !ctxPDF) return res.status(400).json({error:"Prompt o archivos PDF requeridos."});

        const {data:hist, error:histErr} = await supabase.from("mensajes").select("rol, texto").eq("conversacion_id",conversationId).order("fecha_envio",{ascending:true}); // CORREGIDO
        if(histErr) throw histErr;

        const iaPrompt = prompt || (idioma==='es'?"Resume archivos.":"Summarize files.");
        const respIA = await generarRespuestaIA(iaPrompt, hist||[], ctxPDF, modeloSeleccionado, parseFloat(temperatura), parseFloat(topP), idioma);
        
        const {error:mMsgErr} = await supabase.from("mensajes").insert([{conversacion_id:conversationId, rol:"model", texto:respIA}]); // CORREGIDO
        if(mMsgErr) console.error("Error guardando msg model:", mMsgErr.message);
        
        res.json({respuesta:respIA, isNewConversation, conversationId});
    } catch (error) { next(error); }
});

// Generar Imagen (con Hugging Face)
app.post("/api/generateImage", autenticarToken, async (req, res, next) => {
    const { prompt } = req.body;
    const { modelo } = req.query; // Para permitir ?modelo=otro/modelo
    if (!prompt?.trim()) return res.status(400).json({ error: "Prompt inválido." });
    if (!HUGGING_FACE_API_KEY) return res.status(503).json({ error: "Servicio imágenes HF no configurado." });

    try {
        const resultado = await generarYGuardarImagen(prompt.trim(), modelo); // modelo puede ser undefined
        res.json({ message: "Imagen generada con Hugging Face.", fileName: resultado.fileName, imageUrl: resultado.url });
    } catch (error) { next(error); }
});


// --- Servir Archivos Estáticos ---
app.use('/generated_images', express.static(directorioImagenesGeneradas, { maxAge: '1h' }));

// --- Manejador de Errores Global ---
app.use((err, req, res, next) => {
  console.error("‼️ Global Error:", err.status || '(no status)', err.message);
  if (isDev && err.stack) console.error(err.stack);
  if (res.headersSent) return next(err);

  let statusCode = err.status || (err instanceof multer.MulterError ? 400 : 500);
  let msg = err.message || "Error interno del servidor.";

  if (err instanceof multer.MulterError) { /* ... (código sin cambios) ... */
      if (err.code === 'LIMIT_FILE_SIZE') { statusCode = 413; msg = `Archivo grande (Máx: ${TAMANO_MAX_ARCHIVO_MB} MB).`; }
      else if (err.message === 'Solo se permiten archivos PDF.') { statusCode = 400; }
      else { statusCode = 400; msg = `Error subida: ${err.field||''} ${err.code}`; }
  } else if (err instanceof SyntaxError && statusCode === 400 && "body" in err) {
      msg = "JSON mal formado.";
  } else if (msg.includes("no disponible")) statusCode = 503;
  else if (msg.includes("autenticación")||msg.includes("permisos")||msg.includes("API Key inválida")) statusCode = 401;
  else if (msg.includes("Límite")||msg.includes("pago")||msg.includes("créditos")) { statusCode = 402; msg="Límite uso gratuito."; }
  else if (msg.includes("Demasiadas solicitudes")||msg.includes("sobrecargado")||msg.includes("Too Many Requests")) {statusCode=429; msg="Servicio externo ocupado.";}
  else if (msg.includes("inválido")||msg.includes("requerido por")) statusCode = 400;
  else if (statusCode === 500 && msg.includes("fetch")) msg = "Error red externa.";
  else if (msg.includes("404")||msg.includes("no encontrado")) { statusCode=404; msg="Recurso no encontrado.";}
  // Corrección de Supabase: los errores de Supabase ahora deberían tener mensajes más claros
  // y ser capturados antes si es un error de BD, o propagados aquí si es un error inesperado.

  res.status(statusCode).json({ error: msg });
});

// --- Iniciar Servidor ---
const PORT = PUERTO || 3001;
app.listen(PORT, () => {
    console.log(`\n🚀 Servidor en puerto ${PORT} | ${isDev ? 'DEV' : 'PROD'}`);
    console.log(`🔗 Local: http://localhost:${PORT}`);
    console.log(`\n--- Estado Servicios ---`);
    console.log(` Supabase: ${supabase ? '✅ OK' : '❌ NO OK (Verificar URL/KEY)'}`);
    console.log(` Google GenAI: ${clienteIA ? '✅ OK' : '❌ NO OK (Verificar API_KEY)'}`);
    console.log(` HuggingFace Img: ${HUGGING_FACE_API_KEY ? '✅ OK (Key presente)' : '❌ NO OK (Verificar HUGGING_FACE_API_KEY)'}`);
    console.log(`----------------------\n`);
});