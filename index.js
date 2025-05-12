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
import FormData from "form-data"; // Necesario para Clipdrop

// --- Definiciones de Directorio ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const directorioSubidas = path.join(__dirname, "uploads");
const directorioImagenesGeneradas = path.join(__dirname, "generated_images");

// --- Carga de Variables de Entorno ---
dotenv.config();
const {
  PORT: PUERTO = 3001,
  DB_HOST,
  DB_USER,
  DB_PASSWORD,
  DB_NAME,
  API_KEY, // Google GenAI
  JWT_SECRET,
  NODE_ENV = "development",
  SUPABASE_URL,
  SUPABASE_KEY,
  CLIPDROP_API_KEY, // API Key para Clipdrop
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
if (!API_KEY) console.warn("⚠️ [Startup] ADVERTENCIA: API_KEY (Google GenAI) no configurada.");
if (!SUPABASE_URL) console.warn("⚠️ [Startup] ADVERTENCIA: SUPABASE_URL no configurada.");
if (!SUPABASE_KEY) console.warn("⚠️ [Startup] ADVERTENCIA: SUPABASE_KEY no configurada.");
if (!CLIPDROP_API_KEY) console.warn("⚠️ [Startup] ADVERTENCIA: CLIPDROP_API_KEY (para imágenes) no configurada.");

// --- Inicialización de Express ---
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
app.use(cors({ origin: (origin, callback) => { callback(null, origin || true); }, credentials: true }));
app.use(cookieParser());
app.use(express.json());

// --- Middleware de Autenticación ---
const autenticarToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) { return res.status(401).json({ error: "Token no proporcionado" }); }
    if (!JWT_SECRET) { console.error("[Auth Error] JWT_SECRET Missing!"); return res.status(500).json({ error: "Error de configuración del servidor." }); }
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

// --- Configuración de Multer ---
const almacenamiento = multer.diskStorage({
    destination: directorioSubidas,
    filename: (req, file, cb) => {
        const sufijoUnico = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
        const nombreOriginalLimpio = file.originalname.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9.\-_]/g, "_").replace(/_{2,}/g, "_");
        const extension = path.extname(nombreOriginalLimpio) || ".pdf";
        const nombreBase = path.basename(nombreOriginalLimpio, extension);
        cb(null, `${sufijoUnico}-${nombreBase}${extension}`);
    },
});
const subirPdf = multer({
    storage: almacenamiento,
    limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype === "application/pdf") {
            cb(null, true);
        } else {
            console.warn(`⚠️ Rechazado archivo no PDF: ${file.originalname} (${file.mimetype})`);
            cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', 'Solo se permiten archivos PDF.'), false);
        }
    },
}).array("archivosPdf");
const upload = multer({ storage: almacenamiento });

// --- Crear directorios necesarios al inicio ---
[directorioSubidas, directorioImagenesGeneradas].forEach(dir => {
    if (!existsSync(dir)) {
        try { mkdirSync(dir, { recursive: true }); console.log(`✅ Directorio creado: ${dir}`); }
        catch (error) { console.error(`🚨 FATAL: No se pudo crear directorio ${dir}:`, error); }
    } else { console.log(`➡️ Directorio ya existe: ${dir}`); }
});

// --- Funciones Auxiliares ---

async function extraerTextoDePDF(rutaArchivo) {
    const nombreArchivoLog = path.basename(rutaArchivo);
    try {
        await fs.access(rutaArchivo);
        const bufferDatos = await fs.readFile(rutaArchivo);
        const datos = await pdfParse(bufferDatos);
        return { texto: datos?.text?.trim() || null, error: null };
    } catch (error) {
        if (error.code === "ENOENT") {
            console.error(`❌ [PDF Extract] Archivo NO ENCONTRADO: ${rutaArchivo}. Verificar persistencia.`);
            return { texto: null, error: `Archivo no encontrado: ${nombreArchivoLog}` };
        }
        console.error(`❌ [PDF Extract] Error procesando ${nombreArchivoLog}:`, error.message);
        return { texto: null, error: `Error al parsear ${nombreArchivoLog}: ${error.message || "desconocido"}` };
    }
}

async function generarContextoPDF(idUsuario, nombresArchivosUnicos) {
    if (!idUsuario || !nombresArchivosUnicos || nombresArchivosUnicos.length === 0) return "";
    if (!supabase) return "[Error: Base de datos no disponible]";

    let textoCompleto = "";
    try {
        const { data: archivosDB, error: dbError } = await supabase
            .from("archivos_usuario")
            .select("nombre_archivo_unico, nombre_archivo_original")
            .eq("usuario_id", idUsuario)
            .in("nombre_archivo_unico", nombresArchivosUnicos);

        if (dbError) { throw new Error(`Error BD obteniendo archivos: ${dbError.message}`); }
        if (!archivosDB || archivosDB.length === 0) { console.warn("[Context PDF] No se encontraron archivos en DB."); return "[Archivos especificados no encontrados]"; }

        const archivosMap = new Map(archivosDB.map(f => [f.nombre_archivo_unico, f.nombre_archivo_original]));

        for (const nombreUnico of nombresArchivosUnicos) {
            const nombreOriginal = archivosMap.get(nombreUnico);
            if (!nombreOriginal) { console.warn(`[Context PDF] Falta info original para ${nombreUnico}`); continue; }
            const ruta = path.join(directorioSubidas, nombreUnico);
            try {
                const { texto, error: pdfError } = await extraerTextoDePDF(ruta);
                if (texto) textoCompleto += `\n\n[Archivo: ${nombreOriginal}]\n${texto}`;
                else if (pdfError) textoCompleto += `\n\n[Error al procesar archivo: ${nombreOriginal} - ${pdfError}]`;
            } catch (extractErr) { console.error(`[Context PDF] Excepción procesando ${nombreUnico}:`, extractErr); }
        }
        return textoCompleto.trim();
    } catch (error) {
        console.error("[Context PDF] Error general:", error);
        return "[Error al generar contexto desde PDFs]";
    }
}

async function generarRespuestaIA(prompt, historialDB = [], textoPDF = "", modeloReq, temp, topP, lang) {
    if (!clienteIA) throw new Error("Servicio IA (Google) no disponible.");

    const nombreModelo = MODELOS_PERMITIDOS.includes(modeloReq) ? modeloReq : MODELO_POR_DEFECTO;
    const configGeneracion = { temperature: !isNaN(temp) ? Math.max(0, Math.min(1, temp)) : TEMP_POR_DEFECTO, topP: !isNaN(topP) ? Math.max(0, Math.min(1, topP)) : TOPP_POR_DEFECTO };
    const idioma = ["es", "en"].includes(lang) ? lang : IDIOMA_POR_DEFECTO;

    const langStrings = idioma === "en" ?
        { systemBase: "You are a helpful conversational assistant. Answer clearly and concisely in Markdown format.", systemPdf: `You are an assistant that answers *based solely* on the provided text. If the answer isn't in the text, state that clearly. Use Markdown format.\n\nReference Text (Context):\n"""\n{CONTEXT}\n"""\n\n`, label: "Question:", error: "I'm sorry, there was a problem contacting the AI" } :
        { systemBase: "Eres un asistente conversacional útil. Responde de forma clara y concisa en formato Markdown.",
          systemPdf: `Eres un asistente que responde *basándose únicamente* en el texto proporcionado. Si la respuesta no está en el texto, indícalo claramente. Usa formato Markdown.\n\nTexto de Referencia (Contexto):\n"""\n{CONTEXT}\n"""\n\n`,
          label: "Pregunta:", error: "Lo siento, hubo un problema al contactar la IA" };

    let sistemaPrompt = langStrings.systemBase;
    if (textoPDF) {
        const ctx = textoPDF.length > MAX_LONGITUD_CONTEXTO ? textoPDF.substring(0, MAX_LONGITUD_CONTEXTO) + "..." : textoPDF;
        if(textoPDF.length > MAX_LONGITUD_CONTEXTO) console.warn("[Gen IA] Contexto PDF truncado.");
        sistemaPrompt = langStrings.systemPdf.replace("{CONTEXT}", ctx);
    }
    const promptUsuarioActual = `${sistemaPrompt}\n${langStrings.label} ${prompt}`;

    const contenidoGemini = [
        ...historialDB.filter(m => m.texto?.trim()).map(m => ({
            role: m.rol === 'user' ? 'user' : 'model',
            parts: [{ text: m.texto }]
        })),
        { role: 'user', parts: [{ text: promptUsuarioActual }] }
    ];

    console.log(`[Gen IA] Enviando ${contenidoGemini.length} partes a Gemini (${nombreModelo})`);
    try {
        const modeloGemini = clienteIA.getGenerativeModel({ model: nombreModelo });
        const resultado = await modeloGemini.generateContent({ contents: contenidoGemini, generationConfig: configGeneracion });
        const response = resultado?.response;
        const textoRespuesta = response?.candidates?.[0]?.content?.parts?.[0]?.text;

        if (textoRespuesta) { console.log("[Gen IA] Respuesta recibida."); return textoRespuesta.trim(); }

        const blockReason = response?.promptFeedback?.blockReason;
        const finishReason = response?.candidates?.[0]?.finishReason;
        console.warn(`[Gen IA] Respuesta vacía/bloqueada. Block: ${blockReason}, Finish: ${finishReason}`);
        throw new Error(langStrings.error + (blockReason ? ` (Bloqueo: ${blockReason})` : finishReason ? ` (Finalización: ${finishReason})` : " (Respuesta inválida)"));
    } catch (error) {
        console.error(`[Gen IA] Error API (${nombreModelo}):`, error.message);
        throw new Error(langStrings.error + ` (Detalle: ${error.message || 'Desconocido'})`);
    }
}

async function generarImagenClipdrop(promptTexto) {
    if (!CLIPDROP_API_KEY) throw new Error("Servicio de generación de imágenes (Clipdrop) no disponible.");
    if (!promptTexto?.trim()) throw new Error("Se requiere un prompt válido.");

    const CLIPDROP_API_URL = "https://clipdrop-api.co/text-to-image/v1";
    console.log(`[Img Gen Clipdrop] Solicitando para: "${promptTexto}"`);

    try {
        const form = new FormData();
        form.append('prompt', promptTexto.trim());

        // ----- INICIO DEL LOG DE DEBUG AÑADIDO -----
        console.log(`[Img Gen Clipdrop Debug] FormData a enviar: prompt = '${promptTexto.trim()}'`);
        // ----- FIN DEL LOG DE DEBUG AÑADIDO -----

        const response = await fetch(CLIPDROP_API_URL, {
            method: 'POST',
            headers: { 'x-api-key': CLIPDROP_API_KEY, ...form.getHeaders() },
            body: form
        });

        if (!response.ok) {
            const status = response.status;
            let errorMsg = `Error ${status} de Clipdrop.`;
            try { const errJson = await response.json(); errorMsg = errJson.error || JSON.stringify(errJson); }
            catch (e) { try { errorMsg = await response.text(); } catch (e2) {} }
            console.error(`[Img Gen Clipdrop] Error API (${status}):`, errorMsg);
            if (status === 401 || status === 403) throw new Error("Error de autenticación con el servicio de imágenes.");
            if (status === 402) throw new Error("Límite de uso gratuito del servicio de imágenes alcanzado.");
            if (status === 429) throw new Error("Servicio de imágenes sobrecargado. Intente más tarde.");
            // Para error 400 ("prompt: Required"), el mensaje de error ya vendrá en errorMsg
            throw new Error(errorMsg.includes("prompt: Required") ? "El prompt es requerido por Clipdrop." : "Error al contactar el servicio de imágenes.");
        }

        const bufferImagen = Buffer.from(await response.arrayBuffer());
        const tipoMime = response.headers.get('content-type') || 'image/png';
        const extension = tipoMime.split('/')[1] || 'png';
        const nombreArchivo = `${Date.now()}-clipdrop-${promptTexto.substring(0,15).replace(/[^a-z0-9]/gi, '_')}.${extension}`;
        const rutaArchivo = path.join(directorioImagenesGeneradas, nombreArchivo);

        await fs.writeFile(rutaArchivo, bufferImagen);
        console.log(`[Img Gen Clipdrop] Guardada: ${rutaArchivo}`);

        return { fileName: nombreArchivo, url: `/generated_images/${nombreArchivo}` };

    } catch (error) {
        console.error("[Img Gen Clipdrop] Catch Error:", error.message);
        throw new Error(error.message || "Error desconocido generando la imagen.");
    }
}

// --- Rutas API ---

// Autenticación
app.post("/api/register", async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });
    try {
        const hash = await bcrypt.hash(password, 10);
        const { data, error } = await supabase.from("usuarios").insert([{ nombre_usuario: username, contrasena_hash: hash }]).select("id").single();
        if (error) { if (error.code === '23505') return res.status(409).json({ error: "Usuario ya existe." }); throw error; }
        res.status(201).json({ message: "Registro exitoso.", userId: data.id });
    } catch (error) { console.error("[Register Error]", error); next(error); }
});

app.post("/api/login", async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });
    try {
        const { data: user, error } = await supabase.from("usuarios").select("id, nombre_usuario, contrasena_hash").eq("nombre_usuario", username).single();
        if (error || !user || !(await bcrypt.compare(password, user.contrasena_hash))) {
            return res.status(401).json({ error: "Credenciales inválidas." });
        }
        const payload = { id: user.id, username: user.nombre_usuario };
        const token = jwt.sign(payload, JWT_SECRET, JWT_OPTIONS);
        res.cookie("token", token, COOKIE_OPTIONS);
        res.json({ message: "Login exitoso.", user: payload });
    } catch (error) { console.error("[Login Error]", error); next(error); }
});

app.post("/api/logout", (req, res) => {
    res.clearCookie("token", COOKIE_OPTIONS);
    res.status(200).json({ message: "Logout exitoso." });
});

app.get("/api/verify-auth", autenticarToken, (req, res) => {
    res.json({ user: req.usuario });
});


// Archivos PDF
app.post("/api/files", autenticarToken, upload.array("archivosPdf"), async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    try {
        const uid = req.usuario.id;
        const files = req.files;
        if (!files || files.length === 0) return res.status(400).json({ error: "No se subieron archivos." });
        const records = files.map(f => ({ usuario_id: uid, nombre_archivo_unico: f.filename, nombre_archivo_original: f.originalname }));
        const { error } = await supabase.from("archivos_usuario").insert(records);
        if (error) {
            files.forEach(async f => { try { await fs.unlink(f.path); } catch(e){} });
            throw error;
        }
        res.status(200).json({ mensaje: `Se ${files.length > 1 ? 'guardaron' : 'guardó'} ${files.length} archivo(s).` });
    } catch (error) { console.error("[Upload Files Error]", error); next(error); }
});

app.get("/api/files", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    try {
        const { data, error } = await supabase.from("archivos_usuario")
            .select("nombre_archivo_unico, nombre_archivo_original")
            .eq("usuario_id", req.usuario.id)
            .order("fecha_subida", { ascending: false });
        if (error) throw error;
        res.json(data?.map(a => ({ name: a.nombre_archivo_unico, originalName: a.nombre_archivo_original })) || []);
    } catch (error) { console.error("[Get Files Error]", error); next(error); }
});

app.delete("/api/files/:nombreArchivoUnico", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    const { id: idUsuario } = req.usuario; // 'id' es lo que tienes en el payload del token
    const { nombreArchivoUnico } = req.params;
    if (!nombreArchivoUnico) return res.status(400).json({ error: "Falta nombre de archivo." });
    try {
        const { data: archivo, error: findError } = await supabase.from("archivos_usuario")
            .select("id").eq("usuario_id", idUsuario).eq("nombre_archivo_unico", nombreArchivoUnico).single();
        if (findError || !archivo) return res.status(404).json({ error: "Archivo no encontrado o no autorizado." });

        const { error: deleteDbError } = await supabase.from("archivos_usuario").delete().eq("id", archivo.id);
        if (deleteDbError) throw new Error("Error eliminando registro de la BD.");

        const rutaArchivo = path.join(directorioSubidas, nombreArchivoUnico);
        try { await fs.unlink(rutaArchivo); } catch (fsErr) { if(fsErr.code !== 'ENOENT') console.error("Error borrando físico:", fsErr);}

        res.json({ message: "Archivo eliminado." });
    } catch (error) { console.error("[Delete File Error]", error); next(error); }
});


// Conversaciones
app.get("/api/conversations", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    try {
        const { data, error } = await supabase.from("conversaciones").select("id, titulo").eq("usuario_id", req.usuario.id).order("fecha_actualizacion", { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch (error) { console.error("[Get Conversations Error]", error); next(error); }
});

app.get("/api/conversations/:id/messages", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    const { id } = req.params;
    if(!id) return res.status(400).json({error:"Falta ID conversación."});
    try {
        const { data: conv, error: ownerErr } = await supabase.from("conversaciones").select("id").eq("id", id).eq("usuario_id", req.usuario.id).maybeSingle();
        if (ownerErr) throw ownerErr;
        if (!conv) return res.status(404).json({ error: "Conversación no encontrada o no autorizada." });

        const { data: msgs, error: msgErr } = await supabase.from("mensajes").select("rol, texto, fecha_envio").eq("conversacion_id", id).order("fecha_envio", { ascending: true });
        if (msgErr) throw msgErr;
        res.json(msgs || []);
    } catch (error) { console.error("[Get Messages Error]", error); next(error); }
});

app.delete("/api/conversations/:idConv", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    const { idConv } = req.params;
    if(!idConv) return res.status(400).json({error:"Falta ID conversación."});
    try {
        const { error, count } = await supabase.from("conversaciones").delete({ count: 'exact' }).eq("id", idConv).eq("usuario_id", req.usuario.id);
        if (error) throw error;
        res.json({ message: `Conversación ${count > 0 ? 'eliminada' : 'no encontrada/autorizada'}.`, deleted: count > 0 });
    } catch (error) { console.error("[Delete Conversation Error]", error); next(error); }
});

app.put("/api/conversations/:id/title", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    const { id } = req.params;
    const { nuevoTitulo } = req.body;
    if (!id || !nuevoTitulo?.trim()) return res.status(400).json({ error: "Datos inválidos." });
    const tituloLimpio = nuevoTitulo.trim().substring(0, 100);
    try {
        const { error, count } = await supabase.from("conversaciones")
          .update({ titulo: tituloLimpio, fecha_actualizacion: new Date().toISOString() })
          .eq("id", id).eq("usuario_id", req.usuario.id)
          .select({ count: 'exact' });
        if (error) throw error;
        if (count === 0) return res.status(404).json({ error: "Conversación no encontrada o no autorizada." });
        res.status(200).json({ message: "Título actualizado." });
    } catch (error) { console.error("[Update Title Error]", error); next(error); }
});


// --- Rutas Principales de IA (Texto/Imagen) ---

app.post("/api/generateText", autenticarToken, subirPdf, async (req, res, next) => {
    if (!supabase || !clienteIA) return res.status(503).json({ error: "Servicio BD o IA no disponible." });

    const usuarioId = req.usuario.id;
    const { prompt, conversationId: inputConversationId, modeloSeleccionado, temperatura, topP, idioma, archivosSeleccionados } = req.body;
    let archivosSeleccionadosArray = [];
    try { if (archivosSeleccionados) archivosSeleccionadosArray = JSON.parse(archivosSeleccionados || "[]"); if (!Array.isArray(archivosSeleccionadosArray)) throw new Error();}
    catch (e) { return res.status(400).json({ error: "Formato archivosSeleccionados inválido."});}

    let conversationId = inputConversationId;
    let isNewConversation = false;

    try {
        if (!conversationId) {
            const titulo = (prompt || "Chat con PDF").trim().split(/\s+/).slice(0, 5).join(" ") || "Nuevo Chat";
            const {data: convData, error: convErr} = await supabase.from("conversaciones").insert([{usuario_id: usuarioId, titulo }]).select("id").single();
            if (convErr) throw new Error(`Error creando conversación: ${convErr.message}`);
            conversationId = convData.id; isNewConversation = true;
        }

        if (prompt) { await supabase.from("mensajes").insert([{ conversacion_id: conversationId, rol: "user", texto: prompt }]).catch(e => console.error("Error guardando msg user:",e)); }

        const archivosNuevos = req.files || [];
        if (archivosNuevos.length > 0) {
            const records = archivosNuevos.map(f=>({usuario_id:usuarioId, nombre_archivo_unico:f.filename, nombre_archivo_original:f.originalname}));
            const {error: fErr} = await supabase.from("archivos_usuario").insert(records);
            if (fErr) { archivosNuevos.forEach(async f => {try{await fs.unlink(f.path);}catch(e){}}); throw new Error("Error guardando info PDF."); }
        }

        const archivosCtx = [...archivosSeleccionadosArray, ...archivosNuevos.map(f => f.filename)].filter(Boolean);
        let contextoPDF = ""; if(archivosCtx.length > 0){ contextoPDF = await generarContextoPDF(usuarioId, archivosCtx); }

        if (!prompt && !contextoPDF) { return res.status(400).json({ error: "Se requiere prompt o archivos PDF." }); }

        const { data: hist, error: histErr } = await supabase.from("mensajes").select("rol, texto").eq("conversacion_id", conversationId).order("fecha_envio", { ascending: true });
        if(histErr) throw new Error(`Error cargando historial: ${histErr.message}`);

        const promptReal = prompt || (idioma === 'es' ? "Resume los archivos." : "Summarize files.");
        const respIA = await generarRespuestaIA( promptReal, hist || [], contextoPDF, modeloSeleccionado, parseFloat(temperatura), parseFloat(topP), idioma );

        await supabase.from("mensajes").insert([{ conversacion_id: conversationId, rol: "model", texto: respIA }]).catch(e => console.error("Error guardando msg model:", e));

        res.status(200).json({ respuesta: respIA, isNewConversation, conversationId });

    } catch (error) { next(error); }
});

app.post("/api/generateImage", autenticarToken, async (req, res, next) => {
    const { prompt } = req.body;
    if (!prompt?.trim()) return res.status(400).json({ error: "Prompt inválido." });
    if (!CLIPDROP_API_KEY) return res.status(503).json({ error: "Servicio de imágenes no configurado." });

    try {
        const resultado = await generarImagenClipdrop(prompt.trim());
        res.status(200).json({ message: "Imagen generada.", fileName: resultado.fileName, imageUrl: resultado.url });
    } catch (error) { next(error); }
});

// --- Servir Archivos Estáticos ---
app.use('/generated_images', express.static(directorioImagenesGeneradas, { maxAge: '1h' }));

// --- Manejador de Errores Global ---
app.use((err, req, res, next) => {
  console.error("‼️ Global Error Handler:", err.status || '(no status)', err.message);
  if (isDev && err.stack) { console.error(err.stack); }
  if (res.headersSent) { return next(err); }

  let statusCode = err.status || (err instanceof multer.MulterError ? 400 : 500);
  let mensajeUsuario = err.message || "Error interno del servidor.";

  if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') { statusCode = 413; mensajeUsuario = `Archivo grande (Máx: ${TAMANO_MAX_ARCHIVO_MB} MB).`; }
      else if (err.message === 'Solo se permiten archivos PDF.') { statusCode = 400; /* mensaje ya es bueno */ }
      else { statusCode = 400; mensajeUsuario = `Error subida: ${err.field || ''} ${err.code}`; }
  } else if (err instanceof SyntaxError && statusCode === 400 && "body" in err) {
      mensajeUsuario = "Petición JSON mal formada.";
  } else if (err.message.includes("no disponible")) {
      statusCode = 503;
  } else if (err.message.includes("autenticación") || err.message.includes("permisos")) {
      statusCode = 401;
  } else if (err.message.includes("Límite") || err.message.includes("pago")) {
      statusCode = 402; mensajeUsuario = "Límite de uso gratuito alcanzado.";
  } else if (err.message.includes("Demasiadas solicitudes") || err.message.includes("sobrecargado") || err.message.includes("Too Many Requests")) {
      statusCode = 429; mensajeUsuario = "Servicio externo ocupado. Intente más tarde.";
  } else if (err.message.includes("inválido") || err.message.includes("requerido por Clipdrop")) { // Captura "El prompt es requerido por Clipdrop."
        statusCode = 400;
  } else if (statusCode === 500 && mensajeUsuario.includes("fetch")) {
        mensajeUsuario = "Error de red contactando servicio externo.";
  } else if (err.message.includes("404") || err.message.includes("no encontrado")) {
        statusCode = 404;
        mensajeUsuario = "Recurso solicitado no encontrado.";
  }

  res.status(statusCode).json({ error: mensajeUsuario });
});

// --- Iniciar Servidor ---
const PORT = PUERTO || 3001;
app.listen(PORT, () => {
    console.log(`\n🚀 Servidor corriendo en puerto ${PORT} | ${isDev ? 'MODO DESARROLLO' : 'MODO PRODUCCIÓN'}`);
    console.log(`🔗 Acceso local: http://localhost:${PORT}`);
    console.log(`📂 Dir uploads: ${directorioSubidas}`);
    console.log(`🖼️ Dir generated_images: ${directorioImagenesGeneradas}`);
    console.log(`\n--- Estado Servicios ---`);
    console.log(` Supabase: ${supabase ? '✅ OK' : '❌ NO OK'}`);
    console.log(` Google GenAI: ${clienteIA ? '✅ OK' : '❌ NO OK (Verificar API_KEY)'}`);
    console.log(` Clipdrop Imagen: ${CLIPDROP_API_KEY ? '✅ OK (Key presente)' : '❌ NO OK (Verificar CLIPDROP_API_KEY)'}`);
    console.log(`----------------------\n`);
});