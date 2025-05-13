// --- Imports ---
import { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } from "@google/generative-ai";
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
import FormDataNode from "form-data";
import axios from 'axios';

// --- Definiciones de Directorio ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const directorioSubidasPdf = path.join(__dirname, "pdf_uploads_temp");

// --- Carga de Variables de Entorno ---
dotenv.config();
const {
  PORT: PUERTO = 3001, API_KEY, JWT_SECRET, NODE_ENV = "development",
  SUPABASE_URL, SUPABASE_KEY, CLIPDROP_API_KEY,
} = process.env;

const isDev = NODE_ENV !== "production";

// --- Constantes y Configuraciones ---
const COOKIE_OPTIONS = { httpOnly: true, secure: !isDev, sameSite: isDev ? "lax" : "none", maxAge: 3600 * 1000, path: "/" };
const TAMANO_MAX_ARCHIVO_MB = 20;
const MAX_CARACTERES_POR_PDF_CONTEXTO = 7000;
const MAX_LONGITUD_CONTEXTO_TOTAL_IA = 28000;
const MODELOS_PERMITIDOS_GEMINI = ["gemini-1.5-flash-latest", "gemini-pro"];
const MODELO_POR_DEFECTO_GEMINI = "gemini-1.5-flash-latest";
const TEMP_POR_DEFECTO = 0.6;
const TOPP_POR_DEFECTO = 0.9;
const IDIOMA_POR_DEFECTO = "es";
const JWT_OPTIONS = { expiresIn: "1h" };

// --- Verificaciones de Startup ---
console.log("[Startup] JWT_SECRET:", JWT_SECRET ? `${JWT_SECRET.substring(0,3)}... (long: ${JWT_SECRET.length})` : "¡NO CARGADO!");
if (!JWT_SECRET || JWT_SECRET.length < 32) console.warn("⚠️ JWT_SECRET no definido o inseguro!");
if (!API_KEY) console.warn("⚠️ API_KEY (Google GenAI) no configurada.");
if (!SUPABASE_URL || !SUPABASE_KEY) console.warn("⚠️ SUPABASE_URL o SUPABASE_KEY no configuradas.");
if (!CLIPDROP_API_KEY) console.warn("⚠️ CLIPDROP_API_KEY (para imágenes) no configurada.");

const app = express();

// --- Inicialización de Clientes ---
let clienteIA;
if (API_KEY) { try { clienteIA = new GoogleGenerativeAI(API_KEY); console.log("✅ GoogleGenerativeAI creado."); } catch (e) { console.error("🚨 Error GoogleGenerativeAI:", e.message); clienteIA = null;}}
else { clienteIA = null; console.warn("⚠️ GoogleGenerativeAI NO inicializado (sin API_KEY)."); }

let supabase;
if (SUPABASE_URL && SUPABASE_KEY) { try { supabase = createClient(SUPABASE_URL, SUPABASE_KEY); console.log("✅ Supabase client creado."); } catch (e) { console.error("🚨 Error Supabase client:", e.message); supabase = null; }}
else { supabase = null; console.warn("⚠️ Supabase NO inicializado (sin URL/KEY).");}

// --- CONFIGURACIÓN DE CORS ---
const allowedOrigins = ['https://chat-bot-jwpc.onrender.com'];
if (isDev) { allowedOrigins.push('http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:5173'); } // Añadir IP para algunos setups de Vite
app.use(cors({
    origin: function (origin, callback) {
      if (!origin && (isDev || NODE_ENV === 'test')) return callback(null, true); 
      if (!origin && !isDev && NODE_ENV !== 'test') { console.warn(`🚫 CORS: Petición sin origen RECHAZADA en producción`); return callback(new Error('Peticiones sin origen no permitidas en producción'));}
      
      console.log("🌍 Solicitud CORS desde:", origin);
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.warn(`🚫 CORS: Origen ${origin} NO PERMITIDO.`);
        callback(new Error(`El origen ${origin} no está permitido por la política CORS.`));
      }
    },
    credentials: true, methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization','Accept','X-Requested-With'], optionsSuccessStatus: 204
}));

// --- Middlewares Generales ---
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// --- Crear Directorio PDF ---
if (!existsSync(directorioSubidasPdf)) { try { mkdirSync(directorioSubidasPdf, { recursive: true }); console.log(`✅ Dir PDF Creado: ${directorioSubidasPdf}`); } catch (e) { console.error(`🚨 Crear Dir PDF ${directorioSubidasPdf}:`, e); }}
else console.log(`➡️ Dir PDF existe: ${directorioSubidasPdf}`);

// --- Autenticación ---
const autenticarToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) { console.log("[Auth] Fail: No token cookie."); return res.status(401).json({ error: "Token no proporcionado. Inicie sesión de nuevo." });}
    if (!JWT_SECRET) { console.error("CRITICAL: JWT_SECRET no está configurado."); return res.status(500).json({ error: "Error de configuración de autenticación en el servidor." }); }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            const isExpired = err.name === "TokenExpiredError";
            console.error(`[Auth] Fail: Token verify error (${err.name})${isExpired ? " - Expired" : ""}.`);
            if (isExpired) res.clearCookie("token", COOKIE_OPTIONS);
            return res.status(isExpired ? 401 : 403).json({ error: isExpired ? "Token expirado. Inicie sesión de nuevo." : "Token inválido." });
        }
        req.usuario = user; next();
    });
};

// --- Multer ---
const almacenamientoPdf = multer.diskStorage({
    destination: directorioSubidasPdf,
    filename: (req, file, cb) => {
        const sufijo = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
        const nombre = file.originalname.normalize("NFD").replace(/[\u0300-\u036f]/g,"").replace(/[^a-zA-Z0-9.\-_]/gi,'_');
        cb(null, `${sufijo}-${path.basename(nombre, path.extname(nombre))}${path.extname(nombre)||'.pdf'}`);
    },
});
const uploadPdfMiddleware = multer({
  storage: almacenamientoPdf, limits: { fileSize: TAMANO_MAX_ARCHIVO_MB*1024*1024 },
  fileFilter: (r,f,cb) => f.mimetype==="application/pdf"?cb(null,true):(console.warn(`⚠️ Multer: Rechazado ${f.originalname}`),cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE','Solo PDF.'),false))
}).array("archivosPdf", 5);


// --- Funciones Auxiliares ---
async function extraerTextoDePDF(rutaArchivo) {
  console.log(`[PDF Extract] Leyendo: ${path.basename(rutaArchivo)}`);
  if (!existsSync(rutaArchivo)) { console.error(`[PDF Extract] NO EXISTE: ${rutaArchivo}`); return { texto: null, error: `Archivo no hallado en servidor: ${path.basename(rutaArchivo)}`};}
  try {
    const buffer = await fs.readFile(rutaArchivo);
    const datos = await pdfParse(buffer);
    const textoExtraido = datos?.text?.trim() || "";
    if(!textoExtraido) console.warn(`[PDF Extract] Texto vacío para ${path.basename(rutaArchivo)}`);
    return { texto: textoExtraido, error: null };
  } catch (e) { console.error(`[PDF Extract] Error parseando ${path.basename(rutaArchivo)}:`, e.message); return { texto: null, error: `Error parseo PDF: ${e.message}`};}
}

async function generarContextoPDF(idUsuario, nombresArchivosUnicos) {
  if (!idUsuario || !nombresArchivosUnicos?.length) return "";
  if (!supabase) { console.warn("[Context PDF] Supabase no disponible para contexto."); return "[Error: DB no disponible para contexto PDF]";}
  console.log(`[Context PDF] Generando para user ${idUsuario}, archivos: ${nombresArchivosUnicos.join(', ')}`);
  let textoTotal = "";
  try {
    const { data:archivos, error:dbErr } = await supabase.from("archivos_usuario").select("nombre_archivo_unico,nombre_archivo_original").eq("usuario_id",idUsuario).in("nombre_archivo_unico",nombresArchivosUnicos);
    if (dbErr) { console.error("[Context PDF] Supabase error archivos:", dbErr.message); return "[Error DB recuperando archivos]"; }
    if (!archivos?.length) { console.warn(`[Context PDF] No hay archivos en DB para user ${idUsuario} con ${nombresArchivosUnicos.join()}`); return "";}

    for (const {nombre_archivo_unico: unico, nombre_archivo_original: original} of archivos) {
      const ruta = path.join(directorioSubidasPdf, unico);
      const {texto,error} = await extraerTextoDePDF(ruta);
      if (error || !texto) textoTotal += `\n\n[Documento: ${original}]\n[ERROR: El contenido de este documento no pudo ser procesado o está vacío.]\n[Fin del documento: ${original}]\n\n`;
      else textoTotal += `\n\n[Inicio del documento: ${original}]\n${texto.substring(0,MAX_CARACTERES_POR_PDF_CONTEXTO)}\n[Fin del documento: ${original}]\n\n`;
    }
    if (textoTotal.length > MAX_LONGITUD_CONTEXTO_TOTAL_IA) {
        console.warn(`[Context PDF] Contexto PDF total truncado a ${MAX_LONGITUD_CONTEXTO_TOTAL_IA} caracteres.`);
        return textoTotal.substring(0, MAX_LONGITUD_CONTEXTO_TOTAL_IA) + "...(contexto total truncado)";
    }
    return textoTotal.trim();
  } catch(e) { console.error("[Context PDF] Excepción general:",e.message); return "[Error procesando PDFs para contexto]";}
}

async function generarRespuestaIA( prompt, historialDB, textoPDF, modeloReq, temp, topP, lang) {
    if (!clienteIA && NODE_ENV !== 'test') throw new Error("Servicio IA (Google GenAI) no disponible.");
    if (NODE_ENV === 'test' && !clienteIA) return "Test AI Response. PDF Context: " + (textoPDF ? "Yes" : "No");
    
    const modelName = MODELOS_PERMITIDOS_GEMINI.includes(modeloReq) ? modeloReq : MODELO_POR_DEFECTO_GEMINI;
    const generationConfig = { temperature:parseFloat(temp)||TEMP_POR_DEFECTO, topP:parseFloat(topP)||TOPP_POR_DEFECTO };
    const safetySettings = Object.values(HarmCategory).map(category => ({ category, threshold: HarmBlockThreshold.BLOCK_NONE }));
    
    const idioma = ["es","en"].includes(lang)?lang:IDIOMA_POR_DEFECTO;
    const langStrings = idioma === "en" ? 
        { systemBase: "You are a helpful and concise assistant. Answer in Markdown format.", systemPdf: `Based *only* on the provided Reference Text, answer the question. If the answer is not in the text, clearly state that. Use Markdown format.\n\nReference Text (Context):\n"""\n{CONTEXT}\n"""\n\nQuestion:`, error: "AI Error: Could not generate response." } : 
        { systemBase: "Eres un asistente conversacional útil y conciso. Responde en formato Markdown.", systemPdf: `Basándote *únicamente* en el Texto de Referencia proporcionado, responde la pregunta. Si la respuesta no está en el texto, indícalo claramente. Usa formato Markdown.\n\nTexto de Referencia (Contexto):\n"""\n{CONTEXT}\n"""\n\nPregunta:`, error: "Error IA: No se pudo generar respuesta." };

    let systemInstructionForPrompt = langStrings.systemBase;
    if (textoPDF && textoPDF.trim() !== "") {
        systemInstructionForPrompt = langStrings.systemPdf.replace("{CONTEXT}", textoPDF.trim());
    }
    
    const geminiHistory = (historialDB || [])
        .filter(m => m.texto?.trim() && !m.isImage)
        .map(m => ({ role: m.rol, parts: [{ text: m.texto }] }));

    const currentPromptWithInstructions = `${systemInstructionForPrompt} ${prompt}`;
    let requestContents = [...geminiHistory, { role: "user", parts: [{ text: currentPromptWithInstructions }] }];
    // Gemini puede ser sensible al orden exacto user/model.
    // Si el historial está vacío o termina en "model", la nueva parte "user" está bien.
    // Si el historial termina en "user", estrictamente, debería ir un "model" antes de otro "user".
    // Simplificamos, asumiendo que si hay un historial, el último prompt se añade como una nueva parte de usuario.

    console.log(`[Gen IA] Enviando ${requestContents.length} turnos a Gemini (${modelName}). Prompt: "${prompt.substring(0,50)}..."`);
    try {
        const model = clienteIA.getGenerativeModel({model:modelName, safetySettings, generationConfig});
        const result = await model.generateContent({contents:requestContents});
        const response = result.response; const candidate = response?.candidates?.[0];
        if (candidate?.content?.parts?.[0]?.text) { console.log("[Gen IA] Respuesta de Gemini recibida."); return candidate.content.parts[0].text.trim(); }
        const br=response?.promptFeedback?.blockReason, fr=candidate?.finishReason, sr=candidate?.safetyRatings?.map(r=>`${r.category}:${r.probability}`).join();
        const eD=`No válida. ${br?`Bloq:${br}. `:""}${fr&&fr!=="STOP"?`Fin:${fr}. `:""}${sr?`Safe:[${sr}]`:""}`;
        console.warn(`[Gen IA] ⚠️ ${eD}`); throw new Error(`${langStrings.error} (IA: ${eD})`);
    } catch (e) { console.error(`[Gen IA] ❌ Error API Gemini (${modelName}):`, e.message, e.stack); throw new Error(`${langStrings.error} (API: ${e.message||"Desconocido"})`);}
}

async function generarImagenClipdropYSubirASupabase(promptTexto) {
    if (!CLIPDROP_API_KEY) throw new Error("Servicio de imágenes (Clipdrop) no disponible: Falta API key.");
    if (!promptTexto?.trim()) throw new Error("Prompt inválido para generar imagen con Clipdrop.");
    if (!supabase) throw new Error("Cliente Supabase no disponible para subir la imagen generada.");

    const CLIPDROP_API_URL = "https://clipdrop-api.co/text-to-image/v1";
    console.log(`[Img Gen Clipdrop] Solicitando imagen para prompt: "${promptTexto}"`);

    const form = new FormDataNode();
    form.append('prompt', promptTexto.trim());

    try {
        const response = await axios.post(CLIPDROP_API_URL, form, {
            headers: { 'x-api-key': CLIPDROP_API_KEY, ...form.getHeaders() },
            responseType: 'arraybuffer'
        });

        const bufferImagen = Buffer.from(response.data);
        const tipoMime = response.headers['content-type'] || 'image/png';
        const extension = tipoMime.startsWith('image/png') ? 'png' : (tipoMime.startsWith('image/jpeg') ? 'jpeg' : 'jpg');
        
        const promptSanitizado = promptTexto.trim().substring(0, 30).replace(/[^a-zA-Z0-9_.-]/g, '_').replace(/_{2,}/g, '_');
        const nombreArchivoSupabase = `generated_chat_images/${Date.now()}_${promptSanitizado || 'imagen'}.${extension}`; 

        const BUCKET_NAME = 'generated-images'; // ¡¡¡REEMPLAZA ESTO CON EL NOMBRE DE TU BUCKET!!!

        console.log(`[Img Gen Supabase] Subiendo a bucket '${BUCKET_NAME}', archivo '${nombreArchivoSupabase}'...`);
        const { data: uploadData, error: uploadError } = await supabase.storage
            .from(BUCKET_NAME)
            .upload(nombreArchivoSupabase, bufferImagen, { contentType: tipoMime, upsert: false });

        if (uploadError) {
            console.error(`[Img Gen Supabase] Error subiendo a Supabase Storage:`, uploadError);
            let SUpabaseErrorMsg = `Error al guardar imagen en almacenamiento: ${uploadError.message}`;
            if(uploadError.message?.includes("Duplicate")) SUpabaseErrorMsg = "Error: Ya existe un archivo con el mismo nombre en el almacenamiento. Intente de nuevo."
            else if (uploadError.message?.includes("Unauthorized")) SUpabaseErrorMsg = "Error de autorización con Supabase Storage. Verifique las políticas RLS del bucket."
            throw new Error(SUpabaseErrorMsg);
        }
        console.log(`[Img Gen Supabase] Archivo subido. Path: ${uploadData?.path || nombreArchivoSupabase}`);

        const { data: publicUrlData } = supabase.storage.from(BUCKET_NAME).getPublicUrl(nombreArchivoSupabase);
        if (!publicUrlData || !publicUrlData.publicUrl) {
            console.error("[Img Gen Supabase] Error obteniendo URL pública para:", nombreArchivoSupabase, publicUrlData);
            await supabase.storage.from(BUCKET_NAME).remove([nombreArchivoSupabase]).catch(e => console.error("Error eliminando archivo de Supabase tras fallo de getPublicUrl", e));
            throw new Error("Error al obtener URL de imagen persistente después de la subida exitosa.");
        }
        const supabaseImageUrl = publicUrlData.publicUrl;
        console.log(`[Img Gen Supabase] URL pública obtenida: ${supabaseImageUrl}`);
        return {
            fileName: nombreArchivoSupabase,
            imageUrl: supabaseImageUrl,
            message: `Imagen generada para: "${promptTexto.trim()}"`
        };
    } catch (error) {
        let status = 500; let userFriendlyMessage = "Error desconocido generando o guardando la imagen.";
        if (axios.isAxiosError(error)) {
            if (error.response) {
                status = error.response.status;
                const errorDetailRaw = error.response.data;
                let errorDetail = "Detalle no disponible del servicio de imágenes.";
                if (Buffer.isBuffer(errorDetailRaw)) errorDetail = errorDetailRaw.toString();
                else if (typeof errorDetailRaw === 'object' && errorDetailRaw?.error) errorDetail = errorDetailRaw.error;
                else if (typeof errorDetailRaw === 'string') errorDetail = errorDetailRaw;
                userFriendlyMessage = `Error del servicio Clipdrop (${status}): ${String(errorDetail).substring(0,100)}`;
            } else if (error.request) { userFriendlyMessage = "No se pudo contactar el servicio de Clipdrop."; status = 504; }
            else { userFriendlyMessage = "Error al contactar servicio de imágenes.";}
        } else { userFriendlyMessage = error.message || userFriendlyMessage; if(error.message.includes("autorización")) status = 403;}
        console.error("[generarImagenClipdropYSubirASupabase Catch]:", userFriendlyMessage, error.message, error.stack?.substring(0,300));
        const errorToPropagate = new Error(userFriendlyMessage); errorToPropagate.status = status; throw errorToPropagate;
    }
}

// --- Rutas API ---
// AUTH
app.post("/api/register", async (req, res, next) => {
  if (!supabase) return res.status(503).json({error: "BD no disponible"});
  const { username, password } = req.body;
  if (!username || !password || password.length < 6) return res.status(400).json({ error: "Usuario y contraseña (mín. 6 car.) son requeridos." });
  try {
    const contrasenaHasheada = await bcrypt.hash(password, 10);
    const { data, error } = await supabase.from("usuarios").insert([{ nombre_usuario: username, contrasena_hash: contrasenaHasheada }]).select("id").single();
    if (error) { if (error.code === "23505") return res.status(409).json({ error: "Nombre de usuario ya existe." }); return next(error); }
    res.status(201).json({ message: "Registro exitoso.", userId: data.id });
  } catch (error) { next(error); }
});

app.post("/api/login", async (req, res, next) => {
  if (!supabase) return res.status(503).json({error: "BD no disponible"});
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Usuario y contraseña requeridos." });
  try {
    const { data: usuario, error: userError } = await supabase.from("usuarios").select("id, nombre_usuario, contrasena_hash").eq("nombre_usuario", username).single();
    if (userError || !usuario) return res.status(401).json({ error: "Credenciales inválidas." });
    const passwordCorrecta = await bcrypt.compare(password, usuario.contrasena_hash);
    if (!passwordCorrecta) return res.status(401).json({ error: "Credenciales inválidas." });
    const payload = { id: usuario.id, username: usuario.nombre_usuario };
    if(!JWT_SECRET) { console.error("CRITICAL: JWT_SECRET NO CONFIGURADO."); throw new Error("Error de config. del servidor."); }
    const token = jwt.sign(payload, JWT_SECRET, JWT_OPTIONS);
    res.cookie("token", token, COOKIE_OPTIONS);
    res.json({ message: "Login exitoso.", user: payload });
  } catch (error) { next(error); }
});

app.post("/api/logout", (req, res) => { res.clearCookie("token", COOKIE_OPTIONS); res.status(200).json({ message: "Logout exitoso." }); });
app.get("/api/verify-auth", autenticarToken, (req, res) => res.json({ user: req.usuario }));

// FILES (PDFs del usuario)
app.post("/api/files", autenticarToken, uploadPdfMiddleware.array("archivosPdf", 5), async (req,res,next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    try {
      const usuarioId = req.usuario.id; const archivos = req.files;
      if (!archivos?.length) return res.status(400).json({ error: "No se subieron archivos PDF válidos."});
      const registros = archivos.map(f => ({ usuario_id: usuarioId, nombre_archivo_unico: f.filename, nombre_archivo_original: f.originalname }));
      const { data, error } = await supabase.from("archivos_usuario").insert(registros).select("nombre_archivo_unico, nombre_archivo_original");
      if (error) { archivos.forEach(async f => {try{await fs.unlink(path.join(directorioSubidasPdf, f.filename))}catch(e){console.error("Error limpiando PDF:",e.message)}}); return next(error); }
      res.status(201).json({ mensaje: "Archivos PDF subidos.", archivos: data || [] });
    } catch (error) { next(error); }
});

app.get("/api/files", autenticarToken, async (req,res,next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    try {
      const { data, error } = await supabase.from("archivos_usuario").select("nombre_archivo_unico, nombre_archivo_original").eq("usuario_id", req.usuario.id).order("fecha_subida", { ascending: false });
      if (error) return next(error);
      res.json( (data || []).map(a => ({ name: a.nombre_archivo_unico, originalName: a.nombre_archivo_original })) );
    } catch (error) { next(error); }
});

app.delete("/api/files/:nombreArchivoUnico", autenticarToken, async (req,res,next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const idUsuario = req.usuario.id; const { nombreArchivoUnico } = req.params;
    if(!nombreArchivoUnico) return res.status(400).json({error: "Nombre de archivo no especificado."});
    try {
      const { data: meta, error: metaErr } = await supabase.from("archivos_usuario").select("id").eq("usuario_id", idUsuario).eq("nombre_archivo_unico", nombreArchivoUnico).single();
      if (metaErr || !meta) return res.status(404).json({ error: "Archivo no encontrado o no autorizado." });
      const { error: delErr } = await supabase.from("archivos_usuario").delete().eq("id", meta.id);
      if (delErr) throw new Error(`Eliminando de DB: ${delErr.message}`);
      try { await fs.unlink(path.join(directorioSubidasPdf, nombreArchivoUnico)); console.log(`[File Delete] Disco OK: ${nombreArchivoUnico}`);}
      catch (fsErr) { if(fsErr.code !== "ENOENT") console.error(`[File Delete] Error FS: ${fsErr.message}`); else console.log(`[File Delete] Disco: no existía (ENOENT) ${nombreArchivoUnico}`);}
      res.json({ message: "Archivo eliminado." });
    } catch (err) { next(err); }
});

// CONVERSATIONS (Metadata)
app.get("/api/conversations", autenticarToken, async (req,res,next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    try {
        const { data, error } = await supabase.from("conversaciones").select("id, titulo").eq("usuario_id", req.usuario.id).order("fecha_actualizacion", { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch(error) { next(error); }
});
app.put("/api/conversations/:id/title", autenticarToken, async (req,res,next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const { id } = req.params; const convIdNum = parseInt(id, 10);
    if(isNaN(convIdNum)) return res.status(400).json({error: "ID de conversación inválido."});
    const { nuevoTitulo } = req.body;
    if (!nuevoTitulo?.trim()) return res.status(400).json({ error: "Título no válido." });
    try {
        const { error } = await supabase.from("conversaciones").update({ titulo: nuevoTitulo.trim().substring(0,100), fecha_actualizacion:new Date().toISOString() }).eq("id", convIdNum).eq("usuario_id", req.usuario.id);
        if (error) throw error;
        res.status(200).json({ message: "Título actualizado." });
    } catch(err) { next(err); }
});
app.delete("/api/conversations/:idConv", autenticarToken, async (req,res,next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const { idConv } = req.params; const convIdNum = parseInt(idConv, 10);
    if(isNaN(convIdNum)) return res.status(400).json({error: "ID de conversación inválido."});
    try {
        const { error } = await supabase.from("conversaciones").delete().eq("id", convIdNum).eq("usuario_id", req.usuario.id);
        if (error) throw error;
        res.json({ message: "Conversación eliminada." });
    } catch(err) { next(err); }
});

// MESSAGES (Contenido de una conversación)
app.get( "/api/conversations/:id/messages", autenticarToken, async (req, res, next) => {
    console.log(`[GET /messages] Solicitado para conv ID: ${req.params.id}, User: ${req.usuario.id}`);
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const { id } = req.params; const conversationIdNum = parseInt(id, 10);
    if (isNaN(conversationIdNum)) return res.status(400).json({error:"ID de conversación inválido."})
    try {
      const { data: convOwner, error: ownerError } = await supabase.from("conversaciones").select("id").eq("id", conversationIdNum).eq("usuario_id", req.usuario.id).maybeSingle();
      if(ownerError) { console.error("[GET /messages] Error owner check:", ownerError.message); throw ownerError; }
      if (!convOwner) { console.warn("[GET /messages] Owner check failed for conv:", conversationIdNum); return res.status(404).json({ error: "Conversación no encontrada o no autorizada." });}
      const { data: mensajes, error: messagesError } = await supabase.from("mensajes").select("rol, texto, fecha_envio, imageUrl, isImage, fileName").eq("conversacion_id", conversationIdNum).order("fecha_envio", { ascending: true });
      if (messagesError) { console.error("[GET /messages] Error fetching messages:", messagesError.message); throw messagesError; }
      if (mensajes?.some(m=>m.isImage)) console.log(`[GET /messages] Devolviendo ${mensajes.length} mensajes. Imágenes encontradas: ${mensajes.filter(m=>m.isImage).length}`);
      res.json(mensajes || []);
    } catch (error) { next(error); }
});

app.post("/api/conversations/:id/messages", autenticarToken, async (req, res, next) => {
    console.log(`[POST /messages] Inicio. Conv ID param: ${req.params.id}. User: ${req.usuario.id}`);
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    const { id: conversacion_id_str } = req.params; const conversacion_id_num = parseInt(conversacion_id_str, 10);
    if (isNaN(conversacion_id_num)) return res.status(400).json({ error: "ID de conversación inválido." });
    const usuario_id = req.usuario.id;
    const { rol, texto, imageUrl, fileName, isImage } = req.body;
    console.log(`[POST /messages] Body recibido:`, {rol, texto:texto?.substring(0,20)+'...', imageUrl, fileName, isImage});
    if (!rol || (rol !== "user" && rol !== "model")) return res.status(400).json({ error: "Rol de mensaje inválido." });
    if (isImage === true && (!imageUrl || typeof imageUrl !== 'string')) return res.status(400).json({ error: "imageUrl (string) es requerida para mensajes de imagen." });
    try {
        const { data: convData, error: convError } = await supabase.from("conversaciones").select("id").eq("id", conversacion_id_num).eq("usuario_id", usuario_id).single();
        if (convError || !convData) { console.warn(`[POST /messages] Conv no encontrada/auth fallida. User: ${usuario_id}, Conv: ${conversacion_id_num}`, convError?.message); return res.status(404).json({ error: "Conversación no encontrada o no tienes acceso." });}
        const mensajeAGuardar = { conversacion_id:conversacion_id_num, rol, texto:texto||null, imageUrl:isImage===true?(imageUrl||null):null, fileName:isImage===true?(fileName||null):null, isImage:isImage===true };
        console.log("[POST /messages] Insertando en 'mensajes':", mensajeAGuardar);
        const { data: msgInsertado, error: insertError } = await supabase.from("mensajes").insert([mensajeAGuardar]).select().single();
        if (insertError) { console.error(`[POST /messages] Error Supabase al insertar:`, insertError); throw insertError; }
        console.log(`[POST /messages] Mensaje guardado:`, msgInsertado);
        res.status(201).json(msgInsertado);
    } catch (error) { next(error); }
});

// GENERATE TEXT
app.post("/api/generateText", autenticarToken, uploadPdfMiddleware.array("archivosPdf", 5), async (req, res, next) => {
    console.log("[POST /api/generateText] Iniciado. User:", req.usuario.id);
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    if (!clienteIA && NODE_ENV !== 'test') return res.status(503).json({ error: "Servicio IA no disponible."});

    const usuarioId = req.usuario.id;
    const { prompt, conversationId: inputConvIdStr, modeloSeleccionado, temperatura, topP, idioma, archivosSeleccionados } = req.body;
    let conversationId = inputConvIdStr ? parseInt(inputConvIdStr, 10) : null;
    if (inputConvIdStr && isNaN(conversationId)) return res.status(400).json({error: "ID de conversación inválido."});
    let archivosSelNombres = [];
    if(archivosSeleccionados) {try{archivosSelNombres=typeof archivosSeleccionados==='string'?JSON.parse(archivosSeleccionados):archivosSeleccionados;if(!Array.isArray(archivosSelNombres))archivosSelNombres=[];}catch(e){return res.status(400).json({error:"archivosSeleccionados inválido."});}}
    let isNewConv = false; const nuevosArchivosSubidos = [];

    try {
        if (!conversationId) {
            const titulo = (prompt?.trim()||"Chat PDF").substring(0,30).split(/\s+/).slice(0,5).join(" ")||"Nueva";
            const {data:nConv,error:cErr} = await supabase.from("conversaciones").insert([{usuario_id:usuarioId,titulo}]).select("id").single();
            if(cErr) throw new Error(`Creando conv: ${cErr.message}`);
            conversationId=nConv.id; isNewConv=true; console.log(`[GenText] Nueva conv ID: ${conversationId}`);
        }
        if(prompt?.trim()) { const {error:uErr} = await supabase.from("mensajes").insert([{conversacion_id:conversationId,rol:"user",texto:prompt.trim(),isImage:false}]); if(uErr) console.warn("Err guardando msg user:",uErr.message);}
        
        const pdfsNuevos = req.files || [];
        if(pdfsNuevos.length > 0){
            const regs = pdfsNuevos.map(f=>({usuario_id:usuarioId,nombre_archivo_unico:f.filename,nombre_archivo_original:f.originalname}));
            const {error:fErr} = await supabase.from("archivos_usuario").insert(regs);
            if(fErr){pdfsNuevos.forEach(async f=>{try{await fs.unlink(path.join(directorioSubidasPdf,f.filename))}catch(e){}}); throw new Error("Err guardando metadata PDF:"+fErr.message);}
            pdfsNuevos.forEach(f=>nuevosArchivosSubidos.push({name:f.filename,originalName:f.originalname}));
        }
        const archivosCtx = [...archivosSelNombres, ...pdfsNuevos.map(f=>f.filename)].filter(Boolean);
        const ctxPDF = archivosCtx.length>0 ? await generarContextoPDF(usuarioId,archivosCtx) : "";
        if(!prompt?.trim() && (!ctxPDF || ctxPDF.startsWith("[Error")) && !archivosCtx.length) return res.status(400).json({error:"Prompt o PDFs válidos requeridos."});
        
        const {data:histDB,error:hErr} = await supabase.from("mensajes").select("rol,texto,imageUrl,isImage").eq("conversacion_id",conversationId).order("fecha_envio",{ascending:true});
        if(hErr) throw new Error(`Err cargando hist: ${hErr.message}`);
        
        const promptIA = prompt?.trim()||(ctxPDF?(idioma==='es'?"Resume docs.":"Summarize docs."):"Hola.");
        const respIA = await generarRespuestaIA(promptIA,histDB,ctxPDF,modeloSeleccionado,temperatura,topP,idioma);
        
        if(respIA && typeof respIA ==='string' && !respIA.toLowerCase().includes("error ia:")){
            const{error:mErr} = await supabase.from("mensajes").insert([{conversacion_id:conversationId,rol:"model",texto:respIA,isImage:false}]);
            if(mErr) console.warn("[GenText] Err guardando resp modelo:",mErr.message);
        }
        res.json({respuesta:respIA, isNewConversation:isNewConv, conversationId, archivosSubidosNuevos:nuevosArchivosSubidos});
    } catch(e){next(e);}
});

// GENERATE IMAGE
app.post("/api/generateImage", autenticarToken, async (req,res,next) => {
    console.log("[POST /api/generateImage] User:", req.usuario.id);
    const {prompt}=req.body; if(!prompt?.trim())return res.status(400).json({error:"Prompt inválido."});
    try { const rImg = await generarImagenClipdropYSubirASupabase(prompt.trim()); res.json(rImg); }
    catch(e){next(e);}
});

// --- Manejador de Errores Global ---
app.use((err, req, res, next) => {
  console.error("‼️ Global Error Handler:", err.message, (NODE_ENV !== "production" && err.stack) ? err.stack.substring(0, 500) + "..." : "");
  if (res.headersSent) return next(err);
  let statusCode = err.status || (axios.isAxiosError(err) && err.response?.status) || 500;
  let message = err.message || "Error interno del servidor.";

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

 if (err instanceof SyntaxError && err.status === 400 && "body" in err) { statusCode = 400; message = "JSON mal formado."; }
  res.status(statusCode).json({ error: message });
});

// --- Iniciar Servidor ---
app.listen(PUERTO, () => {
    console.log(`\n🚀 Servidor en puerto ${PUERTO} | Modo: ${NODE_ENV}`);
    console.log(`🔗 Local: http://localhost:${PUERTO}`);
    console.log(`\n--- Estado Servicios Configurados ---`);
    console.log(` Supabase: ${supabase ? '✅ OK' : '❌ NO OK (Verificar SUPABASE_URL/KEY)'}`);
    console.log(` Google GenAI: ${clienteIA ? '✅ OK' : '❌ NO OK (Verificar API_KEY)'}`);
    console.log(` Clipdrop Imagen: ${CLIPDROP_API_KEY ? '✅ OK' : '❌ NO OK (Verificar CLIPDROP_API_KEY)'}`);
    console.log(` JWT Secret: ${JWT_SECRET && JWT_SECRET.length >=32 ? '✅ OK' : '❌ NO OK (INSEGURO o NO CONFIGURADO)'}`);
    console.log(`---------------------------------\n`);
});