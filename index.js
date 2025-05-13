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
import FormDataNode from "form-data";
import axios from 'axios';

// --- Definiciones de Directorio ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const directorioSubidasPdf = path.join(__dirname, "pdf_uploads"); // Solo para PDFs temporales

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


// --- CONFIGURACIÓN DE CORS (MUY ARRIBA) ---
const allowedOrigins = [
    'https://chat-bot-jwpc.onrender.com',
    // Descomenta y ajusta para desarrollo local si es necesario
    // 'http://localhost:3000', 
    // 'http://localhost:5173', 
];
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin && (isDev || NODE_ENV === 'test')) return callback(null, true); 
      if (!origin && !isDev && NODE_ENV !== 'test') return callback(new Error('Peticiones sin origen no permitidas en producción'));
      
      console.log("🌍 Solicitud CORS desde:", origin);
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.warn(`🚫 CORS: Origen ${origin} no permitido.`);
        callback(new Error('Origen no permitido por CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    optionsSuccessStatus: 204
  })
);

// --- Middlewares Generales ---
app.use(cookieParser());
app.use(express.json({ limit: '10mb' })); // Para JSON bodies

// --- Crear Directorios Necesarios ---
if (!existsSync(directorioSubidasPdf)) {
    try { mkdirSync(directorioSubidasPdf, { recursive: true }); console.log(`✅ Dir PDF Creado: ${directorioSubidasPdf}`); }
    catch (e) { console.error(`🚨 No se pudo crear dir PDF ${directorioSubidasPdf}:`, e); }
} else console.log(`➡️ Dir PDF Existe: ${directorioSubidasPdf}`);

// --- Autenticación ---
const autenticarToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) { console.log("[Auth] Fail: No token cookie."); return res.status(401).json({ error: "Token no proporcionado" });}
    if (!JWT_SECRET) { console.error("CRITICAL: JWT_SECRET no está configurado."); return res.status(500).json({ error: "Error de configuración de autenticación en el servidor." }); }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            const isExpired = err.name === "TokenExpiredError";
            console.error(`[Auth] Fail: Token verify error (${err.name})${isExpired ? " - Expired" : ""}.`);
            if (isExpired) res.clearCookie("token", COOKIE_OPTIONS);
            return res.status(isExpired ? 401 : 403).json({ error: isExpired ? "Token expirado" : "Token inválido" });
        }
        req.usuario = user;
        next();
    });
};

// --- Multer (para PDFs) ---
const almacenamientoPdf = multer.diskStorage({
    destination: directorioSubidasPdf,
    filename: (req, file, cb) => {
        const sufijo = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
        const nombreOriginalLimpio = file.originalname.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9.\-_]/gi, '_');
        const extension = path.extname(nombreOriginalLimpio) || '.pdf';
        const baseName = path.basename(nombreOriginalLimpio, path.extname(nombreOriginalLimpio));
        cb(null, `${sufijo}-${baseName}${extension}`);
    },
});
const uploadPdfMiddleware = multer({
  storage: almacenamientoPdf,
  limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "application/pdf") {
        cb(null, true);
    } else {
      console.warn( `⚠️ Multer: Rechazado archivo no PDF: ${file.originalname} (${file.mimetype})`);
      cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', 'Solo se permiten archivos PDF.'), false);
    }
  },
});

// --- Funciones Auxiliares ---
async function extraerTextoDePDF(rutaArchivo) {
  // ... (PEGA AQUÍ TU FUNCIÓN COMPLETA Y FUNCIONAL) ...
  console.warn("[ extraerTextoDePDF ] Usando placeholder. Implementa tu lógica.");
  if (!existsSync(rutaArchivo)) return { texto: null, error: "Archivo no encontrado (placeholder)"};
  return { texto: "Texto extraído (placeholder) de " + path.basename(rutaArchivo), error: null };
}

async function generarContextoPDF(idUsuario, nombresArchivosUnicos) {
  // ... (PEGA AQUÍ TU FUNCIÓN COMPLETA Y FUNCIONAL) ...
  console.warn("[ generarContextoPDF ] Usando placeholder. Implementa tu lógica.");
  if (!idUsuario || !nombresArchivosUnicos || nombresArchivosUnicos.length === 0) return "";
  return `Contexto PDF simulado para usuario ${idUsuario} y archivos: ${nombresArchivosUnicos.join(', ')}`;
}

async function generarRespuestaIA( prompt, historialDB, textoPDF, modeloReq, temp, topP, lang) {
  // ... (PEGA AQUÍ TU FUNCIÓN COMPLETA Y FUNCIONAL DE GEMINI) ...
  console.warn("[ generarRespuestaIA ] Usando placeholder. Implementa tu lógica de Gemini.");
  if (!clienteIA && NODE_ENV !== 'test') throw new Error("Servicio IA (Google GenAI) no disponible.");
  return `Respuesta simulada de IA para: "${prompt.substring(0,50)}...". PDF: ${textoPDF ? 'Sí' : 'No'}. Historial: ${historialDB?.length || 0}.`;
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
        
        const promptSanitizado = promptTexto.trim().substring(0, 30).replace(/[^a-zA-Z0-9_.-]/g, '_');
        const nombreArchivoSupabase = `generated_chat_images/${Date.now()}_${promptSanitizado}.${extension}`; 

        const BUCKET_NAME = 'generated-images'; // ¡¡¡CAMBIA ESTO POR TU NOMBRE DE BUCKET!!!

        console.log(`[Img Gen Supabase] Subiendo a bucket '${BUCKET_NAME}', archivo '${nombreArchivoSupabase}'...`);
        const { data: uploadData, error: uploadError } = await supabase.storage
            .from(BUCKET_NAME)
            .upload(nombreArchivoSupabase, bufferImagen, { contentType: tipoMime, upsert: false });

        if (uploadError) {
            console.error(`[Img Gen Supabase] Error subiendo a Supabase Storage:`, uploadError);
            throw new Error(`Error al guardar imagen en almacenamiento: ${uploadError.message}`);
        }

        const { data: publicUrlData } = supabase.storage
            .from(BUCKET_NAME)
            .getPublicUrl(nombreArchivoSupabase);

        if (!publicUrlData || !publicUrlData.publicUrl) {
            console.error("[Img Gen Supabase] Error obteniendo URL pública para:", nombreArchivoSupabase);
            await supabase.storage.from(BUCKET_NAME).remove([nombreArchivoSupabase]).catch(e => console.error("Error eliminando archivo de Supabase tras fallo de getPublicUrl", e));
            throw new Error("Error al obtener URL de imagen persistente después de la subida.");
        }

        const supabaseImageUrl = publicUrlData.publicUrl;
        console.log(`[Img Gen Supabase] URL pública: ${supabaseImageUrl}`);

        return {
            fileName: nombreArchivoSupabase,
            imageUrl: supabaseImageUrl,
            message: `Imagen generada para: "${promptTexto.trim()}"`
        };

    } catch (error) {
        let status = 500;
        let userMessage = "Error desconocido generando imagen.";
        if (axios.isAxiosError(error) && error.response) {
            status = error.response.status;
            const errorDetail = error.response.data?.error || (Buffer.isBuffer(error.response.data) ? error.response.data.toString() : String(error.response.data)) || "Detalle no disponible";
            if (status === 400) userMessage = `Prompt inválido o error de parámetros para Clipdrop: ${errorDetail.substring(0,100)}`;
            else if (status === 401 || status === 403) userMessage = "API Key de Clipdrop inválida o sin permisos.";
            else if (status === 402) userMessage = "Límite de créditos/pago de Clipdrop alcanzado.";
            else if (status === 429) userMessage = "Demasiadas solicitudes a Clipdrop. Intente más tarde.";
            else userMessage = `Error del servicio de imágenes Clipdrop (${status}): ${errorDetail.substring(0,100)}`;
            console.error(`[Img Gen Clipdrop API Error] Status ${status}:`, errorDetail, error.config?.url);
        } else if (error.message.includes("Supabase") || error.message.includes("almacenamiento")) {
            userMessage = error.message;
            console.error("[Img Gen Supabase Storage Error]:", error.message);
        } else if (axios.isAxiosError(error) && error.request) {
             userMessage = "No se pudo contactar el servicio de imágenes (Clipdrop).";
             console.error("[Img Gen Clipdrop Network Error]:", error.message);
             status = 504;
        } else {
            console.error("[Img Gen Catch General]:", error.message, error.stack);
        }
        const errToThrow = new Error(userMessage);
        errToThrow.status = status;
        throw errToThrow;
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
    if (error) {
      if (error.code === "23505") return res.status(409).json({ error: "Nombre de usuario ya existe." });
      return next(error);
    }
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
    if(!JWT_SECRET) { console.error("CRITICAL: JWT_SECRET NO CONFIGURADO PARA LOGIN"); throw new Error("Error de configuración del servidor de autenticación."); }
    const token = jwt.sign(payload, JWT_SECRET, JWT_OPTIONS);
    res.cookie("token", token, COOKIE_OPTIONS);
    res.json({ message: "Login exitoso.", user: payload });
  } catch (error) { next(error); }
});

app.post("/api/logout", (req, res) => { res.clearCookie("token", COOKIE_OPTIONS); res.status(200).json({ message: "Logout exitoso." }); });

app.get("/api/verify-auth", autenticarToken, (req, res) => { res.json({ user: req.usuario }); });


// FILES (PDFs del usuario) - Usa uploadPdfMiddleware
app.post("/api/files", autenticarToken, uploadPdfMiddleware.array("archivosPdf", 5), async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    try {
      const usuarioId = req.usuario.id;
      const archivos = req.files;
      if (!archivos || archivos.length === 0) return res.status(400).json({ error: "No se subieron archivos PDF válidos."});
      
      const registros = archivos.map(f => ({ usuario_id: usuarioId, nombre_archivo_unico: f.filename, nombre_archivo_original: f.originalname }));
      const { data, error } = await supabase.from("archivos_usuario").insert(registros).select(); // .select() para devolver los insertados
      if (error) { 
          archivos.forEach(async f => {try{await fs.unlink(path.join(directorioSubidasPdf, f.filename))}catch(e){console.error("Error limpiando PDF tras fallo DB:",e.message)}});
          return next(error); 
      }
      console.log(`[Files POST] ${archivos.length} archivo(s) PDF guardados para user ${usuarioId}.`);
      res.status(201).json({ mensaje: "Archivos PDF subidos correctamente.", archivos: (data || []).map(d=>({name:d.nombre_archivo_unico, originalName: d.nombre_archivo_original})) });
    } catch (error) { next(error); }
});

app.get("/api/files", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    try {
      const { data: archivos, error } = await supabase.from("archivos_usuario")
        .select("nombre_archivo_unico, nombre_archivo_original")
        .eq("usuario_id", req.usuario.id)
        .order("fecha_subida", { ascending: false });
      if (error) return next(error);
      res.json( (archivos || []).map(a => ({ name: a.nombre_archivo_unico, originalName: a.nombre_archivo_original })) );
    } catch (error) { next(error); }
});

app.delete( "/api/files/:nombreArchivoUnico", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const idUsuario = req.usuario.id;
    const { nombreArchivoUnico } = req.params;
    if(!nombreArchivoUnico) return res.status(400).json({error: "Nombre de archivo no especificado."});

    try {
      const { data: archivoMeta, error: metaError } = await supabase.from("archivos_usuario").select("id").eq("usuario_id", idUsuario).eq("nombre_archivo_unico", nombreArchivoUnico).single();
      if (metaError || !archivoMeta) return res.status(404).json({ error: "Archivo no encontrado o no autorizado." });

      const { error: deleteError } = await supabase.from("archivos_usuario").delete().eq("id", archivoMeta.id);
      if (deleteError) throw new Error(`Eliminando de DB: ${deleteError.message}`);
      
      try { 
          const rutaCompleta = path.join(directorioSubidasPdf, nombreArchivoUnico);
          await fs.unlink(rutaCompleta); 
          console.log(`[File Delete] Archivo del disco eliminado: ${rutaCompleta}`);
      } catch (fsError) { 
          if (fsError.code !== "ENOENT") console.error(`[File Delete] Error FS (ignorando ENOENT): ${fsError.message}`);
          else console.log(`[File Delete] Archivo no encontrado en disco (ENOENT): ${nombreArchivoUnico}`);
      }
      res.json({ message: "Archivo eliminado correctamente." });
    } catch (err) { next(err); }
});


// CONVERSATIONS (Metadata)
app.get("/api/conversations", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    try {
        const { data, error } = await supabase.from("conversaciones")
            .select("id, titulo")
            .eq("usuario_id", req.usuario.id)
            .order("fecha_actualizacion", { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch(error) { next(error); }
});

app.put("/api/conversations/:id/title", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const { id } = req.params;
    const convIdNum = parseInt(id, 10);
    if(isNaN(convIdNum)) return res.status(400).json({error: "ID de conversación inválido."});
    
    const { nuevoTitulo } = req.body;
    if (!nuevoTitulo || typeof nuevoTitulo !== "string" || !nuevoTitulo.trim()) return res.status(400).json({ error: "Título no válido." });
    
    try {
        const { error } = await supabase.from("conversaciones")
            .update({ titulo: nuevoTitulo.trim().substring(0,100), fecha_actualizacion: new Date().toISOString() })
            .eq("id", convIdNum)
            .eq("usuario_id", req.usuario.id);
        if (error) throw error;
        res.status(200).json({ message: "Título actualizado." });
    } catch(err) { next(err); }
});

app.delete("/api/conversations/:idConv", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const { idConv } = req.params;
    const convIdNum = parseInt(idConv, 10);
    if(isNaN(convIdNum)) return res.status(400).json({error: "ID de conversación inválido."});

    try {
        const { error } = await supabase.from("conversaciones")
            .delete()
            .eq("id", convIdNum)
            .eq("usuario_id", req.usuario.id);
        if (error) throw error;
        res.json({ message: "Conversación eliminada." });
    } catch(err) { next(err); }
});


// MESSAGES (Contenido de una conversación)
app.get( "/api/conversations/:id/messages", autenticarToken, async (req, res, next) => {
    console.log(`[GET /messages] Solicitado para conv ID: ${req.params.id}, User: ${req.usuario.id}`);
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const { id } = req.params;
    const conversationIdNum = parseInt(id, 10);
    if (isNaN(conversationIdNum)) return res.status(400).json({error:"ID de conversación inválido."})
    
    try {
      const { data: convOwner, error: ownerError } = await supabase.from("conversaciones").select("id").eq("id", conversationIdNum).eq("usuario_id", req.usuario.id).maybeSingle();
      if(ownerError) { console.error("[GET /messages] Error owner check:", ownerError.message); throw ownerError; }
      if (!convOwner) { console.warn("[GET /messages] Owner check failed for conv:", conversationIdNum); return res.status(404).json({ error: "Conversación no encontrada o no autorizada." });}
      
      const { data: mensajes, error: messagesError } = await supabase
          .from("mensajes")
          .select("rol, texto, fecha_envio, imageUrl, isImage, fileName")
          .eq("conversacion_id", conversationIdNum)
          .order("fecha_envio", { ascending: true });
          
      if (messagesError) { console.error("[GET /messages] Error fetching messages:", messagesError.message); throw messagesError; }
      console.log(`[GET /messages] Devolviendo ${mensajes?.length || 0} mensajes. Imágenes: ${mensajes?.filter(m=>m.isImage).length || 0}`);
      res.json(mensajes || []);
    } catch (error) { next(error); }
  }
);

app.post("/api/conversations/:id/messages", autenticarToken, async (req, res, next) => {
    console.log(`[POST /messages] Inicio. Conv ID param: ${req.params.id}. User: ${req.usuario.id}`);
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    
    const { id: conversacion_id_str } = req.params;
    const conversacion_id_num = parseInt(conversacion_id_str, 10);
    if (isNaN(conversacion_id_num)) return res.status(400).json({ error: "ID de conversación inválido." });

    const usuario_id = req.usuario.id;
    const { rol, texto, imageUrl, fileName, isImage } = req.body;
    console.log(`[POST /messages] Body recibido:`, req.body);

    if (!rol || (rol !== "user" && rol !== "model")) return res.status(400).json({ error: "Rol de mensaje inválido." });
    if (isImage === true && (!imageUrl || typeof imageUrl !== 'string')) return res.status(400).json({ error: "imageUrl (string) es requerida para mensajes de imagen." });

    try {
        const { data: convData, error: convError } = await supabase.from("conversaciones").select("id").eq("id", conversacion_id_num).eq("usuario_id", usuario_id).single();
        if (convError || !convData) { console.warn(`[POST /messages] Conv no encontrada/auth fallida. User: ${usuario_id}, Conv: ${conversacion_id_num}`, convError?.message); return res.status(404).json({ error: "Conversación no encontrada o no tienes acceso." });}

        const mensajeAGuardar = {
            conversacion_id: conversacion_id_num, rol,
            texto: texto || null, 
            imageUrl: isImage === true ? (imageUrl || null) : null, 
            fileName: isImage === true ? (fileName || null) : null,
            isImage: isImage === true,
        };
        console.log("[POST /messages] Insertando en 'mensajes':", mensajeAGuardar);

        const { data: mensajeInsertado, error: insertError } = await supabase.from("mensajes").insert([mensajeAGuardar]).select().single();
        if (insertError) { console.error(`[POST /messages] Error Supabase al insertar:`, insertError); throw insertError; }

        console.log(`[POST /messages] Mensaje guardado:`, mensajeInsertado);
        res.status(201).json(mensajeInsertado);
    } catch (error) { next(error); }
});


// GENERATE TEXT (Con Gemini, puede usar PDFs)
app.post("/api/generateText", autenticarToken, uploadPdfMiddleware.array("archivosPdf", 5), async (req, res, next) => {
    console.log("[POST /api/generateText] Iniciado. User:", req.usuario.id);
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    if (!clienteIA && NODE_ENV !== 'test') return res.status(503).json({ error: "Servicio IA no disponible."});

    const usuarioId = req.usuario.id;
    const { prompt, conversationId: inputConversationIdStr, modeloSeleccionado, temperatura, topP, idioma, archivosSeleccionados } = req.body;
    
    let conversationId = inputConversationIdStr ? parseInt(inputConversationIdStr, 10) : null;
    if (inputConversationIdStr && isNaN(conversationId)) return res.status(400).json({error: "ID de conversación inválido."});

    let archivosSeleccionadosNombres = [];
    if (archivosSeleccionados) {
        try { archivosSeleccionadosNombres = typeof archivosSeleccionados === 'string' ? JSON.parse(archivosSeleccionados) : archivosSeleccionados;
             if(!Array.isArray(archivosSeleccionadosNombres)) archivosSeleccionadosNombres = [];
        } catch(e) { return res.status(400).json({ error: "Formato de archivosSeleccionados inválido." }); }
    }
    
    let isNewConversation = false;
    const archivosNuevosSubidosBackend = [];

    try {
        if (!conversationId) { // Crear nueva conversación
            const tituloNuevaConv = (prompt?.trim() || "Chat con PDF").substring(0,30).split(/\s+/).slice(0,5).join(" ") || "Nueva Conversación";
            const { data: nuevaConv, error: convError } = await supabase.from("conversaciones").insert([{ usuario_id: usuarioId, titulo: tituloNuevaConv }]).select("id").single();
            if (convError) throw new Error(`Creando conversación: ${convError.message}`);
            conversationId = nuevaConv.id;
            isNewConversation = true;
            console.log(`[GenerateText] Nueva conversación ID: ${conversationId} para user ${usuarioId}`);
        }

        if (prompt && prompt.trim()) { // Guardar mensaje del usuario
            const { error: userMsgError } = await supabase.from("mensajes").insert([{ conversacion_id: conversationId, rol: "user", texto: prompt.trim(), isImage: false }]);
            if (userMsgError) console.warn("[GenerateText] Error guardando mensaje usuario:", userMsgError.message);
        }

        const archivosPdfNuevos = req.files || []; // Ya filtrados por Multer
        if (archivosPdfNuevos.length > 0) {
            const registrosArchivosDB = archivosPdfNuevos.map(f => ({ usuario_id: usuarioId, nombre_archivo_unico: f.filename, nombre_archivo_original: f.originalname}));
            const { error: insertArchivosError } = await supabase.from("archivos_usuario").insert(registrosArchivosDB);
            if (insertArchivosError) {
                archivosPdfNuevos.forEach(async f => { try { await fs.unlink(path.join(directorioSubidasPdf,f.filename)); } catch(e){ console.error("Error limpiando PDF tras fallo DB:", e.message); }});
                throw new Error("No se pudieron guardar metadatos de PDF: " + insertArchivosError.message);
            }
            archivosPdfNuevos.forEach(f => archivosNuevosSubidosBackend.push({name: f.filename, originalName: f.originalname}));
        }

        const nombresArchivosParaContexto = [...archivosSeleccionadosNombres, ...archivosPdfNuevos.map(f => f.filename)].filter(Boolean);
        const contextoPDF = nombresArchivosParaContexto.length > 0 ? await generarContextoPDF(usuarioId, nombresArchivosParaContexto) : "";
        
        if ((!prompt || prompt.trim() === "") && (!contextoPDF || contextoPDF.startsWith("[Error")) && nombresArchivosParaContexto.length === 0) {
             return res.status(400).json({error:"Se requiere un prompt o archivos PDF válidos."});
        }
        
        const { data: historialDB, error: errorHist } = await supabase.from("mensajes").select("rol, texto, imageUrl, isImage").eq("conversacion_id", conversationId).order("fecha_envio", { ascending: true });
        if (errorHist) throw new Error(`Cargando historial: ${errorHist.message}`);

        const promptFinalIA = prompt?.trim() || (contextoPDF ? (idioma === 'es' ? "Analiza y resume los documentos proporcionados." : "Analyze and summarize the provided documents.") : "Hola.");
        const respuestaTextoIA = await generarRespuestaIA(promptFinalIA, historialDB, contextoPDF, modeloSeleccionado, parseFloat(temperatura), parseFloat(topP), idioma);

        if (respuestaTextoIA) {
            const { error: modelMsgError } = await supabase.from("mensajes").insert([{ 
                conversacion_id: conversationId, rol: "model", texto: respuestaTextoIA, isImage: false 
            }]);
            if (modelMsgError) console.warn("[GenerateText] Error guardando respuesta modelo (texto) en DB:", modelMsgError.message);
        }

        res.status(200).json({ respuesta: respuestaTextoIA, isNewConversation, conversationId, archivosSubidosNuevos: archivosNuevosSubidosBackend });
    } catch (error) { next(error); }
});

// GENERATE IMAGE (CLIPDROP -> SUPABASE STORAGE)
app.post("/api/generateImage", autenticarToken, async (req, res, next) => {
    console.log("[POST /api/generateImage] Iniciado. User:", req.usuario.id);
    const { prompt } = req.body;
    if (!prompt?.trim()) return res.status(400).json({ error: "Prompt inválido para generar imagen." });
    
    try {
        const resultadoImagen = await generarImagenClipdropYSubirASupabase(prompt.trim());
        res.json({
            message: resultadoImagen.message,
            fileName: resultadoImagen.fileName, 
            imageUrl: resultadoImagen.imageUrl
        });
    } catch (error) {
        next(error);
    }
});

// --- Manejador de Errores Global ---
app.use((err, req, res, next) => {
  console.error("‼️ Global Error Handler:", err.message);
  if (NODE_ENV !== "production" && err.stack) console.error("Stack:", err.stack);

  let statusCode = typeof err.status === "number" ? err.status : (err.response?.status || 500) ; // Usar status del error o de axios si existe
  let mensajeUsuario = err.message || "Error interno del servidor.";

  if (err instanceof multer.MulterError) {
    statusCode = 400;
    if (err.code === "LIMIT_FILE_SIZE") {
      statusCode = 413;
      mensajeUsuario = `Archivo muy grande (Máx: ${TAMANO_MAX_ARCHIVO_MB} MB).`;
    } else if (err.code === 'LIMIT_UNEXPECTED_FILE' && err.message.includes('Solo se permiten archivos PDF')) {
        mensajeUsuario = 'Solo se permiten archivos PDF.'; // El filtro ya pone este mensaje en el error
    } else {
      mensajeUsuario = `Error subida archivo: ${err.message}.`;
    }
  } else if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    statusCode = 400;
    mensajeUsuario = "Petición mal formada (JSON inválido).";
  } else if (err.code && typeof err.code === 'string' && (err.code.startsWith('2') || err.code.startsWith('PGR'))) { // Errores Supabase/Postgres
      console.warn("Error DB:", err.code, err.message, err.detail || err.hint);
      mensajeUsuario = "Error en la operación de base de datos."; // Mensaje genérico para el cliente
      if (err.code === '23505') { statusCode = 409; mensajeUsuario = "Conflicto de datos (recurso ya existe o valor duplicado)."; }
      else if (err.code === '22P02') { statusCode = 400; mensajeUsuario = "Formato de datos inválido para la operación."; }
      else if (err.code === '42P01') { statusCode = 500; mensajeUsuario = "Error interno del servidor (configuración DB)."; } // Tabla no encontrada
      else { statusCode = 500; } // Otros errores de DB específicos se loguean, pero al cliente va genérico
  } else if (err.message.toLowerCase().includes("no disponible") || err.message.toLowerCase().includes("no configurado")) {
    statusCode = 503; // Service Unavailable
  } else if (err.status === 400 || err.message.toLowerCase().includes("inválid") || err.message.toLowerCase().includes("requerid")) {
    statusCode = 400;
  } else if (err.status === 401 || err.message.toLowerCase().includes("autenticación") || err.message.toLowerCase().includes("permisos") || err.message.toLowerCase().includes("api key inválida") || err.message.toLowerCase().includes("token")) {
    statusCode = 401;
  } else if (err.status === 402 || err.message.toLowerCase().includes("límite") || err.message.toLowerCase().includes("pago") || err.message.toLowerCase().includes("créditos")) {
    statusCode = 402;
    mensajeUsuario = "Límite de uso del servicio externo alcanzado.";
  } else if (err.status === 429 || err.message.toLowerCase().includes("demasiadas solicitudes") || err.message.toLowerCase().includes("sobrecargado") || err.message.toLowerCase().includes("too many requests")) {
    statusCode = 429;
    mensajeUsuario = "Servicio externo temporalmente ocupado. Intente más tarde.";
  } else if (axios.isAxiosError(error) && !error.response) { // Error de red de Axios
    statusCode = 504; // Gateway Timeout o similar
    mensajeUsuario = "Error de red al contactar servicio externo.";
  } else if (err.status === 404 || err.message.toLowerCase().includes("no encontrado") || err.message.toLowerCase().includes("not found")) {
      statusCode = 404;
      mensajeUsuario = "Recurso solicitado no encontrado.";
  } else if (err.message.includes("AbortError")) {
      statusCode = 499;
      mensajeUsuario = "La solicitud fue cancelada.";
  }

  // Usar el mensaje del error si no se ha personalizado uno mejor y el error no es de servidor "genérico"
  if (statusCode < 500 && statusCode !== 429 && statusCode !== 402 && err.message && !err.message.startsWith("Error interno")) {
      mensajeUsuario = err.message;
  } else if (statusCode >= 500 && (NODE_ENV === "production" || !err.message.toLowerCase().includes("supabase"))) { // En prod, o si no es de Supabase, dar mensaje genérico
      mensajeUsuario = "Error interno del servidor. Por favor, intente más tarde.";
  }
  
  if (res.headersSent) {
    console.error("‼️ Error GLOBAL Handler: Cabeceras ya enviadas!");
    return next(err); // Pasar al manejador por defecto de Express si no podemos enviar respuesta
  }
  res.status(statusCode).json({ error: mensajeUsuario });
});


// --- Iniciar Servidor ---
const PORT = PUERTO || 3001;
app.listen(PORT, () => {
    console.log(`\n🚀 Servidor en puerto ${PORT} | Modo: ${NODE_ENV}`);
    console.log(`🔗 Local: http://localhost:${PORT}`);
    console.log(`\n--- Estado Servicios Configurados ---`);
    console.log(` Supabase: ${supabase ? '✅ OK' : '❌ NO OK (Verificar SUPABASE_URL/SUPABASE_KEY)'}`);
    console.log(` Google GenAI: ${clienteIA ? '✅ OK' : '❌ NO OK (Verificar API_KEY)'}`);
    console.log(` Clipdrop Imagen: ${CLIPDROP_API_KEY ? '✅ OK (Key presente)' : '❌ NO OK (Verificar CLIPDROP_API_KEY)'}`);
    console.log(` JWT Secret: ${JWT_SECRET && JWT_SECRET.length >=32 ? '✅ OK' : '❌ NO OK (INSEGURO o NO CONFIGURADO)'}`);
    console.log(`---------------------------------\n`);
});