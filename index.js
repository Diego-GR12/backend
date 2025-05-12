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
import FormData from "form-data"; // <--- AÑADIDO PARA CLIPDROP

// --- Definiciones de Directorio ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const directorioSubidas = path.join(__dirname, "uploads");
const directorioImagenesGeneradas = path.join(__dirname, "generated_images"); // <--- AÑADIDO SI NO ESTABA

// --- Carga de Variables de Entorno ---
dotenv.config();
const {
  PORT: PUERTO = 3001,
  DB_HOST,
  DB_USER,
  DB_PASSWORD,
  DB_NAME,
  API_KEY,
  JWT_SECRET,
  NODE_ENV = "development",
  SUPABASE_URL,
  SUPABASE_KEY,
  // HUGGING_FACE_API_KEY, // <--- ELIMINADO O COMENTADO
  CLIPDROP_API_KEY,    // <--- AÑADIDO/ASEGURADO
} = process.env;

const isDev = NODE_ENV !== "production";

// --- Constantes y Configuraciones (Tu código original) ---
const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: !isDev,
  sameSite: isDev ? "lax" : "none",
  maxAge: 3600 * 1000,
  path: "/",
};
const TAMANO_MAX_ARCHIVO_MB = 20;
const MAX_CARACTERES_POR_PDF = 10000;
const MAX_LONGITUD_CONTEXTO = 30000;
const MODELOS_PERMITIDOS = [
  "gemini-1.5-flash",
  "gemini-1.5-pro",
  "gemini-2.0-flash",
  "gemini-2.5-pro-exp-03-25",
];
const MODELO_POR_DEFECTO = "gemini-1.5-flash";
const TEMP_POR_DEFECTO = 0.7;
const TOPP_POR_DEFECTO = 0.9;
const IDIOMA_POR_DEFECTO = "es";
const JWT_OPTIONS = { expiresIn: "1h" };

// --- Verificaciones de Startup ---
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
// if (!HUGGING_FACE_API_KEY) // <--- ELIMINADO O COMENTADO
//   console.warn("⚠️ [Startup] ADVERTENCIA: HUGGING_FACE_API_KEY no configurada.");
if (!CLIPDROP_API_KEY) // <--- AÑADIDO/ASEGURADO
  console.warn("⚠️ [Startup] ADVERTENCIA: CLIPDROP_API_KEY no configurada.");


// --- Inicialización de Express (Tu código original) ---
const app = express();

// --- Inicialización de Clientes (Google AI, Supabase - Tu código original) ---
let clienteIA;
try {
  clienteIA = new GoogleGenerativeAI(API_KEY);
  console.log("✅ Instancia de GoogleGenerativeAI creada.");
} catch (error) {
  console.error(
    "🚨 FATAL: Error al inicializar GoogleGenerativeAI:",
    error.message
  );
  clienteIA = null;
}
if (!clienteIA)
  console.warn("⚠️ ADVERTENCIA: Cliente Google Generative AI no inicializado.");

let supabase;
try {
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
  console.log("✅ Cliente Supabase inicializado.");
} catch (error) {
  console.error("🚨 FATAL: Error al inicializar Supabase:", error.message);
  supabase = null;
}
if (!supabase)
  console.warn("⚠️ ADVERTENCIA: Cliente Supabase no inicializado.");

// --- Middlewares (Tu código original) ---
app.use(
  cors({
    origin: (origin, callback) => {
      if (origin) {
        console.log("🌍 Solicitado desde:", origin);
        callback(null, origin);
      } else {
        callback(null, true);
      }
    },
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json());

// --- Middleware de Autenticación (Tu código original) ---
const autenticarToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    console.log("[Auth] Fail: No token cookie.");
    return res.status(401).json({ error: "Token no proporcionado" });
  }
  jwt.verify(token, JWT_SECRET, (err, usuarioToken) => {
    if (err) {
      const isExpired = err.name === "TokenExpiredError";
      console.error(
        `[Auth] Fail: Token verify error (${err.name})${
          isExpired ? " - Expired" : ""
        }.`
      );
      if (isExpired) res.clearCookie("token", COOKIE_OPTIONS);
      return res
        .status(isExpired ? 401 : 403)
        .json({ error: isExpired ? "Token expirado" : "Token inválido" });
    }
    req.usuario = usuarioToken;
    next();
  });
};

// --- Configuración de Multer (Tu código original) ---
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
const subir = multer({ // Este es tu 'subir' para /api/generateText
  storage: almacenamiento,
  limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const isPdf = file.mimetype === "application/pdf";
    if (!isPdf)
      console.warn(
        `⚠️ Rechazado archivo no PDF: ${file.originalname} (${file.mimetype})`
      );
    cb(null, isPdf); // Mantengo tu lógica original de filtro aquí
  },
}).array("archivosPdf");

// --- Crear directorios necesarios al inicio (Tu código original, adaptado si es necesario) ---
// Aseguramos que también se cree el de imágenes generadas
[directorioSubidas, directorioImagenesGeneradas].forEach(dir => {
    if (!existsSync(dir)) {
        try { mkdirSync(dir, { recursive: true }); console.log(`✅ Directorio creado: ${dir}`); }
        catch (error) { console.error(`🚨 FATAL: No se pudo crear directorio ${dir}:`, error); }
    } else { console.log(`➡️ Directorio ya existe: ${dir}`); }
});


// --- Funciones Auxiliares (PDF, IA Texto - Tu código original) ---

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

    const archivosMap = new Map(
      archivosDB.map((f) => [f.nombre_archivo_unico, f.nombre_archivo_original])
    );

    let textoCompleto = "";
    for (const nombreArchivoUnico of nombresArchivosUnicos) {
      const nombreOriginal = archivosMap.get(nombreArchivoUnico);
      const ruta = path.join(directorioSubidas, nombreArchivoUnico);

      try {
        const buffer = await fs.readFile(ruta);
        const datos = await pdfParse(buffer);
        textoCompleto += `\n\n[${nombreOriginal}]\n${datos.text.trim()}`;
      } catch (err) {
        console.warn(
          `[Context PDF] ⚠️ No se pudo leer ${nombreArchivoUnico}:`,
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
async function generarRespuestaIA(
  prompt,
  historialDB,
  textoPDF,
  modeloReq,
  temp,
  topP,
  lang
) {
  if (!clienteIA) throw new Error("Servicio IA no disponible.");
  const nombreModelo = MODELOS_PERMITIDOS.includes(modeloReq)
    ? modeloReq
    : MODELO_POR_DEFECTO;
  if (modeloReq && nombreModelo !== modeloReq) {
    console.warn(
      `[Gen IA] ⚠️ Modelo no válido ('${modeloReq}'), usando por defecto: ${MODELO_POR_DEFECTO}`
    );
  }
  const configGeneracion = {
    temperature: !isNaN(temp)
      ? Math.max(0, Math.min(1, temp))
      : TEMP_POR_DEFECTO,
    topP: !isNaN(topP) ? Math.max(0, Math.min(1, topP)) : TOPP_POR_DEFECTO,
  };

  const idioma = ["es", "en"].includes(lang) ? lang : IDIOMA_POR_DEFECTO;

  const langStrings =
    idioma === "en"
      ? {
          systemBase:
            "You are a helpful conversational assistant. Answer clearly and concisely in Markdown format.",
          systemPdf: `You are an assistant that answers *based solely* on the provided text. If the answer isn't in the text, state that clearly. Use Markdown format.\n\nReference Text (Context):\n"""\n{CONTEXT}\n"""\n\n`,
          label: "Question",
          error: "I'm sorry, there was a problem contacting the AI",
        }
      : {
          systemBase:
            "Eres un asistente conversacional útil. Responde de forma clara y concisa en formato Markdown.",
          systemPdf: `Eres un asistente que responde *basándose únicamente* en el texto proporcionado. Si la respuesta no está en el texto, indícalo claramente. Usa formato Markdown.\n\nTexto de Referencia (Contexto):\n"""\n{CONTEXT}\n"""\n\n`,
          label: "Pregunta",
          error: "Lo siento, hubo un problema al contactar la IA",
        };

  let instruccionSistema;
  if (textoPDF) {
    const contextoTruncado =
      textoPDF.length > MAX_LONGITUD_CONTEXTO
        ? textoPDF.substring(0, MAX_LONGITUD_CONTEXTO) +
          "... (context truncated)"
        : textoPDF;
    if (textoPDF.length > MAX_LONGITUD_CONTEXTO)
      console.warn(`[Gen IA] ✂️ Contexto PDF truncado.`);
    instruccionSistema = langStrings.systemPdf.replace(
      "{CONTEXT}",
      contextoTruncado
    );
  } else {
    instruccionSistema = langStrings.systemBase;
  }
  const promptCompletoUsuario = `${instruccionSistema}${langStrings.label}: ${prompt}`;
  const contenidoGemini = [
    ...(historialDB || []) // Asegurar que historialDB es un array
      .filter((m) => m.texto?.trim())
      .map((m) => ({
        role: m.rol === "user" ? "user" : "model",
        parts: [{ text: m.texto }],
      })),
    { role: "user", parts: [{ text: promptCompletoUsuario }] },
  ];
  console.log(
    `[Gen IA] ➡️ Enviando ${contenidoGemini.length} partes a Gemini (${nombreModelo}).`
  );
  try {
    const modeloGemini = clienteIA.getGenerativeModel({ model: nombreModelo });
    const resultado = await modeloGemini.generateContent({
      contents: contenidoGemini,
      generationConfig: configGeneracion,
    });
    const response = resultado?.response;
    const textoRespuestaIA =
      response?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (textoRespuestaIA) {
      console.log("[Gen IA] ✅ Respuesta recibida.");
      return textoRespuestaIA.trim();
    }
    const blockReason = response?.promptFeedback?.blockReason;
    const finishReason = response?.candidates?.[0]?.finishReason;
    console.warn(
      `[Gen IA] ⚠️ Respuesta vacía/bloqueada. Block: ${blockReason}, Finish: ${finishReason}`
    );
    let errorMsg = langStrings.error;
    if (blockReason) errorMsg += `. Razón bloqueo: ${blockReason}`;
    else if (finishReason && finishReason !== "STOP")
      errorMsg += `. Razón finalización: ${finishReason}`;
    else errorMsg += ". (Respuesta inválida)";
    // Devolver el mensaje de error en lugar de throw para que el flujo principal lo maneje
    return errorMsg;
  } catch (error) {
    console.error(`[Gen IA] ❌ Error API (${nombreModelo}):`, error.message);
    const detalleError =
      error.details || error.message || "Error no especificado";
    // Devolver el mensaje de error
    return `${langStrings.error}. (Detalle: ${detalleError})`;
  }
}

// --- NUEVA Función para Generar Imágenes con CLIPDROP ---
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
            catch (e) { try { errorBody = await response.text(); } catch (e2) {} } // fallback a texto
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
        // Propagar el error ya formateado o uno genérico si es un error de red
        throw new Error(error.message || "Error desconocido generando imagen con Clipdrop.");
    }
}

// --- Rutas API (Auth, Files, Conversations - Tu código original, con mínimas correcciones para el error .catch) ---
const storageForFiles = multer.diskStorage({ // Esto es 'storage' en tu código original para /api/files
  destination: function (req, file, cb) {
    cb(null, uploadDir); // 'uploadDir' es tu 'directorioSubidas'
  },
  filename: function (req, file, cb) {
    const uniqueName = `${Date.now()}-${file.originalname}`;
    cb(null, uniqueName);
  },
});
const uploadForFiles = multer({ storage: storageForFiles }); // Renombrado para claridad, es tu 'upload'

app.post("/api/register", async (req, res, next) => {
  if (!supabase) return res.status(503).json({error: "BD no disponible"});
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });
  try {
    const contrasenaHasheada = await bcrypt.hash(password, 10);
    // CORRECCIÓN SUPABASE:
    const { data, error } = await supabase.from("usuarios").insert([{ nombre_usuario: username, contrasena_hash: contrasenaHasheada }]).select("id").single();
    if (error) {
      if (error.code === "23505") return res.status(409).json({ error: "Nombre de usuario ya existe." });
      console.error(`[Register] Error Supabase: ${error.message}`);
      throw error;
    }
    res.status(201).json({ message: "Registro exitoso.", userId: data.id });
  } catch (error) { console.error("[Register Catch]", error.message); next(error); }
});

app.post("/api/login", async (req, res, next) => {
  if (!supabase) return res.status(503).json({error: "BD no disponible"});
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });
  try {
    const { data: usuarios, error } = await supabase.from("usuarios").select("id, nombre_usuario, contrasena_hash").eq("nombre_usuario", username).limit(1).single();
    if (error || !usuarios) return res.status(401).json({ error: "Credenciales inválidas." }); // error o !usuarios es suficiente
    const passwordCorrecta = await bcrypt.compare(password, usuarios.contrasena_hash);
    if (!passwordCorrecta) return res.status(401).json({ error: "Credenciales inválidas." });
    const payload = { id: usuarios.id, username: usuarios.nombre_usuario };
    if(!JWT_SECRET) throw new Error("JWT Secret no configurado");
    const token = jwt.sign(payload, JWT_SECRET, JWT_OPTIONS);
    res.cookie("token", token, COOKIE_OPTIONS);
    res.json({ message: "Login exitoso.", user: payload });
  } catch (error) { console.error("[Login Catch]", error.message); next(error); }
});

app.post("/api/logout", (req, res) => { res.clearCookie("token", COOKIE_OPTIONS); res.status(200).json({ message: "Logout exitoso." }); });
app.get("/api/verify-auth", autenticarToken, (req, res) => { res.json({ user: req.usuario }); });

// --- Configurar multer para /api/files (Tu lógica original) ---
const filesUploadStorage = multer.diskStorage({ // 'storage' en tu código para /api/files
  destination: function (req, file, cb) {
    cb(null, uploadDir); // 'uploadDir' era tu `directorioSubidas`
  },
  filename: function (req, file, cb) {
    const uniqueName = `${Date.now()}-${file.originalname}`;
    cb(null, uniqueName);
  },
});
const filesUploadMulter = multer({ storage: filesUploadStorage }); // 'upload' en tu código para /api/files


app.post("/api/files", autenticarToken, filesUploadMulter.array("archivosPdf"), async (req, res, next) => { // Usa tu multer original 'upload'
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    try {
      const usuarioId = req.usuario.id;
      const archivos = req.files;
      if (!archivos || archivos.length === 0) return res.status(400).json({ error: "No se subieron archivos."});
      const registros = archivos.map((file) => ({ usuario_id: usuarioId, nombre_archivo_unico: file.filename, nombre_archivo_original: file.originalname, }));
      // CORRECCIÓN SUPABASE:
      const { error } = await supabase.from("archivos_usuario").insert(registros);
      if (error) {
        console.error("[Upload Files] Error Supabase:", error.message);
        archivos.forEach(async f => {try{await fs.unlink(f.path)}catch(e){}});
        throw error;
      }
      res.status(200).json({ mensaje: "Archivos subidos correctamente." });
    } catch (error) { console.error("[Upload Files Catch]", error.message); next(error); }
  }
);

app.get("/api/files", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    try {
      const { data: archivos, error } = await supabase.from("archivos_usuario").select("nombre_archivo_unico, nombre_archivo_original").eq("usuario_id", req.usuario.id).order("fecha_subida", { ascending: false });
      if (error) throw error;
      res.json( (archivos || []).map((a) => ({ name: a.nombre_archivo_unico, originalName: a.nombre_archivo_original, })) );
    } catch (error) { console.error("[Get Files Catch]", error.message); next(error); }
  }
);

app.delete( "/api/files/:nombreArchivoUnico", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible"});
    const idUsuario = req.usuario.id;
    const nombreArchivoUnico = req.params.nombreArchivoUnico;
    if(!nombreArchivoUnico) return res.status(400).json({error: "Nombre de archivo no especificado."});
    try {
      const { data: archivo, error } = await supabase.from("archivos_usuario").select("id").eq("usuario_id", idUsuario).eq("nombre_archivo_unico", nombreArchivoUnico).single();
      if (error || !archivo) return res.status(404).json({ error: "Archivo no encontrado." }); // Simplificado
      // CORRECCIÓN SUPABASE:
      const { error: deleteError } = await supabase.from("archivos_usuario").delete().eq("id", archivo.id);
      if (deleteError) throw new Error("Error eliminando de la base de datos: " + deleteError.message);
      try { await fs.unlink(path.join(directorioSubidas, nombreArchivoUnico)); } catch (fsError) { if (fsError.code !== "ENOENT") console.error("[Delete File FS Error]", fsError.message); }
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

app.get( "/api/conversations/:id/messages", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible."});
    const { id } = req.params;
    if (!id) return res.status(400).json({error:"ID de conversación requerido."})
    try {
      const { data: convOwner, error: ownerError } = await supabase.from("conversaciones").select("id").eq("id", id).eq("usuario_id", req.usuario.id).maybeSingle();
      if(ownerError) throw ownerError;
      if (!convOwner) return res.status(404).json({ error: "Conversación no encontrada o no autorizada." });
      const { data: mensajes, error } = await supabase.from("mensajes").select("rol, texto, fecha_envio").eq("conversacion_id", id).order("fecha_envio", { ascending: true });
      if (error) throw error;
      res.json(mensajes || []);
    } catch (error) { console.error("[Get Msgs Catch]", error.message); next(error); }
  }
);

app.delete( "/api/conversations/:idConv", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible."});
    const idConv = req.params.idConv;
    if (!idConv) return res.status(400).json({error:"ID de conversación requerido."})
    const idUsuario = req.usuario.id;
    try {
      // CORRECCIÓN SUPABASE:
      const { error } = await supabase.from("conversaciones").delete().eq("id", idConv).eq("usuario_id", idUsuario);
      if (error) throw error;
      // Aquí no había count originalmente, se asume que si no hay error, se borró o no existía para el usuario
      res.json({ message: "Conversación eliminada correctamente." });
    } catch (err) { console.error("[Delete Conv Catch]", err.message); next(err); }
  }
);

app.put( "/api/conversations/:id/title", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({error: "BD no disponible."});
    const { id } = req.params;
    if (!id) return res.status(400).json({error:"ID de conversación requerido."})
    const { nuevoTitulo } = req.body;
    if (!nuevoTitulo || typeof nuevoTitulo !== "string" || !nuevoTitulo.trim()) return res.status(400).json({ error: "Título no válido." });
    const tituloLimpio = nuevoTitulo.trim().substring(0,100);
    try {
      // CORRECCIÓN SUPABASE:
      const { error } = await supabase.from("conversaciones").update({ titulo: tituloLimpio, fecha_actualizacion: new Date().toISOString() }).eq("id", id).eq("usuario_id", req.usuario.id);
      if (error) throw error;
      // En tu código original, no se verificaba `count` aquí, se asumía éxito si no había error.
      res.status(200).json({ message: "Título actualizado correctamente." });
    } catch (err) { console.error("[Update Title Catch]", err.message); next(err); }
  }
);

// --- RUTAS PRINCIPALES DE IA ---

app.post("/api/generateText", autenticarToken, subir, async (req, res, next) => { // Usa 'subir' de tu código
    if (!supabase) return res.status(503).json({ error: "BD no disponible." });
    if (!clienteIA) return res.status(503).json({ error: "Servicio IA (Google) no disponible."});

    const usuarioId = req.usuario.id;
    const { prompt, conversationId: inputConversationId, modeloSeleccionado, temperatura, topP, idioma, archivosSeleccionados, } = req.body;
    let archivosSeleccionadosArray = [];
    try {
        archivosSeleccionadosArray = Array.isArray(archivosSeleccionados) ? archivosSeleccionados : JSON.parse(archivosSeleccionados || "[]");
    } catch(e) { return res.status(400).json({ error: "Formato de archivosSeleccionados inválido." }); }


    let conversationId = inputConversationId;
    let isNewConversation = false;

    try {
        if (!conversationId) {
            // CORRECCIÓN SUPABASE:
            const { data, error } = await supabase.from("conversaciones").insert([{ usuario_id: usuarioId, titulo: (prompt?.trim().split(/\s+/).slice(0, 5).join(" ") || "Conversación nueva"), }]).select("id").single();
            if (error) throw new Error("Error creando conversación: " + error.message);
            conversationId = data.id;
            isNewConversation = true;
        }

        // Guardar mensaje del usuario si hay prompt
        if (prompt && prompt.trim() !== "") {
            // CORRECCIÓN SUPABASE:
            const { error: msgInsertError } = await supabase.from("mensajes").insert([{ conversacion_id: conversationId, rol: "user", texto: prompt }]);
            if (msgInsertError) console.error("[GenerateText] Error guardando mensaje usuario:", msgInsertError.message); // No fatal
        }


        const archivosNuevos = (req.files || []).filter(f => f.mimetype === 'application/pdf'); // Doble chequeo
        if (archivosNuevos.length > 0) {
            const registrosArchivos = archivosNuevos.map((file) => ({ usuario_id: usuarioId, nombre_archivo_unico: file.filename, nombre_archivo_original: file.originalname,}));
            // CORRECCIÓN SUPABASE:
            const { error: errorInsertarArchivos } = await supabase.from("archivos_usuario").insert(registrosArchivos);
            if (errorInsertarArchivos) {
                archivosNuevos.forEach(async f => {try{await fs.unlink(f.path)}catch(e){}}); // Limpiar
                console.error("[Archivos] Error al insertar archivos:", errorInsertarArchivos.message);
                throw new Error("No se pudieron guardar los archivos PDF.");
            }
        }

        const nombresArchivos = [...archivosSeleccionadosArray, ...archivosNuevos.map((f) => f.filename),].filter(Boolean);
        const contextoPDF = await generarContextoPDF(usuarioId, nombresArchivos);

        // Tu lógica original para cuando no hay prompt ni contexto:
        if ((!prompt || prompt.trim() === "") && (!contextoPDF || contextoPDF.startsWith("[Error"))) {
            return res.status(400).json({error:"Se requiere un prompt o archivos PDF válidos para generar una respuesta."});
        }
        
        // CORRECCIÓN SUPABASE:
        const { data: historial, error: errorHist } = await supabase.from("mensajes").select("rol, texto").eq("conversacion_id", conversationId).order("fecha_envio", { ascending: true });
        if (errorHist) throw new Error("Error cargando historial: " + errorHist.message);

        const promptParaIA = prompt || (idioma === 'es' ? "Resume el contenido de los archivos." : "Summarize the content of the files.");
        const respuestaIA = await generarRespuestaIA(promptParaIA, historial, contextoPDF, modeloSeleccionado, parseFloat(temperatura), parseFloat(topP), idioma);

        // CORRECCIÓN SUPABASE:
        const { error: modelMsgError } = await supabase.from("mensajes").insert([{ conversacion_id: conversationId, rol: "model", texto: respuestaIA }]);
        if (modelMsgError) console.error("[GenerateText] Error guardando mensaje modelo:", modelMsgError.message); // No fatal

        res.status(200).json({ respuesta: respuestaIA, isNewConversation, conversationId });
    } catch (error) {
        console.error("[GenerateText Catch]", error.message);
        next(error);
    }
});

// Generar Imagen (con Clipdrop)
app.post("/api/generateImage", autenticarToken, async (req, res, next) => {
    const { prompt } = req.body;
    if (!prompt?.trim()) return res.status(400).json({ error: "Prompt inválido." });
    if (!CLIPDROP_API_KEY) return res.status(503).json({ error: "Servicio de imágenes (Clipdrop) no configurado." });

    try {
        const resultado = await generarImagenClipdrop(prompt.trim()); // Llama a la función de Clipdrop
        res.json({ message: "Imagen generada con Clipdrop.", fileName: resultado.fileName, imageUrl: resultado.url });
    } catch (error) { next(error); }
});


// --- Servir Archivos Estáticos ---
app.use('/generated_images', express.static(directorioImagenesGeneradas, { maxAge: '1h' }));

// --- Manejador de Errores Global (Tu código original) ---
app.use((err, req, res, next) => {
  console.error("‼️ Global Error:", err.message);
  if (NODE_ENV !== "production" && err.stack) console.error(err.stack);
  let statusCode = typeof err.status === "number" ? err.status : 500;
  let mensajeUsuario = "Error interno del servidor.";
  const errorLang = req?.body?.idioma === "en" ? "en" : "es";
  if (err instanceof multer.MulterError) {
    statusCode = 400;
    if (err.code === "LIMIT_FILE_SIZE") {
      statusCode = 413;
      mensajeUsuario =
        errorLang === "en"
          ? `File too large (Max: ${TAMANO_MAX_ARCHIVO_MB} MB).`
          : `Archivo muy grande (Máx: ${TAMANO_MAX_ARCHIVO_MB} MB).`;
    } else if (err.message === 'Solo se permiten archivos PDF.') { // Capturar error del filtro
        mensajeUsuario = err.message;
    } else {
      mensajeUsuario =
        errorLang === "en"
          ? `File upload error: ${err.message}.`
          : `Error subida archivo: ${err.message}.`;
    }
  } else if ( err instanceof SyntaxError && err.status === 400 && "body" in err ) {
    statusCode = 400;
    mensajeUsuario = errorLang === "en" ? "Malformed request (Invalid JSON)." : "Petición mal formada (JSON inválido).";
  } else if (err.message.includes("Servicio") && (err.message.includes("no disponible") || err.message.includes("no configurado"))) { // Ampliado
    statusCode = 503;
    mensajeUsuario = err.message;
  } else if (err.message.includes("inválid") || err.message.includes("requerido") || err.message.includes("requerido por Clipdrop")) {
    statusCode = 400;
    mensajeUsuario = err.message;
  } else if (err.message.includes("autenticación") || err.message.includes("permisos") || err.message.includes("API Key inválida")) {
    statusCode = 401;
    mensajeUsuario = err.message;
  } else if (err.message.includes("Límite") || err.message.includes("pago") || err.message.includes("créditos")) {
    statusCode = 402;
    mensajeUsuario = "Límite de uso gratuito alcanzado.";
  } else if (err.message.includes("Demasiadas solicitudes") || err.message.includes("sobrecargado") || err.message.includes("Too Many Requests")) {
    statusCode = 429;
    mensajeUsuario = "Servicio externo ocupado. Intente más tarde.";
  } else if (statusCode === 500 && (err.message.toLowerCase().includes("fetch") || err.message.toLowerCase().includes("network") || err.message.toLowerCase().includes("socket")) ) {
    mensajeUsuario = "Error de red contactando servicio externo.";
  } else if (err.message.includes("404") || err.message.includes("no encontrado")) {
      statusCode = 404;
      mensajeUsuario = "Recurso no encontrado.";
  } else if (err.code && typeof err.code === 'string' ) { // Errores de Supabase pueden tener un 'code'
      // Podrías mapear códigos de error específicos de Supabase/Postgres aquí si quieres
      // Por ahora, dejamos el mensaje de error original de Supabase que ya es bueno
      mensajeUsuario = err.message;
  }
  // Default si no se ha modificado mensajeUsuario y statusCode sigue siendo 500.
  else if (statusCode === 500 && err.message && err.message !== "Error interno del servidor.") {
      mensajeUsuario = err.message; // Usa el mensaje del error si es un 500 con detalles
  }


  if (res.headersSent) {
    console.error("‼️ Error caught AFTER headers were sent!");
    return next(err);
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