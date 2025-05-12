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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const directorioSubidas = path.join(__dirname, "uploads");
const directorioImagenesGeneradas = path.join(__dirname, "generated_images"); // Directorio para imágenes

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
  HUGGING_FACE_API_KEY, // <- CONSISTENT NAME
} = process.env;

const isDev = NODE_ENV !== "production";

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: !isDev,
  sameSite: isDev ? "lax" : "none",
  maxAge: 3600 * 1000,
  path: "/",
};

// --- Constantes y configuraciones --- (Sin cambios aquí)
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

// --- Verificaciones de variables de entorno ---
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
if (!HUGGING_FACE_API_KEY) // <- Verifica el nombre consistente
  console.warn("⚠️ [Startup] ADVERTENCIA: HUGGING_FACE_API_KEY no configurada.");

const app = express();

// --- Inicialización de Clientes IA y Supabase ---
let clienteIA;
try {
  if (API_KEY) {
      clienteIA = new GoogleGenerativeAI(API_KEY);
      console.log("✅ Instancia de GoogleGenerativeAI creada.");
  } else {
      clienteIA = null;
      console.warn("⚠️ ADVERTENCIA: API_KEY (Google) no configurada. GoogleGenerativeAI no inicializado.");
  }
} catch (error) {
  console.error( "🚨 FATAL: Error al inicializar GoogleGenerativeAI:", error.message );
  clienteIA = null;
}
// No advertir si la API_KEY nunca fue proporcionada
// if (!clienteIA && API_KEY) console.warn("⚠️ ADVERTENCIA: Cliente Google Generative AI no inicializado.");


let supabase;
try {
    if(SUPABASE_URL && SUPABASE_KEY) {
        supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
        console.log("✅ Cliente Supabase inicializado.");
    } else {
        supabase = null;
        console.warn("⚠️ ADVERTENCIA: SUPABASE_URL o SUPABASE_KEY no configuradas. Supabase no inicializado.");
    }
} catch (error) {
  console.error("🚨 FATAL: Error al inicializar Supabase:", error.message);
  supabase = null;
}
// if (!supabase && SUPABASE_URL && SUPABASE_KEY) console.warn("⚠️ ADVERTENCIA: Cliente Supabase no inicializado.");


// --- Middlewares ---
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

// --- Middleware de Autenticación ---
const autenticarToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    console.log("[Auth] Fail: No token cookie.");
    return res.status(401).json({ error: "Token no proporcionado" });
  }
  if (!JWT_SECRET) {
     console.error("[Auth] Fail: JWT_SECRET no está configurado en el servidor.");
     return res.status(500).json({ error: "Error de configuración de autenticación."});
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

// --- Configuración de Multer ---
const almacenamiento = multer.diskStorage({
  destination: directorioSubidas,
  filename: (req, file, cb) => {
    const sufijoUnico = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const nombreOriginalLimpio = file.originalname
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-zA-Z0-9.\-_]/g, "_")
      .replace(/_{2,}/g, "_");
    const extension = path.extname(nombreOriginalLimpio) || ".pdf"; // Asume .pdf si no hay extensión
    const nombreBase = path.basename(nombreOriginalLimpio, extension);
    cb(null, `${sufijoUnico}-${nombreBase}${extension}`);
  },
});
// Instancia de Multer para filtrar PDFs específicamente (usado en generateText)
const subirPdf = multer({
  storage: almacenamiento,
  limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const isPdf = file.mimetype === "application/pdf";
    if (!isPdf) {
        console.warn(`⚠️ Rechazado archivo no PDF en ruta PDF: ${file.originalname} (${file.mimetype})`);
        // Pasar un error a Multer para que lo maneje el error handler global
        return cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', 'Solo se permiten archivos PDF.'), false);
    }
    cb(null, true);
  },
}).array("archivosPdf");

// Instancia de Multer más genérica (usado en /api/files si fuera necesario para otros tipos)
const upload = multer({ storage: almacenamiento });


// --- Crear directorios necesarios al inicio ---
[directorioSubidas, directorioImagenesGeneradas].forEach(dir => {
  if (!existsSync(dir)) {
    try {
      mkdirSync(dir, { recursive: true });
      console.log(`✅ Directorio creado: ${dir}`);
    } catch (error) {
        console.error(`🚨 FATAL: No se pudo crear el directorio ${dir}:`, error);
        // Podrías decidir terminar la aplicación si estos directorios son críticos
        // process.exit(1);
    }
  } else {
    console.log(`➡️ Directorio ya existe: ${dir}`);
  }
});


// --- Funciones Auxiliares (PDF, IA Texto, IA Imagen) ---

async function extraerTextoDePDF(rutaArchivo) {
    // ... (sin cambios)
    const nombreArchivoLog = path.basename(rutaArchivo);
    try {
        await fs.access(rutaArchivo); // Verifica si existe primero
        const bufferDatos = await fs.readFile(rutaArchivo);
        const datos = await pdfParse(bufferDatos);
        const textoExtraido = datos?.text?.trim() || null;
        return { texto: textoExtraido, error: null };
    } catch (error) {
        if (error.code === "ENOENT") {
            console.error(`❌ [PDF Extract] Archivo NO ENCONTRADO: ${rutaArchivo}. Comprobar persistencia en Render.`);
            return {
                texto: null,
                error: `Archivo no encontrado: ${nombreArchivoLog}`,
            };
        }
        console.error(`❌ [PDF Extract] Error procesando ${nombreArchivoLog}:`, error.message);
        return {
            texto: null,
            error: `Error al parsear ${nombreArchivoLog}: ${ error.message || "desconocido" }`,
        };
    }
}

async function generarContextoPDF(idUsuario, nombresArchivosUnicos) {
    if (!nombresArchivosUnicos || nombresArchivosUnicos.length === 0) return "";
    if (!supabase) return "[Error: Cliente Supabase no inicializado]";

    try {
        const { data: archivosDB, error } = await supabase
            .from("archivos_usuario")
            .select("nombre_archivo_unico, nombre_archivo_original")
            .eq("usuario_id", idUsuario)
            .in("nombre_archivo_unico", nombresArchivosUnicos);

        if (error) {
            console.error("[Context PDF] ❌ Error Supabase al obtener archivos:", error.message);
            return "[Error al recuperar archivos PDF del usuario]";
        }
        if (!archivosDB || archivosDB.length === 0) {
            console.warn("[Context PDF] No se encontraron archivos en Supabase para los nombres proporcionados.");
            return "[No se encontraron los archivos especificados en la base de datos]";
        }

        const archivosMap = new Map(
            archivosDB.map((f) => [f.nombre_archivo_unico, f.nombre_archivo_original])
        );

        let textoCompleto = "";
        for (const nombreArchivoUnico of nombresArchivosUnicos) {
            const nombreOriginal = archivosMap.get(nombreArchivoUnico);
            if (!nombreOriginal) {
                console.warn(`[Context PDF] No se encontró el nombre original para ${nombreArchivoUnico} en Supabase Map.`);
                continue; // Saltar si no encontramos la info del archivo
            }
            const ruta = path.join(directorioSubidas, nombreArchivoUnico);

            try {
                // Aquí también aplica la advertencia sobre filesystem efímero
                const { texto, error: pdfError } = await extraerTextoDePDF(ruta);
                if (texto) {
                     textoCompleto += `\n\n[${nombreOriginal}]\n${texto}`;
                } else if (pdfError) {
                    console.warn(`[Context PDF] ⚠️ Error extrayendo texto de ${nombreArchivoUnico} (Original: ${nombreOriginal}): ${pdfError}`);
                    // Opcional: Incluir una nota sobre el error en el contexto
                    // textoCompleto += `\n\n[Error al procesar archivo: ${nombreOriginal}]`;
                }
            } catch (err) { // Catch extra por si extraerTextoDePDF fallara inesperadamente
                console.error(`[Context PDF] ❌ Excepción interna al procesar ${nombreArchivoUnico}:`, err);
            }
        }
        return textoCompleto.trim();
    } catch (err) {
        console.error("[Context PDF] ❌ Excepción general:", err);
        return "[Error fatal al generar contexto desde archivos PDF]";
    }
}

async function generarRespuestaIA(prompt, historialDB, textoPDF, modeloReq, temp, topP, lang ) {
    if (!clienteIA) throw new Error("Servicio IA (Google) no disponible.");
    // ... (resto de la función sin cambios, ya era robusta)
    const nombreModelo = MODELOS_PERMITIDOS.includes(modeloReq)
        ? modeloReq
        : MODELO_POR_DEFECTO;
    if (modeloReq && nombreModelo !== modeloReq) {
        console.warn(`[Gen IA] ⚠️ Modelo no válido ('${modeloReq}'), usando por defecto: ${MODELO_POR_DEFECTO}`);
    }
    const configGeneracion = {
        temperature: !isNaN(temp) ? Math.max(0, Math.min(1, temp)) : TEMP_POR_DEFECTO,
        topP: !isNaN(topP) ? Math.max(0, Math.min(1, topP)) : TOPP_POR_DEFECTO,
    };

    const idioma = ["es", "en"].includes(lang) ? lang : IDIOMA_POR_DEFECTO;

    const langStrings = idioma === "en"
        ? { systemBase: "You are a helpful conversational assistant. Answer clearly and concisely in Markdown format.", systemPdf: `You are an assistant that answers *based solely* on the provided text. If the answer isn't in the text, state that clearly. Use Markdown format.\n\nReference Text (Context):\n"""\n{CONTEXT}\n"""\n\n`, label: "Question", error: "I'm sorry, there was a problem contacting the AI" }
        : { systemBase: "Eres un asistente conversacional útil. Responde de forma clara y concisa en formato Markdown.", systemPdf: `Eres un asistente que responde *basándose únicamente* en el texto proporcionado. Si la respuesta no está en el texto, indícalo claramente. Usa formato Markdown.\n\nTexto de Referencia (Contexto):\n"""\n{CONTEXT}\n"""\n\n`, label: "Pregunta", error: "Lo siento, hubo un problema al contactar la IA" };

    let instruccionSistema;
    if (textoPDF) {
        const contextoTruncado = textoPDF.length > MAX_LONGITUD_CONTEXTO
            ? textoPDF.substring(0, MAX_LONGITUD_CONTEXTO) + "... (context truncated)"
            : textoPDF;
        if (textoPDF.length > MAX_LONGITUD_CONTEXTO) console.warn(`[Gen IA] ✂️ Contexto PDF truncado.`);
        instruccionSistema = langStrings.systemPdf.replace( "{CONTEXT}", contextoTruncado );
    } else {
        instruccionSistema = langStrings.systemBase;
    }
    const promptCompletoUsuario = `${instruccionSistema}${langStrings.label}: ${prompt}`;
    const contenidoGemini = [
        ...historialDB
            .filter((m) => m.texto?.trim())
            .map((m) => ({ role: m.rol === "user" ? "user" : "model", parts: [{ text: m.texto }] })),
        { role: "user", parts: [{ text: promptCompletoUsuario }] },
    ];
    console.log( `[Gen IA] ➡️ Enviando ${contenidoGemini.length} partes a Gemini (${nombreModelo}).` );

    try {
        const modeloGemini = clienteIA.getGenerativeModel({ model: nombreModelo });
        const resultado = await modeloGemini.generateContent({
            contents: contenidoGemini,
            generationConfig: configGeneracion,
        });
        const response = resultado?.response;
        const textoRespuestaIA = response?.candidates?.[0]?.content?.parts?.[0]?.text;

        if (textoRespuestaIA) {
            console.log("[Gen IA] ✅ Respuesta recibida.");
            return textoRespuestaIA.trim();
        }
        const blockReason = response?.promptFeedback?.blockReason;
        const finishReason = response?.candidates?.[0]?.finishReason;
        console.warn( `[Gen IA] ⚠️ Respuesta vacía/bloqueada. Block: ${blockReason}, Finish: ${finishReason}` );
        let errorMsg = langStrings.error;
        if (blockReason) errorMsg += `. Razón bloqueo: ${blockReason}`;
        else if (finishReason && finishReason !== "STOP") errorMsg += `. Razón finalización: ${finishReason}`;
        else errorMsg += ". (Respuesta inválida)";
        return errorMsg; // Devolver mensaje de error informativo
    } catch (error) {
        console.error(`[Gen IA] ❌ Error API (${nombreModelo}):`, error.message);
        const detalleError = error.details || error.message || "Error no especificado";
        // Devolver un mensaje de error para el usuario
        return `${langStrings.error}. (Detalle técnico: ${detalleError})`;
    }
}

// --- Función Refinada para Generar y Guardar Imágenes ---
async function generarYGuardarImagen(promptTexto, modeloId = "stabilityai/stable-diffusion-2-1-base") {
  // Usa la variable de entorno consistente
  if (!HUGGING_FACE_API_KEY) {
    console.error("[Img Gen] Error: HUGGING_FACE_API_KEY no está configurado.");
    throw new Error("Servicio de generación de imágenes no disponible (sin token).");
  }
  if (!promptTexto || typeof promptTexto !== 'string' || promptTexto.trim() === '') {
    throw new Error("Se requiere un prompt de texto válido para generar la imagen.");
  }

  const modeloSeleccionado = modeloId || "stabilityai/stable-diffusion-2-1-base"; // Asegura un default
  console.log(`[Img Gen] Solicitando imagen para prompt: "${promptTexto}" usando modelo: ${modeloSeleccionado}`);
  const HUGGING_FACE_API_URL = `https://api-inference.huggingface.co/models/${modeloSeleccionado}`;
  console.log(`[Img Gen Debug] Llamando a API URL: ${HUGGING_FACE_API_URL}`);
  console.log(`[Img Gen Debug] HF API Key Presente: ${!!HUGGING_FACE_API_KEY}`);


  try {
    const respuestaAPI = await fetch(HUGGING_FACE_API_URL, {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${HUGGING_FACE_API_KEY}`,
            "Content-Type": "application/json",
            // "Accept": "image/jpeg" // Podemos quitarlo o especificarlo si sabemos el formato exacto
        },
        body: JSON.stringify({ inputs: promptTexto.trim() }),
    });

    if (!respuestaAPI.ok) {
        const status = respuestaAPI.status;
        let errorBodyText = "Error desconocido en la API de Hugging Face.";
        try {
           // Intenta leer como texto primero, que suele ser el caso del 404 'Not Found'
           errorBodyText = await respuestaAPI.text();
           // Intenta parsear como JSON si el texto parece JSON
           if (errorBodyText.trim().startsWith('{') || errorBodyText.trim().startsWith('[')) {
               const errorJson = JSON.parse(errorBodyText);
               errorBodyText = errorJson.error || (Array.isArray(errorJson.errors) ? errorJson.errors.join(', ') : errorBodyText);
               console.error(`[Img Gen] Error API Hugging Face (${status}):`, errorBodyText, errorJson);
           } else {
              console.error(`[Img Gen] Error API Hugging Face (${status}). Cuerpo del error (no JSON):`, errorBodyText);
           }
        } catch (e) {
           console.error(`[Img Gen] Error procesando cuerpo de error API (${status}):`, e.message);
           // errorBodyText se queda con lo que se leyó
        }
        // Personalizar mensaje de error para el usuario
        if (status === 401 || status === 403) errorBodyText = "Autenticación fallida con el servicio de imágenes.";
        else if (status === 404) errorBodyText = `Modelo de imagen '${modeloSeleccionado}' no encontrado o no disponible en la API.`;
        else if (status === 503) errorBodyText = "Servicio de imágenes está temporalmente sobrecargado o inicializando. Intente más tarde.";
        else if (status === 400) errorBodyText = "Solicitud inválida al servicio de imágenes (prompt inválido?).";

        throw new Error(`Error ${status}: ${errorBodyText}`); // Lanzar error con mensaje claro
      }

      // La respuesta OK debería ser la imagen binaria
      const arrayBufferImagen = await respuestaAPI.arrayBuffer();
      const bufferImagen = Buffer.from(arrayBufferImagen);

      // Guardar la imagen en el servidor
      const tipoImagen = respuestaAPI.headers.get('content-type') || 'image/jpeg'; // Obtener tipo si es posible
      const extension = tipoImagen.split('/')[1] || 'jpeg'; // Extraer extensión
      const nombreArchivoImagen = `${Date.now()}-${modeloSeleccionado.split('/').pop()}-${promptTexto.substring(0, 20).replace(/[^a-zA-Z0-9]/g, '_')}.${extension}`;
      const rutaArchivoImagen = path.join(directorioImagenesGeneradas, nombreArchivoImagen);

      try {
        await fs.writeFile(rutaArchivoImagen, bufferImagen);
        console.log(`[Img Gen] ✅ Imagen generada y guardada en: ${rutaArchivoImagen}`);
      } catch (writeError) {
          console.error(`[Img Gen] ❌ Error guardando archivo de imagen ${rutaArchivoImagen}:`, writeError);
          throw new Error("Error interno al guardar la imagen generada."); // Lanzar nuevo error
      }

      return {
        filePath: rutaArchivoImagen,
        fileName: nombreArchivoImagen,
        url: `/generated_images/${nombreArchivoImagen}`, // URL relativa
        // buffer: bufferImagen // No necesitamos devolver el buffer si devolvemos la URL
      };

    } catch (error) {
      // Si el error ya fue procesado y lanzado desde el bloque if (!respuestaAPI.ok)
      // o desde fs.writeFile, tendrá un mensaje claro.
      // Si es otro error (ej. fetch falla por red), se relanza.
      console.error("[Img Gen] ❌ Catch - Error en generarYGuardarImagen:", error.message);
      throw error; // Re-lanzar para que la ruta lo maneje
    }
}


// --- Rutas API ---

// Auth
app.post("/api/register", async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
    // ... (sin cambios en la lógica interna)
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: "Usuario/contraseña requeridos." });

    try {
      const contrasenaHasheada = await bcrypt.hash(password, 10);

      const { data, error } = await supabase
        .from("usuarios")
        .insert([ { nombre_usuario: username, contrasena_hash: contrasenaHasheada } ])
        .select("id")
        .single();

      if (error) {
        if (error.code === "23505") { // UNIQUE violation
          console.warn(`[Register] Fail: Usuario ya existe (${username})`);
          return res.status(409).json({ error: "Nombre de usuario ya existe." });
        }
        console.error(`[Register] Error Supabase: User ${username}`, error.message);
        return res.status(500).json({ error: "Error al registrar el usuario." });
      }

      console.log(`[Register] OK: User ${username} (ID: ${data.id})`);
      res.status(201).json({ message: "Registro exitoso.", userId: data.id });
    } catch (error) {
      console.error(`[Register] Catch Error: User ${username}`, error);
      next(error);
    }
});

app.post("/api/login", async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
    // ... (sin cambios en la lógica interna)
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: "Usuario/contraseña requeridos." });
    try {
      const { data: usuarioDB, error } = await supabase
        .from("usuarios")
        .select("id, nombre_usuario, contrasena_hash")
        .eq("nombre_usuario", username)
        .limit(1)
        .single();

      if (error || !usuarioDB) {
        console.log(`[Login] Fail: Usuario no encontrado '${username}' o error DB (${error?.message || 'No user'})`);
        return res.status(401).json({ error: "Credenciales inválidas." });
      }

      const passwordCorrecta = await bcrypt.compare( password, usuarioDB.contrasena_hash );
      if (!passwordCorrecta) {
        console.log(`[Login] Fail: Contraseña incorrecta para ${username}`);
        return res.status(401).json({ error: "Credenciales inválidas." });
      }

      const payload = { id: usuarioDB.id, username: usuarioDB.nombre_usuario };
      if (!JWT_SECRET) throw new Error("JWT_SECRET no configurado"); // Error interno grave
      const token = jwt.sign(payload, JWT_SECRET, JWT_OPTIONS);
      res.cookie("token", token, COOKIE_OPTIONS);
      console.log(`[Login] OK: User ${username}, cookie sent.`);
      res.json({ message: "Login exitoso.", user: payload });
    } catch (error) {
      console.error(`[Login] Catch Error: User ${username}`, error);
      next(error);
    }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token", COOKIE_OPTIONS);
  res.status(200).json({ message: "Logout exitoso." });
});

app.get("/api/verify-auth", autenticarToken, (req, res) => {
  res.json({ user: req.usuario }); // Devuelve el payload decodificado del token
});


// Rutas de archivos PDF
app.post( "/api/files", autenticarToken, upload.array("archivosPdf"), async (req, res) => { // Usar 'upload' genérico aquí
    if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
    // ... (sin cambios en lógica interna)
     try {
      const usuarioId = req.usuario.id;
      const archivos = req.files;

      if (!archivos || archivos.length === 0) {
        return res.status(400).json({ error: "No se subieron archivos."});
      }

      // Verificar tipos de archivo si es necesario aquí también, aunque multer podría haber filtrado
      // const archivosPdf = archivos.filter(f => f.mimetype === 'application/pdf');
      // if(archivosPdf.length !== archivos.length) { ... manejar error ... }

      const registros = archivos.map((file) => ({
        usuario_id: usuarioId,
        nombre_archivo_unico: file.filename,
        nombre_archivo_original: file.originalname,
      }));

      const { error } = await supabase.from("archivos_usuario").insert(registros);

      if (error) {
        console.error("[Upload Files] ❌ Error Supabase:", error.message);
        // TODO: Considerar borrar los archivos físicos si falla la BD
        archivos.forEach(async (file) => {
            try { await fs.unlink(path.join(directorioSubidas, file.filename)); } catch (e) {}
        });
        return res.status(500).json({ error: "Error al guardar información de archivos." });
      }

      console.log(`[Upload Files] ✅ ${archivos.length} archivo(s) guardado(s) para user ${usuarioId}.`);
      res.status(200).json({ mensaje: "Archivos subidos correctamente." });
    } catch (error) {
      console.error("[Upload Files] ❌ Catch Excepción:", error);
      res.status(500).json({ error: "Error interno al subir archivos" });
    }
});

app.get("/api/files", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
    // ... (sin cambios en lógica interna)
    try {
        const { data: archivos, error } = await supabase
          .from("archivos_usuario")
          .select("nombre_archivo_unico, nombre_archivo_original")
          .eq("usuario_id", req.usuario.id)
          .order("fecha_subida", { ascending: false });

        if (error) {
          console.error("[Files Get] Error Supabase:", error.message);
          return res.status(500).json({ error: "Error al obtener lista de archivos." });
        }

        res.json(
          archivos.map((a) => ({
            name: a.nombre_archivo_unico,
            originalName: a.nombre_archivo_original,
          })) || [] // Devolver array vacío si no hay archivos
        );
    } catch (error) {
        console.error("[Files Get] Error Catch User", req.usuario.id, ":", error);
        next(error);
    }
});

app.delete( "/api/files/:nombreArchivoUnico", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
    // ... (sin cambios en lógica interna, ya era robusta)
     const idUsuario = req.usuario.id;
    const nombreArchivoUnico = req.params.nombreArchivoUnico;

    if (!nombreArchivoUnico) return res.status(400).json({ error: "Nombre de archivo no especificado."});

    try {
      const { data: archivo, error } = await supabase
        .from("archivos_usuario")
        .select("id")
        .eq("usuario_id", idUsuario)
        .eq("nombre_archivo_unico", nombreArchivoUnico)
        .single();

      if (error || !archivo) {
        console.warn(`[File Delete] Archivo no encontrado en BD o no autorizado: ${nombreArchivoUnico} para user ${idUsuario}. Error: ${error?.message}`);
        return res.status(404).json({ error: "Archivo no encontrado o no autorizado." });
      }

      const { error: deleteError } = await supabase
        .from("archivos_usuario")
        .delete()
        .eq("id", archivo.id);

      if (deleteError) {
        console.error("[File Delete] Error Supabase al eliminar registro:", deleteError.message);
        throw new Error( "Error eliminando registro de la base de datos." ); // Mensaje más genérico al usuario
      }

      // Ahora, intenta borrar el archivo físico (best effort)
      const rutaArchivo = path.join(directorioSubidas, nombreArchivoUnico);
      try {
        await fs.unlink(rutaArchivo);
        console.log(`[File Delete] ✅ Archivo físico eliminado: ${rutaArchivo}`);
      } catch (fsError) {
        if (fsError.code === "ENOENT") {
          console.warn(`[File Delete] ⚠️ Archivo físico no encontrado (quizás ya borrado o no persistió): ${rutaArchivo}`);
        } else {
          console.error(`[File Delete] ❌ Error eliminando archivo físico ${rutaArchivo}:`, fsError);
          // No fallar la operación por esto, pero loguearlo
        }
      }

      console.log(`[File Delete] ✅ Registro de archivo eliminado de BD: ${nombreArchivoUnico} para user ${idUsuario}`);
      res.json({ message: "Archivo eliminado correctamente." });
    } catch (err) {
      console.error("[File Delete] ❌ Catch Excepción:", err);
      next(err); // Dejar que el handler global maneje el error
    }
});


// Rutas de Conversaciones
app.get("/api/conversations", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
    // ... (sin cambios en lógica interna)
    try {
        const { data: conversaciones, error } = await supabase
          .from("conversaciones")
          .select("id, titulo")
          .eq("usuario_id", req.usuario.id)
          .order("fecha_actualizacion", { ascending: false });

        if (error) {
          console.error("[Conv Get] Error Supabase:", error.message);
          return res.status(500).json({ error: "Error al obtener conversaciones." });
        }

        res.json(conversaciones || []);
    } catch (error) {
        console.error("[Conv Get] Error Catch User", req.usuario.id, ":", error);
        next(error);
    }
});

app.get( "/api/conversations/:id/messages", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
    // ... (sin cambios en lógica interna, la verificación de owner ya estaba implícita por el token)
    const { id } = req.params;
    if (!id) return res.status(400).json({ error: "ID de conversación no proporcionado."});

    try {
      // Verificar que la conversación pertenece al usuario es una buena práctica extra
      const { data: convOwner, error: ownerError } = await supabase
        .from("conversaciones")
        .select("id") // Solo necesito saber si existe y coincide
        .eq("id", id)
        .eq("usuario_id", req.usuario.id) // Clave de la verificación
        .maybeSingle(); // Puede que no exista

       if (ownerError) {
          console.error(`[Conv Msg Get] Error verificando dueño conv ${id} user ${req.usuario.id}:`, ownerError.message);
          return res.status(500).json({ error: "Error verificando la conversación."});
       }
       if (!convOwner) {
            console.warn(`[Conv Msg Get] Intento de acceso a conv ${id} (no encontrada o no autorizada) por user ${req.usuario.id}`);
            return res.status(404).json({ error: "Conversación no encontrada o acceso no autorizado." });
       }

      // Ahora que sabemos que el usuario es el dueño, obtenemos los mensajes
      const { data: mensajes, error: msgError } = await supabase
        .from("mensajes")
        .select("rol, texto, fecha_envio")
        .eq("conversacion_id", id)
        .order("fecha_envio", { ascending: true });

      if (msgError) {
        console.error(`[Conv Msg Get] Error Supabase obteniendo mensajes conv ${id}:`, msgError.message);
        return res.status(500).json({ error: "Error al obtener mensajes." });
      }

      res.json(mensajes || []);
    } catch (error) {
      console.error( `[Conv Msg Get] Catch Error User ${req.usuario.id}, ConvID ${id}:`, error );
      next(error);
    }
});

app.delete( "/api/conversations/:idConv", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
    // ... (sin cambios en lógica interna)
    const idConv = req.params.idConv;
    const idUsuario = req.usuario.id;
     if (!idConv) return res.status(400).json({ error: "ID de conversación no proporcionado."});

    try {
      // La condición eq("usuario_id", idUsuario) asegura que solo el dueño puede borrar
      const { error, count } = await supabase
        .from("conversaciones")
        .delete({ count: 'exact' }) // Pedir el conteo de filas borradas
        .eq("id", idConv)
        .eq("usuario_id", idUsuario);

      if (error) {
        console.error("[Conv Delete] Error Supabase:", error.message);
        return res.status(500).json({ error: "Error al eliminar conversación." });
      }

      if (count === 0) {
         console.warn(`[Conv Delete] Intento de borrar conv ${idConv} por user ${idUsuario}, pero no se encontró o no coincidió dueño.`);
         // Devolver 200 ok o 404, debatible. 200 ok ya que el estado deseado (no existe) se cumple.
      } else {
          console.log(`[Conv Delete] ✅ Conversación ${idConv} eliminada por usuario ${idUsuario}`);
      }

      res.json({ message: "Conversación eliminada correctamente." });
    } catch (err) {
      console.error("[Conv Delete] ❌ Catch Excepción:", err);
      next(err);
    }
});

app.put( "/api/conversations/:id/title", autenticarToken, async (req, res, next) => {
    if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
    // ... (sin cambios en lógica interna)
    const { id } = req.params;
    const { nuevoTitulo } = req.body;
    const usuarioId = req.usuario.id;
     if (!id) return res.status(400).json({ error: "ID de conversación no proporcionado."});

    if (!nuevoTitulo || typeof nuevoTitulo !== "string" || nuevoTitulo.trim().length === 0 || nuevoTitulo.trim().length > 100) { // Añadir límite de longitud
      return res.status(400).json({ error: "Título no válido o demasiado largo (máx 100 caracteres)." });
    }
    const tituloLimpio = nuevoTitulo.trim();

    try {
      const { data, error, count } = await supabase
        .from("conversaciones")
        .update({ titulo: tituloLimpio, fecha_actualizacion: new Date().toISOString() }) // Actualizar timestamp también
        .eq("id", id)
        .eq("usuario_id", usuarioId) // Solo el dueño
        .select({ count: 'exact' });

      if (error) {
        console.error(`[Conv Title] Error Supabase al actualizar conv ${id} user ${usuarioId}:`, error.message );
        return res.status(500).json({ error: "Error al actualizar el título." });
      }

      if (count === 0) {
         console.warn(`[Conv Title] Intento de actualizar conv ${id} por user ${usuarioId}, pero no se encontró o no coincidió dueño.`);
         return res.status(404).json({ error: "Conversación no encontrada o no autorizada."});
      }

      console.log(`[Conv Title] ✅ Título actualizado para conv ${id} por user ${usuarioId}`);
      res.status(200).json({ message: "Título actualizado correctamente." });
    } catch (err) {
      console.error( `[Conv Title] ❌ Catch Excepción conv ${id} user ${usuarioId}:`, err );
      next(err);
    }
});


// Rutas Principales de IA
app.post("/api/generateText", autenticarToken, subirPdf, async (req, res, next) => { // Usar subirPdf con filtro
    if (!supabase) return res.status(503).json({ error: "Servicio de base de datos no disponible." });
    if (!clienteIA) return res.status(503).json({ error: "Servicio de IA (Google) no disponible."});
    // ... (Lógica interna ya bastante robusta, sin cambios mayores)
    const usuarioId = req.usuario.id;
    const { prompt, conversationId: inputConversationId, modeloSeleccionado, temperatura, topP, idioma, archivosSeleccionados } = req.body;

    let archivosSeleccionadosArray = [];
    try {
        if (archivosSeleccionados) {
            archivosSeleccionadosArray = Array.isArray(archivosSeleccionados) ? archivosSeleccionados : JSON.parse(archivosSeleccionados || "[]");
            if (!Array.isArray(archivosSeleccionadosArray)) throw new Error("archivosSeleccionados debe ser un array JSON.");
        }
    } catch (parseError) {
        console.warn("[GenerateText] Error parseando archivosSeleccionados:", parseError.message);
        return res.status(400).json({ error: "Formato de archivosSeleccionados inválido." });
    }

    let conversationId = inputConversationId;
    let isNewConversation = false;

    try {
        // 1. Asegurar que existe una conversación
        if (!conversationId) {
            const { data: convData, error: convError } = await supabase
                .from("conversaciones")
                .insert([{
                    usuario_id: usuarioId,
                    titulo: (prompt || "Conversación con archivo(s)").trim().split(/\s+/).slice(0, 5).join(" ") || "Nueva Conversación"
                }])
                .select("id")
                .single();

            if (convError) throw new Error(`Error creando conversación: ${convError.message}`);
            conversationId = convData.id;
            isNewConversation = true;
        }

        // 2. Guardar mensaje de usuario (si existe)
        if (prompt) {
            const { error: msgError } = await supabase.from("mensajes")
              .insert([{ conversacion_id: conversationId, rol: "user", texto: prompt }]);
            if(msgError) console.error(`[GenerateText] Error guardando mensaje de usuario conv ${conversationId}:`, msgError.message); // No fatal
        }

        // 3. Procesar archivos nuevos (si existen)
        const archivosNuevos = req.files || [];
        if (archivosNuevos.length > 0) {
            const registrosArchivos = archivosNuevos.map((file) => ({
                usuario_id: usuarioId,
                nombre_archivo_unico: file.filename,
                nombre_archivo_original: file.originalname,
            }));
            const { error: fileInsertError } = await supabase.from("archivos_usuario").insert(registrosArchivos);
            if (fileInsertError) {
                console.error("[Archivos en GenerateText] ❌ Error al insertar archivos:", fileInsertError.message);
                // Limpiar archivos subidos si falla la BD
                archivosNuevos.forEach(async f => { try { await fs.unlink(f.path); } catch(e){} });
                throw new Error("No se pudo guardar la información de los archivos PDF.");
            }
            console.log(`[Archivos en GenerateText] ✅ ${archivosNuevos.length} archivo(s) PDF guardado(s) en BD.`);
        }

        // 4. Generar contexto PDF (si hay archivos seleccionados o nuevos)
        const nombresArchivosParaContexto = [
            ...archivosSeleccionadosArray,
            ...archivosNuevos.map((f) => f.filename),
        ].filter(Boolean);

        let contextoPDF = "";
        if (nombresArchivosParaContexto.length > 0) {
            contextoPDF = await generarContextoPDF(usuarioId, nombresArchivosParaContexto);
        }

        // 5. Si no hay prompt Y no hay contexto PDF útil -> Error o mensaje informativo
         if (!prompt && !contextoPDF) {
            // Si se intentó subir archivos pero falló la extracción o no se encontraron
             if (nombresArchivosParaContexto.length > 0 && !contextoPDF.includes('[')) { // Comprobación básica si contextoPDF está vacío o es solo errores
                 return res.status(400).json({ error: "No se pudo procesar el contenido de los archivos proporcionados."});
             }
            // Si simplemente no se envió nada útil
            return res.status(400).json({ error: "Se requiere un prompt o archivos PDF válidos para continuar." });
        }

        // 6. Cargar historial para la IA
        const { data: historial, error: errorHist } = await supabase
            .from("mensajes")
            .select("rol, texto")
            .eq("conversacion_id", conversationId)
            .order("fecha_envio", { ascending: true });

        if (errorHist) throw new Error(`Error cargando historial: ${errorHist.message}`);

        // 7. Generar respuesta IA
        const promptParaIA = prompt || (idioma === 'es' ? "Resume el contenido del/los archivo(s) proporcionado(s)." : "Summarize the content of the provided file(s).");
        const respuestaIA = await generarRespuestaIA( promptParaIA, historial || [], contextoPDF, modeloSeleccionado, parseFloat(temperatura), parseFloat(topP), idioma );

        // 8. Guardar respuesta del modelo
        const { error: modelMsgError } = await supabase
          .from("mensajes")
          .insert([{ conversacion_id: conversationId, rol: "model", texto: respuestaIA }]);
        if(modelMsgError) console.error(`[GenerateText] Error guardando mensaje de modelo conv ${conversationId}:`, modelMsgError.message); // No fatal

        // 9. Devolver al frontend
        res.status(200).json({
            respuesta: respuestaIA,
            isNewConversation,
            conversationId,
        });

    } catch (error) {
        console.error("[GenerateText] ❌ Catch Error general:", error.message, error.stack);
        // Pasar el error al manejador global
        next(error);
    }
});


app.post("/api/generateImage", autenticarToken, async (req, res, next) => {
  console.log(`[API /generateImage] Solicitud recibida por user ${req.usuario.id}. Body:`, req.body);
  const { prompt } = req.body;
  const { modelo } = req.query; // Permitir especificar modelo, ej. ?modelo=stabilityai/stable-diffusion-2-1-base

  if (!prompt || typeof prompt !== "string" || prompt.trim().length === 0) {
    return res.status(400).json({ error: "Prompt inválido o vacío." });
  }
  if (!HUGGING_FACE_API_KEY) {
     return res.status(503).json({ error: "Servicio de generación de imágenes no configurado." });
  }

  try {
    // Llama a la función que genera Y GUARDA la imagen
    const resultadoImagen = await generarYGuardarImagen(prompt.trim(), modelo); // Pasamos modelo opcional

    // Devolvemos la URL relativa donde se puede acceder a la imagen
    res.status(200).json({
      message: "Imagen generada exitosamente.",
      fileName: resultadoImagen.fileName,
      imageUrl: resultadoImagen.url // --> /generated_images/nombre_archivo.jpeg
    });

  } catch (error) {
    console.error("[API /generateImage] ❌ Catch Error:", error.message);
    // El error lanzado por generarYGuardarImagen ya debería ser informativo
    // Determinar status code basado en el mensaje de error puede ser útil
    let statusCode = 500;
    if (error.message) {
        if (error.message.includes("401") || error.message.includes("403")) statusCode = 403; // Auth error
        else if (error.message.includes("404")) statusCode = 404; // Model not found
        else if (error.message.includes("503")) statusCode = 503; // Service unavailable / overloaded
        else if (error.message.includes("400") || error.message.includes("inválido")) statusCode = 400; // Bad request
        else if (error.message.includes("token")) statusCode = 503; // Config error (token missing)
    }
    // Pasamos el error al manejador global o devolvemos aquí
    // next(error); // Opción 1: Usar handler global
    res.status(statusCode).json({ error: error.message || "Error desconocido al generar la imagen." }); // Opción 2: Devolver aquí
  }
});

// --- Servir Archivos Estáticos ---
// Servir imágenes generadas desde una ruta pública
app.use('/generated_images', express.static(directorioImagenesGeneradas, {
    // Opciones opcionales para el caché, etc.
    // maxAge: '1d'
}));
// Considera si también necesitas servir 'uploads' o si solo se usan internamente


// --- Manejador de Errores Global ---
app.use((err, req, res, next) => {
  console.error("‼️ Global Error Handler:", err.message);
  // Loguear stack trace en desarrollo para más detalles
  if (NODE_ENV === "development" && err.stack) {
    console.error(err.stack);
  }

  // Si los encabezados ya se enviaron, delegar al manejador por defecto de Express
  if (res.headersSent) {
    console.error("‼️ Error caught AFTER headers were sent! Delegating to default handler.");
    return next(err);
  }

  let statusCode = err.status || (err instanceof multer.MulterError ? 400 : 500);
  let mensajeUsuario = err.message || "Error interno del servidor.";

  // Personalizar mensajes y códigos basados en tipos de error conocidos
  if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
          statusCode = 413;
          mensajeUsuario = `Archivo demasiado grande (Máx: ${TAMANO_MAX_ARCHIVO_MB} MB).`;
      } else if (err.code === 'LIMIT_UNEXPECTED_FILE' && err.message === 'Solo se permiten archivos PDF.') {
          statusCode = 400; // Bad Request - tipo de archivo incorrecto
          mensajeUsuario = err.message;
      } else {
          statusCode = 400;
          mensajeUsuario = `Error en subida de archivo: ${err.field ? `campo '${err.field}'` : ''} ${err.code}`;
      }
  } else if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
      statusCode = 400;
      mensajeUsuario = "Petición mal formada (JSON inválido).";
  } else if (err.message.includes("Servicio IA") || err.message.includes("Servicio de base de datos") || err.message.includes("servicio no disponible")) {
      statusCode = 503; // Service Unavailable
      // mensajeUsuario ya suele ser descriptivo
  } else if (error.message && (error.message.includes("401") || error.message.includes("403") || error.message.includes("Autenticación"))) {
       statusCode = 403; // Forbidden or Unauthorized
       mensajeUsuario = "Error de autenticación o autorización."; // Mensaje genérico seguro
   } else if (error.message && error.message.includes("404")) {
        statusCode = 404; // Not found
        mensajeUsuario = "Recurso no encontrado.";
    }
  // Si es un 500 y no tiene mensaje específico, se queda "Error interno del servidor."

  res.status(statusCode).json({ error: mensajeUsuario });
});


// --- Iniciar Servidor ---
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`🔗 Acceso local: http://localhost:${PORT}`);
  console.log(`📂 Directorio uploads: ${directorioSubidas}`);
  console.log(`🖼️ Directorio generated_images: ${directorioImagenesGeneradas}`);
  if (!isDev) {
    console.log("🟢 Modo Producción");
  } else {
    console.log("🟡 Modo Desarrollo");
  }
  // Verificar conectividad básica si es posible
  if (supabase) console.log("✅ Supabase parece inicializado."); else console.warn("⚠️ Supabase NO inicializado.");
  if (clienteIA) console.log("✅ Cliente Google GenAI parece inicializado."); else console.warn("⚠️ Cliente Google GenAI NO inicializado.");
  if (HUGGING_FACE_API_KEY) console.log("✅ Hugging Face API Key presente."); else console.warn("⚠️ Hugging Face API Key NO presente.");
});