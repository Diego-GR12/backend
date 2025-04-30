import { GoogleGenerativeAI } from "@google/generative-ai";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import pdfParse from "pdf-parse/lib/pdf-parse.js";
import path from "path";
import fs from "fs/promises";
import { existsSync, mkdirSync } from 'fs';
import { fileURLToPath } from "url";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { createClient } from "@supabase/supabase-js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const {
    PORT: PUERTO = 3001,
    DB_HOST, DB_USER, DB_PASSWORD, DB_NAME,
    API_KEY, JWT_SECRET,
    NODE_ENV = 'development',
    SUPABASE_URL, 
    SUPABASE_KEY
} = process.env;



const TAMANO_MAX_ARCHIVO_MB = 20;
const MAX_CARACTERES_POR_PDF = 10000;
const MAX_LONGITUD_CONTEXTO = 30000;
const MODELOS_PERMITIDOS = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash", "gemini-2.5-pro-exp-03-25"];
const MODELO_POR_DEFECTO = "gemini-1.5-flash";
const TEMP_POR_DEFECTO = 0.7;
const TOPP_POR_DEFECTO = 0.9;
const IDIOMA_POR_DEFECTO = 'es';
const JWT_OPTIONS = { expiresIn: '1h' };
const COOKIE_OPTIONS = {
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 3600 * 1000,
    path: '/',
};

console.log('[Startup] JWT_SECRET cargado:', JWT_SECRET ? `${JWT_SECRET.substring(0, 3)}... (longitud: ${JWT_SECRET.length})` : '¡NO CARGADO!');
if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.warn('⚠️ [Startup] ADVERTENCIA: JWT_SECRET no definido o inseguro!');
}
if (!API_KEY) console.warn("⚠️ [Startup] ADVERTENCIA: API_KEY (Google) no configurada.");
if (!SUPABASE_URL) console.warn("⚠️ [Startup] ADVERTENCIA: SUPABASE_URL no configurada.");
if (!SUPABASE_KEY) console.warn("⚠️ [Startup] ADVERTENCIA: SUPABASE_KEY no configurada.");

const app = express();



let clienteIA;
try {
    clienteIA = new GoogleGenerativeAI(API_KEY);
    console.log("✅ Instancia de GoogleGenerativeAI creada.");
} catch (error) {
    console.error("🚨 FATAL: Error al inicializar GoogleGenerativeAI:", error.message);
    clienteIA = null;
}
if (!clienteIA) console.warn("⚠️ ADVERTENCIA: Cliente Google Generative AI no inicializado.");

// Inicializamos el cliente Supabase
let supabase;
try {
    supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
    console.log("✅ Cliente Supabase inicializado.");
} catch (error) {
    console.error("🚨 FATAL: Error al inicializar Supabase:", error.message);
    supabase = null;
}
if (!supabase) console.warn("⚠️ ADVERTENCIA: Cliente Supabase no inicializado.");



// Definir los orígenes permitidos (local y producción)
const origenesPermitidos = [           // frontend local
  'https://chat-frontend-y914.onrender.com' // tu frontend en producción (ajústalo si usas otro)
];

// Configurar CORS antes de cualquier middleware
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || origenesPermitidos.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('❌ No permitido por CORS: ' + origin));
    }
  },
  credentials: true
}));
app.use(cookieParser());
app.use(express.json());

const autenticarToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        console.log('[Auth] Fail: No token cookie.');
        return res.status(401).json({ error: 'Token no proporcionado' });
    }
    jwt.verify(token, JWT_SECRET, (err, usuarioToken) => {
        if (err) {
            const isExpired = err.name === 'TokenExpiredError';
            console.error(`[Auth] Fail: Token verify error (${err.name})${isExpired ? ' - Expired' : ''}.`);
            if (isExpired) res.clearCookie('token', COOKIE_OPTIONS);
            return res.status(isExpired ? 401 : 403).json({ error: isExpired ? 'Token expirado' : 'Token inválido' });
        }
        req.usuario = usuarioToken;
        next();
    });
};

const almacenamiento = multer.diskStorage({
    destination: directorioSubidas,
    filename: (req, file, cb) => {
        const sufijoUnico = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
        const nombreOriginalLimpio = file.originalname
            .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
            .replace(/[^a-zA-Z0-9.\-_]/g, "_").replace(/_{2,}/g, '_');
        const extension = path.extname(nombreOriginalLimpio) || '.pdf';
        const nombreBase = path.basename(nombreOriginalLimpio, extension);
        cb(null, `${sufijoUnico}-${nombreBase}${extension}`);
    },
});
const subir = multer({
    storage: almacenamiento,
    limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const isPdf = file.mimetype === 'application/pdf';
        if (!isPdf) console.warn(`⚠️ Rechazado archivo no PDF: ${file.originalname} (${file.mimetype})`);
        cb(null, isPdf);
    }
}).array("archivosPdf");

async function extraerTextoDePDF(rutaArchivo) {
    const nombreArchivoLog = path.basename(rutaArchivo);
    try {
        await fs.access(rutaArchivo);
        const bufferDatos = await fs.readFile(rutaArchivo);
        const datos = await pdfParse(bufferDatos);
        const textoExtraido = datos?.text?.trim() || null;
        return { texto: textoExtraido, error: null };
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.error(`❌ [PDF Extract] Archivo NO ENCONTRADO: ${rutaArchivo}`);
            return { texto: null, error: `Archivo no encontrado: ${nombreArchivoLog}` };
        }
        console.error(`❌ [PDF Extract] Error procesando ${nombreArchivoLog}:`, error.message);
        return { texto: null, error: `Error al parsear ${nombreArchivoLog}: ${error.message || 'desconocido'}` };
    }
}

async function generarContextoPDF(idUsuario, nombresArchivosUnicos) {
    if (!nombresArchivosUnicos || nombresArchivosUnicos.length === 0) return "";

    try {
        // 1. Obtener metadatos de archivos desde Supabase
        const { data: archivosDB, error } = await supabase
            .from('archivos_usuario')
            .select('nombre_archivo_unico, nombre_archivo_original')
            .eq('usuario_id', idUsuario)
            .in('nombre_archivo_unico', nombresArchivosUnicos);

        if (error) {
            console.error("[Context PDF] ❌ Error Supabase:", error.message);
            return "[Error al recuperar archivos PDF del usuario]";
        }

        // 2. Asociar archivos encontrados
        const archivosMap = new Map(archivosDB.map(f => [f.nombre_archivo_unico, f.nombre_archivo_original]));

        // 3. Leer y parsear los archivos locales
        let textoCompleto = "";
        for (const nombreArchivoUnico of nombresArchivosUnicos) {
            const nombreOriginal = archivosMap.get(nombreArchivoUnico);
            const ruta = path.join(directorioSubidas, nombreArchivoUnico);

            try {
                const buffer = await fs.readFile(ruta);
                const datos = await pdfParse(buffer);
                textoCompleto += `\n\n[${nombreOriginal}]\n${datos.text.trim()}`;
            } catch (err) {
                console.warn(`[Context PDF] ⚠️ No se pudo leer ${nombreArchivoUnico}:`, err.message);
            }
        }

        return textoCompleto.trim();

    } catch (err) {
        console.error("[Context PDF] ❌ Excepción:", err);
        return "[Error al generar contexto desde archivos PDF]";
    }
}
async function generarRespuestaIA(prompt, historialDB, textoPDF, modeloReq, temp, topP, lang) {
    if (!clienteIA) throw new Error("Servicio IA no disponible.");
    const nombreModelo = MODELOS_PERMITIDOS.includes(modeloReq) ? modeloReq : MODELO_POR_DEFECTO;
    if (modeloReq && nombreModelo !== modeloReq) {
        console.warn(`[Gen IA] ⚠️ Modelo no válido ('${modeloReq}'), usando por defecto: ${MODELO_POR_DEFECTO}`);
    }
    const configGeneracion = {
        temperature: !isNaN(temp) ? Math.max(0, Math.min(1, temp)) : TEMP_POR_DEFECTO,
        topP: !isNaN(topP) ? Math.max(0, Math.min(1, topP)) : TOPP_POR_DEFECTO
    };
    const idioma = ['es', 'en'].includes(lang) ? lang : IDIOMA_POR_DEFECTO;
    const langStrings = idioma === 'en' ? {
        systemBase: "You are a helpful conversational assistant. Answer clearly and concisely in Markdown format.",
        systemPdf: `You are an assistant that answers *based solely* on the provided text. If the answer isn't in the text, state that clearly. Use Markdown format.\n\nReference Text (Context):\n"""\n{CONTEXT}\n"""\n\n`,
        label: "Question",
        error: "I'm sorry, there was a problem contacting the AI"
    } : {
        systemBase: "Eres un asistente conversacional útil. Responde de forma clara y concisa en formato Markdown.",
        systemPdf: `Eres un asistente que responde *basándose únicamente* en el texto proporcionado. Si la respuesta no está en el texto, indícalo claramente. Usa formato Markdown.\n\nTexto de Referencia (Contexto):\n"""\n{CONTEXT}\n"""\n\n`,
        label: "Pregunta",
        error: "Lo siento, hubo un problema al contactar la IA"
    };
    let instruccionSistema;
    if (textoPDF) {
        const contextoTruncado = textoPDF.length > MAX_LONGITUD_CONTEXTO ? textoPDF.substring(0, MAX_LONGITUD_CONTEXTO) + "... (context truncated)" : textoPDF;
        if (textoPDF.length > MAX_LONGITUD_CONTEXTO) console.warn(`[Gen IA] ✂️ Contexto PDF truncado.`);
        instruccionSistema = langStrings.systemPdf.replace('{CONTEXT}', contextoTruncado);
    } else {
        instruccionSistema = langStrings.systemBase;
    }
    const promptCompletoUsuario = `${instruccionSistema}${langStrings.label}: ${prompt}`;
    const contenidoGemini = [
        ...historialDB.filter(m => m.texto?.trim()).map(m => ({ role: m.rol === 'user' ? 'user' : 'model', parts: [{ text: m.texto }] })),
        { role: 'user', parts: [{ text: promptCompletoUsuario }] }
    ];
    console.log(`[Gen IA] ➡️ Enviando ${contenidoGemini.length} partes a Gemini (${nombreModelo}).`);
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
        else if (finishReason && finishReason !== 'STOP') errorMsg += `. Razón finalización: ${finishReason}`;
        else errorMsg += ". (Respuesta inválida)";
        return errorMsg;
    } catch (error) {
        console.error(`[Gen IA] ❌ Error API (${nombreModelo}):`, error.message);
        const detalleError = error.details || error.message || 'Error no especificado';
        return `${langStrings.error}. (Detalle: ${detalleError})`;
    }
}

app.post("/api/register", async (req, res, next) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });

    try {
        const contrasenaHasheada = await bcrypt.hash(password, 10);

        const { data, error } = await supabase
            .from('usuarios')
            .insert([{ nombre_usuario: username, contrasena_hash: contrasenaHasheada }])
            .select('id') // Obtener el ID generado
            .single();

        if (error) {
            if (error.code === '23505') { // Código PostgreSQL para UNIQUE violation
                console.warn(`[Register] Fail: Usuario ya existe (${username})`);
                return res.status(409).json({ error: "Nombre de usuario ya existe." });
            }
            console.error(`[Register] Error: User ${username}`, error.message);
            return res.status(500).json({ error: "Error al registrar el usuario." });
        }

        console.log(`[Register] OK: User ${username} (ID: ${data.id})`);
        res.status(201).json({ message: "Registro exitoso.", userId: data.id });

    } catch (error) {
        console.error(`[Register] Error: User ${username}`, error);
        next(error);
    }
});


app.post("/api/login", async (req, res, next) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Usuario/contraseña requeridos." });
    try {
        const { data: usuarios, error } = await supabase
            .from('usuarios')
            .select('id, nombre_usuario, contrasena_hash')
            .eq('nombre_usuario', username)
            .limit(1)
            .single();

        if (error || !usuarios) {
            console.log(`[Login] Fail: Usuario no encontrado o error (${error?.message})`);
            return res.status(401).json({ error: "Credenciales inválidas." });
        }

        const usuario = usuarios;
        const passwordCorrecta = await bcrypt.compare(password, usuario.contrasena_hash);
        if (!passwordCorrecta) {
            console.log(`[Login] Fail: Contraseña incorrecta para ${username}`);
            return res.status(401).json({ error: "Credenciales inválidas." });
        }

        const payload = { id: usuario.id, username: usuario.nombre_usuario };
        const token = jwt.sign(payload, JWT_SECRET, JWT_OPTIONS);
        res.cookie('token', token, COOKIE_OPTIONS);
        console.log(`[Login] OK: User ${username}, cookie sent.`);
        res.json({ message: "Login exitoso.", user: payload });
    } catch (error) {
        console.error(`[Login] Error: User ${username}`, error);
        next(error);
    }
});


app.post("/api/logout", (req, res) => {
    res.clearCookie('token', COOKIE_OPTIONS);
    res.status(200).json({ message: "Logout exitoso." });
});

app.get("/api/verify-auth", autenticarToken, (req, res) => {
    res.json({ user: req.usuario });
});


// Configurar el directorio de subidas
const uploadDir = path.join(__dirname, 'uploads');
if (!existsSync(uploadDir)) {
    mkdirSync(uploadDir, { recursive: true });
  console.log(`Directorio de subidas creado: ${uploadDir}`);
} else {
  console.log(`Directorio de subidas ya existe: ${uploadDir}`);
}

// Configurar multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueName = `${Date.now()}-${file.originalname}`;
    cb(null, uniqueName);
  }
});
const upload = multer({ storage });


app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://chat-frontend-y914.onrender.com' // actualiza con tu dominio de frontend
  ],
  credentials: true
}));
app.use(cookieParser());
app.use(express.json());
app.post("/api/files", autenticarToken, upload.array("archivosPdf"), async (req, res) => {
    try {
      const usuarioId = req.usuario.id;
      const archivos = req.files;
  
      const queries = archivos.map(file => {
        return pool.execute(
          "INSERT INTO archivos_usuario (usuario_id, nombre_archivo_unico, nombre_archivo_original) VALUES (?, ?, ?)",
          [usuarioId, file.filename, file.originalname]
        );
      });
  
      await Promise.all(queries);
      res.status(200).json({ mensaje: "Archivos subidos correctamente." });
    } catch (error) {
      console.error("[Upload Files] Error:", error);
      res.status(500).json({ error: "Error al subir archivos" });
    }
  });

app.get("/api/files", autenticarToken, async (req, res, next) => {
    try {
        const { data: archivos, error } = await supabase
            .from('archivos_usuario')
            .select('nombre_archivo_unico, nombre_archivo_original')
            .eq('usuario_id', req.usuario.id)
            .order('fecha_subida', { ascending: false });

        if (error) {
            console.error("[Files Get] Error Supabase:", error.message);
            return res.status(500).json({ error: "Error al obtener lista de archivos." });
        }

        res.json(
            archivos.map(a => ({
                name: a.nombre_archivo_unico,
                originalName: a.nombre_archivo_original
            }))
        );
    } catch (error) {
        console.error("[Files Get] Error User", req.usuario.id, ":", error);
        next(error);
    }
});


app.delete("/api/files/:nombreArchivoUnico", autenticarToken, async (req, res, next) => {
    const idUsuario = req.usuario.id;
    const nombreArchivoUnico = req.params.nombreArchivoUnico;

    try {
        // Buscar el archivo en la BD
        const { data: archivo, error } = await supabase
            .from('archivos_usuario')
            .select('id')
            .eq('usuario_id', idUsuario)
            .eq('nombre_archivo_unico', nombreArchivoUnico)
            .single();

        if (error || !archivo) {
            console.warn(`[File Delete] Archivo no encontrado o no autorizado: ${nombreArchivoUnico}`);
            return res.status(404).json({ error: "Archivo no encontrado." });
        }

        // Eliminar de la BD
        const { error: deleteError } = await supabase
            .from('archivos_usuario')
            .delete()
            .eq('id', archivo.id);

        if (deleteError) {
            throw new Error("Error eliminando de la base de datos: " + deleteError.message);
        }

        // Eliminar del sistema de archivos
        const rutaArchivo = path.join(directorioSubidas, nombreArchivoUnico);
        try {
            await fs.unlink(rutaArchivo);
        } catch (fsError) {
            if (fsError.code !== 'ENOENT') throw fsError; // Ignorar si ya no existe
        }

        console.log(`[File Delete] ✅ Archivo eliminado: ${nombreArchivoUnico}`);
        res.json({ message: "Archivo eliminado correctamente." });

    } catch (err) {
        console.error("[File Delete] ❌ Excepción:", err);
        next(err);
    }
});
app.get("/api/conversations", autenticarToken, async (req, res, next) => {
    try {
        const { data: conversaciones, error } = await supabase
            .from('conversaciones')
            .select('id, titulo')
            .eq('usuario_id', req.usuario.id)
            .order('fecha_actualizacion', { ascending: false });

        if (error) {
            console.error("[Conv Get] Error Supabase:", error.message);
            return res.status(500).json({ error: "Error al obtener conversaciones." });
        }

        res.json(conversaciones);
    } catch (error) {
        console.error("[Conv Get] Error User", req.usuario.id, ":", error);
        next(error);
    }
});


app.get("/api/conversations/:id/messages", autenticarToken, async (req, res, next) => {
    const { id } = req.params;
    try {
        const { data: mensajes, error } = await supabase
            .from('mensajes')
            .select('rol, texto, fecha_envio')
            .eq('conversacion_id', id)
            .order('fecha_envio', { ascending: true });

        if (error) {
            console.error("[Conv Msg Get] Error Supabase:", error.message);
            return res.status(500).json({ error: "Error al obtener mensajes." });
        }

        res.json(mensajes);
    } catch (error) {
        console.error("[Conv Msg Get] Error User", req.usuario.id, "ConvID", id, ":", error);
        next(error);
    }
});

app.delete("/api/conversations/:idConv", autenticarToken, async (req, res, next) => {
    const idConv = req.params.idConv;
    const idUsuario = req.usuario.id;

    try {
        const { error } = await supabase
            .from('conversaciones')
            .delete()
            .eq('id', idConv)
            .eq('usuario_id', idUsuario);

        if (error) {
            console.error("[Conv Delete] Error Supabase:", error.message);
            return res.status(500).json({ error: "Error al eliminar conversación." });
        }

        console.log(`[Conv Delete] ✅ Conversación ${idConv} eliminada por usuario ${idUsuario}`);
        res.json({ message: "Conversación eliminada correctamente." });

    } catch (err) {
        console.error("[Conv Delete] ❌ Excepción:", err);
        next(err);
    }
});

app.put("/api/conversations/:id/title", autenticarToken, async (req, res, next) => {
    const { id } = req.params;
    const { nuevoTitulo } = req.body;
    const usuarioId = req.usuario.id;

    if (!nuevoTitulo || typeof nuevoTitulo !== 'string') {
        return res.status(400).json({ error: "Título no válido." });
    }

    try {
        const { error } = await supabase
            .from('conversaciones')
            .update({ titulo: nuevoTitulo })
            .eq('id', id)
            .eq('usuario_id', usuarioId);

        if (error) {
            console.error(`[Conv Title] Error al actualizar título para conv ${id} user ${usuarioId}:`, error.message);
            return res.status(500).json({ error: "Error al actualizar el título." });
        }

        console.log(`[Conv Title] ✅ Título actualizado para conv ${id} por user ${usuarioId}`);
        res.status(200).json({ message: "Título actualizado correctamente." });

    } catch (err) {
        console.error(`[Conv Title] ❌ Excepción conv ${id} user ${usuarioId}:`, err);
        next(err);
    }
});

app.post("/api/generateText", autenticarToken, subir, async (req, res) => {
    const usuarioId = req.usuario.id;
    const {
        prompt,
        conversationId: inputConversationId,
        modeloSeleccionado,
        temperatura,
        topP,
        idioma,
        archivosSeleccionados
    } = req.body;

    const archivosSeleccionadosArray = Array.isArray(archivosSeleccionados)
        ? archivosSeleccionados
        : JSON.parse(archivosSeleccionados || "[]");

    let conversationId = inputConversationId;
    let isNewConversation = false;

    try {
        // Crear conversación si no existe
        if (!conversationId) {
            const { data, error } = await supabase
                .from("conversaciones")
                .insert([{ usuario_id: usuarioId, titulo: "Nueva conversación" }])
                .select("id")
                .single();

            if (error) throw new Error("Error creando conversación: " + error.message);

            conversationId = data.id;
            isNewConversation = true;
        }

        // Guardar mensaje del usuario
        await supabase
            .from("mensajes")
            .insert([{ conversacion_id: conversationId, rol: "user", texto: prompt }]);

        // ✅ Guardar archivos nuevos en la base de datos
        const archivosNuevos = req.files || [];
        if (archivosNuevos.length > 0) {
            const registrosArchivos = archivosNuevos.map(file => ({
                usuario_id: usuarioId,
                nombre_archivo_unico: file.filename,
                nombre_archivo_original: file.originalname
            }));

            const { error: errorInsertarArchivos } = await supabase
                .from("archivos_usuario")
                .insert(registrosArchivos);

            if (errorInsertarArchivos) {
                console.error("[Archivos] ❌ Error al insertar archivos:", errorInsertarArchivos.message);
                throw new Error("No se pudieron guardar los archivos PDF.");
            }

            console.log(`[Archivos] ✅ ${archivosNuevos.length} archivo(s) guardado(s) en la base de datos.`);
        }

        // Combinar archivos seleccionados + nuevos
        const nombresArchivos = [
            ...archivosSeleccionadosArray,
            ...archivosNuevos.map(f => f.filename)
        ];

        // Generar contexto desde los PDFs
        const contextoPDF = await generarContextoPDF(usuarioId, nombresArchivos);

        // Cargar historial de mensajes
        const { data: historial, error: errorHist } = await supabase
            .from("mensajes")
            .select("rol, texto")
            .eq("conversacion_id", conversationId)
            .order("fecha_envio", { ascending: true });

        if (errorHist) throw new Error("Error cargando historial: " + errorHist.message);

        // Obtener respuesta de IA
        const respuestaIA = await generarRespuestaIA(
            prompt,
            historial,
            contextoPDF,
            modeloSeleccionado,
            parseFloat(temperatura),
            parseFloat(topP),
            idioma
        );

        // Guardar respuesta del modelo
        await supabase
            .from("mensajes")
            .insert([{ conversacion_id: conversationId, rol: "model", texto: respuestaIA }]);

        // Devolver al frontend
        res.status(200).json({
            respuesta: respuestaIA,
            isNewConversation,
            conversationId
        });

    } catch (error) {
        console.error("[GenerateText] ❌ Error general:", error.message);
        res.status(500).json({ error: "Error generando respuesta: " + error.message });
    }
});




app.use((err, req, res, next) => {
    console.error("‼️ Global Error:", err.message);
    if (NODE_ENV !== 'production' && err.stack) console.error(err.stack);
    let statusCode = typeof err.status === 'number' ? err.status : 500;
    let mensajeUsuario = "Error interno del servidor.";
    const errorLang = req?.body?.idioma === 'en' ? 'en' : 'es';
    if (err instanceof multer.MulterError) {
        statusCode = 400;
        if (err.code === 'LIMIT_FILE_SIZE') {
            statusCode = 413;
            mensajeUsuario = errorLang === 'en' ? `File too large (Max: ${TAMANO_MAX_ARCHIVO_MB} MB).` : `Archivo muy grande (Máx: ${TAMANO_MAX_ARCHIVO_MB} MB).`;
        } else {
            mensajeUsuario = errorLang === 'en' ? `File upload error: ${err.message}.` : `Error subida archivo: ${err.message}.`;
        }
    } else if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        statusCode = 400;
        mensajeUsuario = errorLang === 'en' ? "Malformed request (Invalid JSON)." : "Petición mal formada (JSON inválido).";
    } else if (err.message === "Servicio IA o BD no disponible.") {
        statusCode = 503;
        mensajeUsuario = errorLang === 'en' ? "Service temporarily unavailable." : "Servicio no disponible temporalmente.";
    } else if (err.message === 'Solo se permiten archivos PDF.') {
        statusCode = 400;
        mensajeUsuario = err.message;
    } else if (statusCode < 500 && err.message) {
        mensajeUsuario = err.message;
    }
    if (res.headersSent) {
        console.error("‼️ Error caught AFTER headers were sent!");
    } else {
        res.status(statusCode).json({ error: mensajeUsuario });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
});