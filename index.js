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
  PORT: PUERTO_ENV = 3001,
  API_KEY: CLAVE_API_GOOGLE,
  JWT_SECRET: SECRETO_JWT_ENV,
  NODE_ENV: ENTORNO_NODE = "development",
  SUPABASE_URL: URL_SUPABASE_ENV,
  SUPABASE_KEY: CLAVE_SUPABASE_ENV,
  CLIPDROP_API_KEY: CLAVE_API_CLIPDROP_ENV,
} = process.env;

const esDesarrollo = ENTORNO_NODE !== "production";

// --- Constantes y Configuraciones ---
const OPCIONES_COOKIE = { httpOnly: true, secure: !esDesarrollo, sameSite: esDesarrollo ? "lax" : "none", maxAge: 3600 * 1000, path: "/" };
const TAMANO_MAX_ARCHIVO_MB = 20;
const MAX_LONGITUD_CONTEXTO = 30000;
const MODELOS_PERMITIDOS = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash", "gemini-2.5-pro-exp-03-25"];
const MODELO_POR_DEFECTO = "gemini-1.5-flash";
const TEMP_POR_DEFECTO = 0.7;
const TOPP_POR_DEFECTO = 0.9;
const IDIOMA_POR_DEFECTO = "es";
const OPCIONES_JWT = { expiresIn: "1h" };

const BUCKET_PDF_SUPABASE = "user-pdfs";
const BUCKET_IMAGENES_SUPABASE = "generated-images";

// --- Verificaciones de Startup ---
console.log("[Startup] SECRETO_JWT_ENV cargado:", SECRETO_JWT_ENV ? `${SECRETO_JWT_ENV.substring(0, 3)}... (long: ${SECRETO_JWT_ENV.length})` : "NO CARGADO!");
if (!SECRETO_JWT_ENV || SECRETO_JWT_ENV.length < 32) console.warn("⚠️ SECRETO_JWT_ENV no definido o inseguro!");
if (!CLAVE_API_GOOGLE) console.warn("⚠️ CLAVE_API_GOOGLE (Google GenAI) no configurada.");
if (!URL_SUPABASE_ENV) console.warn("⚠️ URL_SUPABASE_ENV no configurada.");
if (!CLAVE_SUPABASE_ENV) console.warn("⚠️ CLAVE_SUPABASE_ENV no configurada.");
if (!CLAVE_API_CLIPDROP_ENV) console.warn("⚠️ CLAVE_API_CLIPDROP_ENV (para imágenes) no configurada.");

const app = express(); 

// --- Inicialización de Clientes ---
let clienteIA;
try {
  if (CLAVE_API_GOOGLE) { clienteIA = new GoogleGenerativeAI(CLAVE_API_GOOGLE); console.log("✅ GoogleGenerativeAI creado."); }
  else { clienteIA = null; console.warn("⚠️ GoogleGenerativeAI NO inicializado (sin CLAVE_API_GOOGLE)."); }
} catch (errorExcepcion) { console.error("🚨 Error GoogleGenerativeAI:", errorExcepcion.message); clienteIA = null; }

let supabase;
try {
  console.log("[Env Vars Check Before Supabase Init] URL_SUPABASE_ENV:", URL_SUPABASE_ENV ? `Cargada (longitud: ${URL_SUPABASE_ENV.length})` : "NO CARGADA O VACÍA");
  console.log("[Env Vars Check Before Supabase Init] CLAVE_SUPABASE_ENV:", CLAVE_SUPABASE_ENV ? `Cargada (primeros 3 chars: ${CLAVE_SUPABASE_ENV.substring(0,3)}..., longitud: ${CLAVE_SUPABASE_ENV.length})` : "NO CARGADA O VACÍA");

  if (URL_SUPABASE_ENV && CLAVE_SUPABASE_ENV) {
    supabase = createClient(URL_SUPABASE_ENV, CLAVE_SUPABASE_ENV);
    console.log("✅ Supabase client creado.");
  } else {
    supabase = null;
    console.warn("⚠️ Supabase NO inicializado (sin URL/KEY). Esto causará errores en operaciones de DB y Storage.");
  }
} catch (errorExcepcion) {
  console.error("🚨 Error Supabase client al inicializar:", errorExcepcion.message);
  supabase = null;
}

// --- Middlewares ---
app.use(cors({ origin: (origen, callback) => callback(null, origen || true), credentials: true }));
app.use(cookieParser());
app.use(express.json());

// --- Autenticación ---
const autenticarToken = (solicitud, respuesta, siguiente) => {
    const token = solicitud.cookies.token;
    if (!token) return respuesta.status(401).json({ error: "Token no proporcionado" });
    if (!SECRETO_JWT_ENV) { console.error("[Auth] SECRETO_JWT_ENV falta!"); return respuesta.status(500).json({ error: "Error auth server." }); }
    jwt.verify(token, SECRETO_JWT_ENV, (errorVerificacion, datosUsuario) => {
        if (errorVerificacion) {
            if (errorVerificacion.name === "TokenExpiredError") respuesta.clearCookie("token", OPCIONES_COOKIE);
            return respuesta.status(errorVerificacion.name === "TokenExpiredError" ? 401 : 403).json({ error: errorVerificacion.name === "TokenExpiredError" ? "Token expirado" : "Token inválido" });
        }
        solicitud.usuario = datosUsuario;
        siguiente();
    });
};

// --- Multer ---
const almacenamientoEnMemoria = multer.memoryStorage();
const filtroArchivosMulter = (solicitud, archivo, callback) => {
    const esPdf = archivo.mimetype === "application/pdf";
    if (!esPdf){
      callback(new multer.MulterError('LIMIT_UNEXPECTED_FILE', 'Solo se permiten archivos PDF.'), false);
    } else {
        callback(null, true);
    }
};
const subirArchivosParaGenerarTexto = multer({ storage: almacenamientoEnMemoria, limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 }, fileFilter: filtroArchivosMulter }).array("archivosPdf");
const subirArchivosPdf = multer({ storage: almacenamientoEnMemoria, limits: { fileSize: TAMANO_MAX_ARCHIVO_MB * 1024 * 1024 }, fileFilter: filtroArchivosMulter }).array("archivosPdf");

// --- Funciones Auxiliares ---
async function generarContextoPDF(idUsuario, rutasSupabaseArchivos) {
  if (!rutasSupabaseArchivos || rutasSupabaseArchivos.length === 0) return "";
  if (!supabase) { console.warn("[Context PDF] Supabase no disponible."); return "[Error: Base de datos no disponible]";}
  try {
    const { data: archivosDesdeDB, error: errorDB } = await supabase
      .from("archivos_usuario").select("nombre_archivo_unico, nombre_archivo_original")
      .eq("usuario_id", idUsuario).in("nombre_archivo_unico", rutasSupabaseArchivos);
    if (errorDB) { console.error("[Context PDF] Supabase error (meta):", errorDB.message); return "[Error al recuperar metadatos PDF]"; }
    if (!archivosDesdeDB || archivosDesdeDB.length === 0) { return ""; }
    const mapaArchivos = new Map(archivosDesdeDB.map((archivoInfo) => [archivoInfo.nombre_archivo_unico, archivoInfo.nombre_archivo_original]));
    let textoCompleto = "";
    for (const rutaSupabase of rutasSupabaseArchivos) {
      const nombreOriginal = mapaArchivos.get(rutaSupabase);
      if (!nombreOriginal) continue;
      const { data: datosArchivo, error: errorDescarga } = await supabase.storage.from(BUCKET_PDF_SUPABASE).download(rutaSupabase);
      if (errorDescarga) { console.warn(`[Context PDF] Supabase download error ${rutaSupabase}:`, errorDescarga.message); continue; }
      try {
        const buffer = Buffer.from(await datosArchivo.arrayBuffer());
        const datosParseados = await pdfParse(buffer);
        textoCompleto += `\n\n[${nombreOriginal}]\n${(datosParseados.text || "").trim()}`;
      } catch (errorParseo) { console.warn(`[Context PDF] Parse error ${rutaSupabase}:`, errorParseo.message); }
    }
    return textoCompleto.trim();
  } catch (errorExcepcion) { console.error("[Context PDF] Exception:", errorExcepcion); return "[Error al generar contexto PDF]"; }
}

async function generarRespuestaIA( entradaUsuario, historialDesdeDB, textoPDF, modeloRequerido, temperatura, topP, idiomaSolicitado) {
  if (!clienteIA) throw new Error("Servicio IA (Google) no disponible.");
  const nombreModelo = MODELOS_PERMITIDOS.includes(modeloRequerido) ? modeloRequerido : MODELO_POR_DEFECTO;
  if (modeloRequerido && nombreModelo !== modeloRequerido) console.warn(`[Gen IA] Modelo no válido ('${modeloRequerido}'), usando: ${MODELO_POR_DEFECTO}`);
  const configuracionGeneracion = { temperature: !isNaN(temperatura) ? Math.max(0, Math.min(1, temperatura)) : TEMP_POR_DEFECTO, topP: !isNaN(topP) ? Math.max(0, Math.min(1, topP)) : TOPP_POR_DEFECTO, };
  const idioma = ["es", "en"].includes(idiomaSolicitado) ? idiomaSolicitado : IDIOMA_POR_DEFECTO;
  const textosIdioma = idioma === "en" ? { baseSistema: "You are a helpful conversational assistant. Answer clearly and concisely in Markdown format.", pdfSistema: `You are an assistant that answers *based solely* on the provided text. If the answer isn't in the text, state that clearly. Use Markdown format.\n\nReference Text (Context):\n"""\n{CONTEXT}\n"""\n\n`, etiqueta: "Question", errorTexto: "I'm sorry, there was a problem contacting the AI" } : { baseSistema: "Eres un asistente conversacional útil. Responde de forma clara y concisa en formato Markdown.", pdfSistema: `Eres un asistente que responde *basándose únicamente* en el texto proporcionado. Si la respuesta no está en el texto, indícalo claramente. Usa formato Markdown.\n\nTexto de Referencia (Contexto):\n"""\n{CONTEXT}\n"""\n\n`, etiqueta: "Pregunta", errorTexto: "Lo siento, hubo un problema al contactar la IA" };
  let instruccionSistema = textoPDF ? textosIdioma.pdfSistema.replace("{CONTEXT}", (textoPDF.length > MAX_LONGITUD_CONTEXTO ? textoPDF.substring(0, MAX_LONGITUD_CONTEXTO) + "... (context truncated)" : textoPDF)) : textosIdioma.baseSistema;
  if (textoPDF && textoPDF.length > MAX_LONGITUD_CONTEXTO) console.warn(`[Gen IA] ✂️ Contexto PDF truncado.`);
  const entradaCompletaUsuario = `${instruccionSistema}${textosIdioma.etiqueta}: ${entradaUsuario}`;
  const contenidoParaGemini = [ ...(historialDesdeDB || []).filter((mensajeHistorial) => mensajeHistorial.texto?.trim()).map((mensajeHistorial) => ({ role: mensajeHistorial.rol === "user" ? "user" : "model", parts: [{ text: mensajeHistorial.texto }], })), { role: "user", parts: [{ text: entradaCompletaUsuario }] }, ];
  console.log( `[Gen IA] ➡️ Enviando ${contenidoParaGemini.length} partes a Gemini (${nombreModelo}).` );
  try {
    const modeloGemini = clienteIA.getGenerativeModel({ model: nombreModelo });
    const resultadoIA = await modeloGemini.generateContent({ contents: contenidoParaGemini, generationConfig: configuracionGeneracion, });
    const respuestaApiGemini = resultadoIA?.response;
    const textoRespuestaIA = respuestaApiGemini?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (textoRespuestaIA) { console.log("[Gen IA] ✅ Respuesta recibida."); return textoRespuestaIA.trim(); }
    const razonBloqueo = respuestaApiGemini?.promptFeedback?.blockReason; const razonFinalizacion = respuestaApiGemini?.candidates?.[0]?.finishReason;
    const detalleErrorIA = razonBloqueo ? `Bloqueo: ${razonBloqueo}` : razonFinalizacion ? `Finalización: ${razonFinalizacion}` : "Respuesta inválida";
    console.warn(`[Gen IA] ⚠️ Respuesta vacía/bloqueada. ${detalleErrorIA}`); throw new Error(`${textosIdioma.errorTexto}. (${detalleErrorIA})`);
  } catch (errorProceso) { console.error(`[Gen IA] ❌ Error API (${nombreModelo}):`, errorProceso.message); throw new Error(`${textosIdioma.errorTexto}. (Detalle: ${errorProceso.message || "Desconocido"})`); }
}

async function generarImagenClipdrop(textoEntrada) {
    if (!CLAVE_API_CLIPDROP_ENV) throw new Error("Servicio de imágenes (Clipdrop) no disponible (sin API key).");
    if (!textoEntrada?.trim()) throw new Error("Prompt inválido para Clipdrop.");
    if (!supabase) throw new Error("Supabase no disponible para guardar imagen.");
    const URL_API_CLIPDROP = "https://clipdrop-api.co/text-to-image/v1";
    console.log(`[Img Gen Clipdrop Axios] Solicitando para: "${textoEntrada}"`);
    const formulario = new FormData();
    formulario.append('prompt', textoEntrada.trim());
    try {
        const respuestaApi = await axios.post(URL_API_CLIPDROP, formulario, { headers: { 'x-api-key': CLAVE_API_CLIPDROP_ENV, ...formulario.getHeaders() }, responseType: 'arraybuffer' });
        const bufferImagen = Buffer.from(respuestaApi.data);
        const tipoMime = respuestaApi.headers['content-type'] || 'image/png';
        const extension = tipoMime.includes('png') ? 'png' : (tipoMime.includes('jpeg') ? 'jpeg' : 'out');
        const nombreArchivoImagenOriginal = `${Date.now()}-clipdrop-${textoEntrada.substring(0,15).replace(/[^a-z0-9]/gi, '_')}.${extension}`;
        const rutaImagenSupabase = nombreArchivoImagenOriginal;

        console.log(`[Supabase Storage Img Upload Debug] Intentando subir '${nombreArchivoImagenOriginal}' como '${rutaImagenSupabase}' al bucket '${BUCKET_IMAGENES_SUPABASE}'`);
        const { error: errorSubida } = await supabase.storage
            .from(BUCKET_IMAGENES_SUPABASE).upload(rutaImagenSupabase, bufferImagen, { contentType: tipoMime, upsert: true });
        if (errorSubida) {
            console.error(`[Supabase Storage Img Upload Fail] Error detallado al subir '${rutaImagenSupabase}':`, JSON.stringify(errorSubida, null, 2));
            throw new Error(`Error al guardar la imagen generada en el almacenamiento: ${errorSubida.message}`);
        }
        console.log(`[Supabase Storage Img Upload Success] Subida '${rutaImagenSupabase}' exitosamente.`);

        const { data: datosUrlPublica } = supabase.storage.from(BUCKET_IMAGENES_SUPABASE).getPublicUrl(rutaImagenSupabase);
        if (!datosUrlPublica || !datosUrlPublica.publicUrl) {
            console.error(`[Supabase Storage] Error obteniendo URL pública para ${rutaImagenSupabase}. Datos devueltos:`, datosUrlPublica);
            await supabase.storage.from(BUCKET_IMAGENES_SUPABASE).remove([rutaImagenSupabase]).catch(errorEliminacion => console.error(`Error al intentar borrar imagen ${rutaImagenSupabase} tras fallo de getPublicUrl:`, errorEliminacion));
            throw new Error("Error al obtener la URL de la imagen generada (datosUrlPublica es nulo o no tiene publicUrl).");
        }

        console.log(`[Img Gen Clipdrop Axios] Guardada en Supabase. URL Pública: ${datosUrlPublica.publicUrl}`);
        return { nombreArchivo: nombreArchivoImagenOriginal, url: datosUrlPublica.publicUrl };
    } catch (errorProceso) {
        let estadoHttp = 500; let mensajeErrorUsuario = "Error desconocido generando imagen.";
        if (errorProceso.message.includes("almacenamiento") || errorProceso.message.includes("URL de la imagen")) { mensajeErrorUsuario = errorProceso.message; }
        else if (errorProceso.response) { estadoHttp = errorProceso.response.status; const datosRespuesta = errorProceso.response.data; let errorClipdrop = "Error de Clipdrop."; if (datosRespuesta) { if (Buffer.isBuffer(datosRespuesta)) { try { const objetoError = JSON.parse(datosRespuesta.toString('utf-8')); errorClipdrop = objetoError.error || datosRespuesta.toString('utf-8'); } catch (errorParseoJson) { errorClipdrop = datosRespuesta.toString('utf-8'); } } else if (typeof datosRespuesta === 'object' && datosRespuesta.error) { errorClipdrop = datosRespuesta.error; } else if (typeof datosRespuesta === 'string') { errorClipdrop = datosRespuesta; } } console.error(`[Img Gen Clipdrop Axios] Error API Clipdrop (${estadoHttp}):`, errorClipdrop); if (estadoHttp === 400) mensajeErrorUsuario = "Prompt inválido para Clipdrop."; else if (estadoHttp === 401 || estadoHttp === 403) mensajeErrorUsuario = "API Key de Clipdrop inválida."; else if (estadoHttp === 402) mensajeErrorUsuario = "Límite Clipdrop alcanzado."; else if (estadoHttp === 429) mensajeErrorUsuario = "Límite de tasa Clipdrop. Intente más tarde."; else mensajeErrorUsuario = `Error servicio imágenes: ${errorClipdrop.substring(0,150)}`; }
        else if (errorProceso.request) { console.error("[Img Gen Clipdrop Axios] Sin respuesta de Clipdrop:", errorProceso.message); mensajeErrorUsuario = "No se pudo contactar el servicio de imágenes."; }
        else { console.error("[Img Gen Clipdrop Axios] Error interno:", errorProceso.message); mensajeErrorUsuario = errorProceso.message || "Error interno en solicitud de imagen."; }
        const errorParaLanzar = new Error(mensajeErrorUsuario); errorParaLanzar.status = estadoHttp; throw errorParaLanzar;
    }
}
// --- Rutas API (Usuarios, Login, Logout, Auth) ---
app.post("/api/register", async (solicitud, respuesta, siguiente) => {
  if (!supabase) return respuesta.status(503).json({error: "BD no disponible"});
  const { nombreUsuario, contrasena } = solicitud.body;
  if (!nombreUsuario || !contrasena) return respuesta.status(400).json({ error: "Usuario/contraseña requeridos." });
  try {
    const contrasenaHasheada = await bcrypt.hash(contrasena, 10);
    const { data: datosRegistro, error: errorRegistro } = await supabase.from("usuarios").insert([{ nombre_usuario: nombreUsuario, contrasena_hash: contrasenaHasheada }]).select("id").single();
    if (errorRegistro) {
      if (errorRegistro.code === "23505") return respuesta.status(409).json({ error: "Nombre de usuario ya existe." });
      throw errorRegistro;
    }
    respuesta.status(201).json({ mensaje: "Registro exitoso.", idUsuario: datosRegistro.id });
  } catch (errorExcepcion) { siguiente(errorExcepcion); }
});

app.post("/api/login", async (solicitud, respuesta, siguiente) => {
  if (!supabase) return respuesta.status(503).json({error: "BD no disponible"});
  const { nombreUsuario, contrasena } = solicitud.body;
  if (!nombreUsuario || !contrasena) return respuesta.status(400).json({ error: "Usuario/contraseña requeridos." });
  try {
    const { data: datosUsuarioDB, error: errorLogin } = await supabase.from("usuarios").select("id, nombre_usuario, contrasena_hash").eq("nombre_usuario", nombreUsuario).limit(1).single();
    if (errorLogin || !datosUsuarioDB) return respuesta.status(401).json({ error: "Credenciales inválidas." });
    const contrasenaCorrecta = await bcrypt.compare(contrasena, datosUsuarioDB.contrasena_hash);
    if (!contrasenaCorrecta) return respuesta.status(401).json({ error: "Credenciales inválidas." });
    const cargaUtilToken = { id: datosUsuarioDB.id, username: datosUsuarioDB.nombre_usuario };
    if(!SECRETO_JWT_ENV) { console.error("SECRETO_JWT_ENV no está configurado!"); throw new Error("Error de configuración de autenticación."); }
    const token = jwt.sign(cargaUtilToken, SECRETO_JWT_ENV, OPCIONES_JWT);
    respuesta.cookie("token", token, OPCIONES_COOKIE);
    respuesta.json({ mensaje: "Login exitoso.", usuario: cargaUtilToken });
  } catch (errorExcepcion) { siguiente(errorExcepcion); }
});

app.post("/api/logout", (solicitud, respuesta) => {
    respuesta.clearCookie("token", OPCIONES_COOKIE);
    respuesta.status(200).json({ mensaje: "Logout exitoso." });
});

app.get("/api/verify-auth", autenticarToken, (solicitud, respuesta) => {
    respuesta.json({ usuario: solicitud.usuario });
});

// --- Rutas API (Archivos PDF) ---
app.post("/api/files", autenticarToken, subirArchivosPdf, async (solicitud, respuesta, siguiente) => {
    if (!supabase) return respuesta.status(503).json({error: "BD no disponible"});
    try {
      const idUsuario = solicitud.usuario.id;
      const archivosRecibidos = solicitud.files;
      if (!archivosRecibidos || archivosRecibidos.length === 0) return respuesta.status(400).json({ error: "No se subieron archivos PDF."});
      const resultadosSubidaDB = [];
      const erroresAlmacenamiento = [];
      for (const archivoSubido of archivosRecibidos) {
          console.log("[Storage Upload Debug /api/files] idUsuario:", idUsuario);
          const nombreArchivoSupabase = `${idUsuario}/${Date.now()}-${archivoSubido.originalname.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9.\-_]/gi, '_')}`;
          console.log(`[Storage Upload Debug /api/files] Intentando subir '${archivoSubido.originalname}' como '${nombreArchivoSupabase}' al bucket '${BUCKET_PDF_SUPABASE}'`);
          if (!archivoSubido.buffer) {
              console.error(`[Storage Upload Debug /api/files] Error: archivoSubido.buffer no existe para el archivo ${archivoSubido.originalname}.`);
              erroresAlmacenamiento.push({ originalName: archivoSubido.originalname, generatedName: nombreArchivoSupabase, errorDetails: { message: "archivoSubido.buffer is missing" } });
              continue;
          }
          const { error: errorSubidaArchivo } = await supabase.storage.from(BUCKET_PDF_SUPABASE).upload(nombreArchivoSupabase, archivoSubido.buffer, { contentType: archivoSubido.mimetype, upsert: false });
          if (errorSubidaArchivo) {
              console.error(`[Storage Upload Fail /api/files] Error detallado al subir '${nombreArchivoSupabase}' (Original: ${archivoSubido.originalname}):`, JSON.stringify(errorSubidaArchivo, null, 2));
              erroresAlmacenamiento.push({ originalName: archivoSubido.originalname, generatedName: nombreArchivoSupabase, errorDetails: errorSubidaArchivo });
          } else {
              console.log(`[Storage Upload Success /api/files] Subido '${nombreArchivoSupabase}' exitosamente.`);
              resultadosSubidaDB.push({ usuario_id: idUsuario, nombre_archivo_unico: nombreArchivoSupabase, nombre_archivo_original: archivoSubido.originalname });
          }
      }
      if (resultadosSubidaDB.length > 0) {
          const { error: errorInsercionDB } = await supabase.from("archivos_usuario").insert(resultadosSubidaDB);
          if (errorInsercionDB) {
            console.error("[DB Insert PDF Meta /api/files] Error:", errorInsercionDB);
            for (const archivoSubidoConExito of resultadosSubidaDB) {
                const { error: errorEliminacionStorage } = await supabase.storage.from(BUCKET_PDF_SUPABASE).remove([archivoSubidoConExito.nombre_archivo_unico]);
                if (errorEliminacionStorage) console.error("Error limpiando PDF de Storage tras fallo DB (/api/files):", errorEliminacionStorage.message);
            }
            return siguiente(new Error(`Error guardando metadatos en DB: ${errorInsercionDB.message}`));
          }
      }
      if (erroresAlmacenamiento.length > 0) {
          return respuesta.status(resultadosSubidaDB.length > 0 ? 207 : 400).json({
              mensaje: resultadosSubidaDB.length > 0 ? "Algunos PDF subidos, otros fallaron." : "No se pudo subir ningún PDF.",
              subidos: resultadosSubidaDB.map(resultado => resultado.nombre_archivo_original),
              errores: erroresAlmacenamiento.map(errorDetalle => ({ originalName: errorDetalle.originalName, error: errorDetalle.errorDetails?.message || "Error desconocido en la subida" }))
          });
      }
      respuesta.status(200).json({ mensaje: "PDFs subidos y registrados." });
    } catch (errorExcepcion) { siguiente(errorExcepcion); }
});
app.get("/api/files", autenticarToken, async (solicitud, respuesta, siguiente) => {
    if (!supabase) return respuesta.status(503).json({error: "BD no disponible"});
    try {
      const { data: listaArchivos, error: errorConsulta } = await supabase.from("archivos_usuario").select("nombre_archivo_unico, nombre_archivo_original").eq("usuario_id", solicitud.usuario.id).order("fecha_subida", { ascending: false });
      if (errorConsulta) throw errorConsulta;
      respuesta.json( (listaArchivos || []).map((archivoInfo) => ({ nombre: archivoInfo.nombre_archivo_unico, nombreOriginal: archivoInfo.nombre_archivo_original, })) );
    } catch (errorExcepcion) { siguiente(errorExcepcion); }
});

app.delete( "/api/files/:rutaSupabaseArchivo(.*)", autenticarToken, async (solicitud, respuesta, siguiente) => {
    if (!supabase) return respuesta.status(503).json({error: "BD no disponible"});
    const idUsuario = solicitud.usuario.id; const rutaArchivoSupabaseParam = solicitud.params.rutaSupabaseArchivo;
    if(!rutaArchivoSupabaseParam) return respuesta.status(400).json({error: "Ruta de archivo Supabase no especificada."});
    try {
      const { data: metadatosArchivo, error: errorMetadatos } = await supabase.from("archivos_usuario").select("id").eq("usuario_id", idUsuario).eq("nombre_archivo_unico", rutaArchivoSupabaseParam).single();
      if (errorMetadatos || !metadatosArchivo) { if (errorMetadatos && errorMetadatos.code !== 'PGRST116') { console.error("[Delete File Meta Error]", errorMetadatos); throw errorMetadatos; } return respuesta.status(404).json({ error: "Archivo no encontrado o no pertenece al usuario." });}
      const { error: errorEliminacionAlmacenamiento } = await supabase.storage.from(BUCKET_PDF_SUPABASE).remove([rutaArchivoSupabaseParam]);
      if (errorEliminacionAlmacenamiento) { console.warn("[Supabase Storage Delete Warning/Error]", errorEliminacionAlmacenamiento.message); }
      const { error: errorEliminacionDB } = await supabase.from("archivos_usuario").delete().eq("id", metadatosArchivo.id);
      if (errorEliminacionDB) { console.error("[DB Delete PDF Meta Error]", errorEliminacionDB.message); throw new Error(`Error eliminando metadato PDF de DB: ${errorEliminacionDB.message}.`); }
      respuesta.json({ mensaje: "Archivo PDF eliminado." });
    } catch (errorProceso) { siguiente(errorProceso); }
});

// --- Rutas de Conversaciones y Mensajes ---
app.get("/api/conversations", autenticarToken, async (solicitud, respuesta, siguiente) => {
    if (!supabase) return respuesta.status(503).json({error: "BD no disponible"});
    try {
      const { data: listaConversaciones, error: errorConsulta } = await supabase.from("conversaciones").select("id, titulo").eq("usuario_id", solicitud.usuario.id).order("fecha_actualizacion", { ascending: false });
      if (errorConsulta) throw errorConsulta;
      respuesta.json(listaConversaciones || []);
    } catch (errorExcepcion) { siguiente(errorExcepcion); }
  }
);

app.get( "/api/conversations/:id/messages", autenticarToken, async (solicitud, respuesta, siguiente) => {
    if (!supabase) return respuesta.status(503).json({error: "BD no disponible"});
    const idConversacionParam = solicitud.params.id;
    const idConversacionEntero = parseInt(idConversacionParam);
    if (isNaN(idConversacionEntero)) return respuesta.status(400).json({error:"ID de conversación inválido."});
    try {
      const { data: propietarioConversacion, error: errorPropietario } = await supabase.from("conversaciones").select("id").eq("id", idConversacionEntero).eq("usuario_id", solicitud.usuario.id).maybeSingle();
      if(errorPropietario) throw errorPropietario;
      if (!propietarioConversacion) return respuesta.status(404).json({ error: "Conversación no encontrada o no autorizada." });
      const { data: listaMensajes, error: errorConsulta } = await supabase.from("mensajes").select("id, rol, texto, fecha_envio, es_error, tipo_mensaje").eq("conversacion_id", idConversacionEntero).order("fecha_envio", { ascending: true });
      if (errorConsulta) throw errorConsulta;
      respuesta.json(listaMensajes || []);
    } catch (errorExcepcion) { siguiente(errorExcepcion); }
  }
);

app.delete( "/api/conversations/:idConv", autenticarToken, async (solicitud, respuesta, siguiente) => {
    if (!supabase) return respuesta.status(503).json({error: "BD no disponible"});
    const idConversacionParam = solicitud.params.idConv;
    if (!idConversacionParam) return respuesta.status(400).json({error:"ID de conversación requerido."})
    const idUsuario = solicitud.usuario.id;
    try {
      const { error: errorEliminacion } = await supabase.from("conversaciones").delete().eq("id", idConversacionParam).eq("usuario_id", idUsuario);
      if (errorEliminacion) throw errorEliminacion;
      respuesta.json({ mensaje: "Conversación eliminada." });
    } catch (errorProceso) { siguiente(errorProceso); }
  }
);

app.put( "/api/conversations/:id/title", autenticarToken, async (solicitud, respuesta, siguiente) => {
    if (!supabase) return respuesta.status(503).json({error: "BD no disponible"});
    const idConversacionParam = solicitud.params.id;
    if (!idConversacionParam) return respuesta.status(400).json({error:"ID de conversación requerido."})
    const { nuevoTitulo: nuevoTituloReq } = solicitud.body;
    if (!nuevoTituloReq || typeof nuevoTituloReq !== "string" || !nuevoTituloReq.trim()) return respuesta.status(400).json({ error: "Título no válido." });
    const tituloLimpio = nuevoTituloReq.trim().substring(0,100);
    try {
      const { error: errorActualizacion } = await supabase.from("conversaciones").update({ titulo: tituloLimpio, fecha_actualizacion: new Date().toISOString() }).eq("id", idConversacionParam).eq("usuario_id", solicitud.usuario.id);
      if (errorActualizacion) throw errorActualizacion;
      respuesta.status(200).json({ mensaje: "Título actualizado." });
    } catch (errorProceso) { siguiente(errorProceso); }
  }
);

// --- RUTAS PRINCIPALES DE IA ---
app.post("/api/generateText", autenticarToken, subirArchivosParaGenerarTexto, async (solicitud, respuesta, siguiente) => {
    if (!supabase) { console.error("Error: Cliente Supabase no inicializado en /api/generateText"); return respuesta.status(503).json({ error: "Servicio de base de datos no disponible." }); }
    if (!clienteIA) { console.error("Error: Cliente GoogleGenerativeAI no inicializado en /api/generateText"); return respuesta.status(503).json({ error: "Servicio de IA no disponible." }); }

    const idUsuario = solicitud.usuario.id;
    console.log("[Storage Upload Debug /api/generateText] Iniciando. idUsuario:", idUsuario);

    const { prompt: entradaUsuarioReq, conversationId: idConversacionEntrada, modeloSeleccionado: modeloSeleccionadoReq, temperatura: temperaturaReq, topP: topPReq, idioma: idiomaReq, archivosSeleccionados: archivosSeleccionadosReq } = solicitud.body;
    const archivosPdfNuevosSubidos = solicitud.files || [];
    let archivosSeleccionadosParseados = [];
    if (archivosSeleccionadosReq) {
        try { archivosSeleccionadosParseados = typeof archivosSeleccionadosReq === 'string' ? JSON.parse(archivosSeleccionadosReq) : archivosSeleccionadosReq; if (!Array.isArray(archivosSeleccionadosParseados)) archivosSeleccionadosParseados = []; }
        catch(errorParseoJson) { if (typeof archivosSeleccionadosReq === 'string') return respuesta.status(400).json({ error: "Formato archivosSeleccionadosReq inválido." }); archivosSeleccionadosParseados = []; }
    }
    let idConversacion = idConversacionEntrada ? parseInt(idConversacionEntrada) : null;
    let esNuevaConversacion = false;
    const rutasSupabaseNuevosArchivos = [];
    const erroresAlmacenamientoNuevos = []; const registrosParaDB = [];
    try {
        if (!idConversacion) {
            const { data: datosNuevaConversacion, error: errorCreacionConversacion } = await supabase.from("conversaciones").insert([{ usuario_id: idUsuario, titulo: (entradaUsuarioReq?.trim().substring(0,50) || "Conversación") }]).select("id").single();
            if (errorCreacionConversacion) throw new Error(`Error creando conv: ${errorCreacionConversacion.message}`);
            idConversacion = datosNuevaConversacion.id; esNuevaConversacion = true;
        } else {
            const { data: datosConversacionExistente, error: errorConsultaConversacion } = await supabase.from("conversaciones").select("id").eq("id",idConversacion).eq("usuario_id",idUsuario).maybeSingle();
            if(errorConsultaConversacion) throw errorConsultaConversacion; if(!datosConversacionExistente) return respuesta.status(404).json({error:"Conversación no encontrada."});
        }
        if (entradaUsuarioReq?.trim()) {
            const { error: errorMensajeUsuario } = await supabase.from("mensajes").insert([{ conversacion_id: idConversacion, rol: "user", texto: entradaUsuarioReq, tipo_mensaje: "text" }]);
            if (errorMensajeUsuario) console.error("Error guardando msg usr:", errorMensajeUsuario.message);
        }
        if (archivosPdfNuevosSubidos.length > 0) {
            for (const archivoNuevo of archivosPdfNuevosSubidos) {
                console.log("[Storage Upload Debug /api/generateText] Dentro del bucle de archivos. Archivo actual:", archivoNuevo.originalname);
                const nombreArchivoSupabaseNuevo = `${idUsuario}/${Date.now()}-${archivoNuevo.originalname.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9.\-_]/gi, '_')}`;
                console.log(`[Storage Upload Debug /api/generateText] Intentando subir '${archivoNuevo.originalname}' como '${nombreArchivoSupabaseNuevo}' al bucket '${BUCKET_PDF_SUPABASE}'`);
                if (!archivoNuevo.buffer) { console.error(`[Storage Upload Debug /api/generateText] Error: archivoNuevo.buffer no existe para ${archivoNuevo.originalname}.`); erroresAlmacenamientoNuevos.push({ originalName: archivoNuevo.originalname, generatedName: nombreArchivoSupabaseNuevo, errorDetails: { message: "archivoNuevo.buffer is missing" }}); continue; }
                const {error: errorSubidaArchivoNuevo} = await supabase.storage.from(BUCKET_PDF_SUPABASE).upload(nombreArchivoSupabaseNuevo, archivoNuevo.buffer, {contentType:archivoNuevo.mimetype});
                if(errorSubidaArchivoNuevo){ console.error(`[Storage Upload Fail /api/generateText] Error detallado al subir '${nombreArchivoSupabaseNuevo}' (Original: ${archivoNuevo.originalname}):`, JSON.stringify(errorSubidaArchivoNuevo, null, 2)); erroresAlmacenamientoNuevos.push({ originalName: archivoNuevo.originalname, generatedName: nombreArchivoSupabaseNuevo, errorDetails: errorSubidaArchivoNuevo });
                } else { console.log(`[Storage Upload Success /api/generateText] Subido '${nombreArchivoSupabaseNuevo}'.`); rutasSupabaseNuevosArchivos.push(nombreArchivoSupabaseNuevo); registrosParaDB.push({usuario_id:idUsuario, nombre_archivo_unico:nombreArchivoSupabaseNuevo, nombre_archivo_original:archivoNuevo.originalname});}
            }
            if(registrosParaDB.length > 0){
                const{error: errorInsercionMetaDB}=await supabase.from("archivos_usuario").insert(registrosParaDB);
                if(errorInsercionMetaDB){ console.error("[DB Insert PDF Meta /api/generateText] Error:", errorInsercionMetaDB); for(const rutaParaLimpiar of rutasSupabaseNuevosArchivos){ const { error: errorEliminacionLimpieza } = await supabase.storage.from(BUCKET_PDF_SUPABASE).remove([rutaParaLimpiar]); if (errorEliminacionLimpieza) console.error("Fallo limpieza Storage tras error DB (/api/generateText):", errorEliminacionLimpieza.message); } throw new Error("Fallo guardado meta PDF nuevos."); }
            }
            if(erroresAlmacenamientoNuevos.length > 0) { console.warn(`Fallaron en Storage durante generateText: ${erroresAlmacenamientoNuevos.map(errorDetalleSubida => errorDetalleSubida.originalName).join(', ')}`); }
        }
        const todasRutasSupabaseContexto = [...archivosSeleccionadosParseados, ...rutasSupabaseNuevosArchivos].filter(Boolean);
        const contextoPDFGenerado = await generarContextoPDF(idUsuario, todasRutasSupabaseContexto);
        if ((!entradaUsuarioReq?.trim()) && (!contextoPDFGenerado || contextoPDFGenerado.startsWith("[Error"))) return respuesta.status(400).json({error:"Prompt o PDF válidos requeridos."});
        const {data: historialConversacion, error: errorHistorial} = await supabase.from("mensajes").select("rol, texto").eq("conversacion_id",idConversacion).eq("es_error",false).order("fecha_envio",{ascending:true}); if(errorHistorial) throw new Error("Error cargando historial: "+errorHistorial.message);
        const entradaParaIA = entradaUsuarioReq || (idiomaReq ==='es' ? "Resume archivos.":"Summarize files.");
        const respuestaDeIA = await generarRespuestaIA(entradaParaIA, (historialConversacion||[]), contextoPDFGenerado, modeloSeleccionadoReq, parseFloat(temperaturaReq), parseFloat(topPReq), idiomaReq);
        const { error: errorMensajeModelo } = await supabase.from("mensajes").insert([{conversacion_id:idConversacion, rol:"model", texto:respuestaDeIA, tipo_mensaje:"text"}]);
        if (errorMensajeModelo) console.error("Error guardando msg model:", errorMensajeModelo.message);
        if (erroresAlmacenamientoNuevos.length > 0) { return respuesta.status(207).json({ respuesta: respuestaDeIA, esNuevaConversacion, idConversacion, erroresSubida: erroresAlmacenamientoNuevos.map(errorDetalleSubida => ({originalName: errorDetalleSubida.originalName, error: errorDetalleSubida.errorDetails?.message || "Error desconocido en la subida"})) }); }
        respuesta.status(200).json({ respuesta: respuestaDeIA, esNuevaConversacion, idConversacion });
    } catch (errorExcepcion) { siguiente(errorExcepcion); }
});

app.post("/api/generateImage", autenticarToken, async (solicitud, respuesta, siguiente) => {
    if (!supabase || !CLAVE_API_CLIPDROP_ENV) return respuesta.status(503).json({ error: "Servicio(s) no disponible(s)." });
    const { prompt: entradaUsuarioReq, conversationId: idConversacionEntrada } = solicitud.body;
    if (!entradaUsuarioReq?.trim()) return respuesta.status(400).json({ error: "Prompt inválido." });
    if (!idConversacionEntrada) return respuesta.status(400).json({ error: "ID de conversación requerido." });
    const idConversacion = parseInt(idConversacionEntrada); if (isNaN(idConversacion)) return respuesta.status(400).json({ error: "ID de conversación inválido." });
    try {
        const { data: datosPropietarioConversacion, error: errorConsultaPropietario } = await supabase.from("conversaciones").select("id").eq("id",idConversacion).eq("usuario_id",solicitud.usuario.id).maybeSingle(); if(errorConsultaPropietario) throw errorConsultaPropietario; if(!datosPropietarioConversacion) return respuesta.status(404).json({error:"Conversación no encontrada/autorizada."});
        const resultadoGeneracionImagen = await generarImagenClipdrop(entradaUsuarioReq.trim());
        const { data: datosMensajeImagen, error: errorMensajeImagenDB } = await supabase.from("mensajes").insert([{conversacion_id:idConversacion, rol:"model", texto:resultadoGeneracionImagen.url, tipo_mensaje:"image"}]).select("id").single();
        if(errorMensajeImagenDB) { console.error("[GenerateImage] Error DB:",errorMensajeImagenDB.message); return respuesta.status(207).json({mensaje:"Imagen generada pero error guardándola en conv.", nombreArchivo:resultadoGeneracionImagen.nombreArchivo, urlImagen:resultadoGeneracionImagen.url, errorDB:errorMensajeImagenDB.message});}
        respuesta.json({ mensaje: "Imagen generada y guardada.", nombreArchivo:resultadoGeneracionImagen.nombreArchivo, urlImagen:resultadoGeneracionImagen.url, idConversacion, idMensaje:datosMensajeImagen?.id });
    } catch (errorProceso) { siguiente(errorProceso); }
});

// --- Manejador de Errores Global ---
app.use((errorRecibido, solicitud, respuesta, siguiente) => {
  console.error("‼️ Global Error:", errorRecibido.message, ...(esDesarrollo && errorRecibido.stack ? [errorRecibido.stack] : []));
  if (respuesta.headersSent) return siguiente(errorRecibido);
  let codigoEstado = errorRecibido.status || (errorRecibido instanceof multer.MulterError ? 400 : 500);
  let mensajeUsuario = errorRecibido.message || "Error interno servidor.";
  const idiomaError = solicitud?.body?.idioma==='en'?"en":"es";

  if(errorRecibido instanceof multer.MulterError){
    if(errorRecibido.code==="LIMIT_FILE_SIZE"){ codigoEstado=413; mensajeUsuario=idiomaError==='en'?`File large (Max: ${TAMANO_MAX_ARCHIVO_MB}MB).`:`Archivo grande (Máx: ${TAMANO_MAX_ARCHIVO_MB}MB).`; }
    else if(errorRecibido.code==="LIMIT_UNEXPECTED_FILE"&&errorRecibido.message==='Solo se permiten archivos PDF.'){ codigoEstado=415; mensajeUsuario=errorRecibido.message; }
    else { codigoEstado=400; mensajeUsuario=idiomaError==='en'?`Upload error: ${errorRecibido.message}.`:`Error subida: ${errorRecibido.message}.`; }
  } else if(errorRecibido instanceof SyntaxError && "body" in errorRecibido){ codigoEstado=errorRecibido.status||400; mensajeUsuario=idiomaError==='en'?"Malformed JSON.":"JSON mal formado."; }
  else if (errorRecibido.message.includes("no disponible")||errorRecibido.message.includes("no configurado")) codigoEstado=503;
  else if (errorRecibido.message.includes("inválid")||errorRecibido.message.includes("requerido")) codigoEstado=400;
  else if (errorRecibido.message.includes("autenticación")||errorRecibido.message.includes("permisos")||errorRecibido.message.includes("API Key inválida")) codigoEstado=401;
  else if (errorRecibido.message.includes("Límite")||errorRecibido.message.includes("pago")||errorRecibido.message.includes("créditos")){ codigoEstado=402; mensajeUsuario="Límite de uso gratuito."; }
  else if(errorRecibido.message.includes("Demasiadas solicitudes")||errorRecibido.message.includes("sobrecargado")||errorRecibido.message.includes("Too Many Requests")){ codigoEstado=429; mensajeUsuario="Servicio externo ocupado."; }
  else if(codigoEstado===500&&(errorRecibido.message.toLowerCase().includes("fetch")||errorRecibido.message.toLowerCase().includes("network")||errorRecibido.message.toLowerCase().includes("socket"))) mensajeUsuario="Error de red externa.";
  else if(errorRecibido.message.includes("404")||errorRecibido.message.includes("no encontrado")){ codigoEstado=404; mensajeUsuario="Recurso no encontrado."; }
  else if(errorRecibido.code && typeof errorRecibido.code ==='string'&&(errorRecibido.code.startsWith('2')||errorRecibido.code.startsWith('PGR'))){ console.warn("Error DB (Supabase/Postgres):", errorRecibido.code, errorRecibido.detail||errorRecibido.hint); mensajeUsuario=errorRecibido.message.includes("constraint")?"Conflicto de datos.":"Error en BD."; if(errorRecibido.code==='23505')codigoEstado=409; else codigoEstado=500;}
  respuesta.status(codigoEstado).json({ error: mensajeUsuario });
});


const PUERTO = PUERTO_ENV || 3001;
app.listen(PUERTO, () => {
    console.log(`\n🚀 Servidor en puerto ${PUERTO} | ${esDesarrollo ? 'DEV' : 'PROD'}`);
    console.log(`🔗 Local: http://localhost:${PUERTO}`);
    console.log(`\n--- Estado Servicios ---`);
    console.log(` Supabase: ${supabase ? `✅ OK (PDFs en '${BUCKET_PDF_SUPABASE}', Imágenes en '${BUCKET_IMAGENES_SUPABASE}')` : '❌ NO OK (Verificar URL/KEY)'}`);
    console.log(` Google GenAI: ${clienteIA ? '✅ OK' : '❌ NO OK (Verificar CLAVE_API_GOOGLE)'}`);
    console.log(` Clipdrop Imagen: ${CLAVE_API_CLIPDROP_ENV ? '✅ OK' : '❌ NO OK (Verificar CLAVE_API_CLIPDROP_ENV)'}`);
    console.log(`----------------------\n`);
});
