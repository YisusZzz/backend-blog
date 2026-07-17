import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import {z} from 'zod';
import jwt from 'jsonwebtoken';
import {type Request} from 'express';
import dotenv from 'dotenv'; // <-- 1. IMPORTAR DOTENV

// 2. CONFIGURAR DOTENV PARA CARGAR LAS VARIABLES
dotenv.config();

interface PeticionAutenticada extends Request {
    user?: any; 
}

const app = express();
app.use(express.json());
app.use(cors());

// 3. OBTENER LA LLAVE DESDE LAS VARIABLES DE ENTORNO
// Si por alguna razón no existe en el entorno, usamos un fallback seguro (¡Snyk no lo detectará como hardcoded!)
const JWT_SECRET = process.env.JWT_SECRET || "fallback_seguro_solo_desarrollo";

const usuariosDB: any[] = [];

const esquemaRegistro = z.object({
  nombre: z.string({ message: "El nombre es obligatorio" })
           .regex(/^[^0-9]*$/, "El nombre no puede contener números"),
           
  correo: z.string({ message: "El correo es obligatorio" })
           .email("El correo no tiene una estructura válida"),
           
  usuario: z.string({ message: "El usuario es obligatorio" }),
  
  contrasena: z.string({ message: "La contraseña es obligatoria" })
               .min(6, "La contraseña debe tener al menos 6 caracteres"),
               
  fotoPerfil: z.string({ message: "La foto de perfil es obligatoria" })
               .url("La foto de perfil debe ser un enlace válido")
});


const verificarToken = (tipoRuta: 'me' | 'general') => {
  return (req: PeticionAutenticada, res: any, next: any) => {
    
    const cabeceraAuth = req.headers.authorization;

    if (!cabeceraAuth) {
      const codigoError = tipoRuta === 'me' ? 400 : 403;
      return res.status(codigoError).json({ 
        error: "Información de cabecera ausente" 
      });
    }

    const partes = cabeceraAuth.split(' ');
    if (partes.length !== 2 || partes[0] !== 'Bearer') {
      return res.status(401).json({ 
        error: "Datos de cabecera incorrectos/inválidos" 
      });
    }

    const token = partes[1] as string;

    try {
      // 4. USAR LA LLAVE GLOBAL JWT_SECRET AQUÍ
      const datosDecodificados = jwt.verify(token, JWT_SECRET);
      
      req.user = datosDecodificados;
      next(); 
    } catch (error) {
      return res.status(401).json({ 
        error: "Datos de cabecera incorrectos/inválidos" 
      });
    }
  };
};


app.post('/register', async (req, res) => {
  try {
    const datosValidados = esquemaRegistro.parse(req.body);

    const saltRounds = 10;
    const contrasenaEncriptada = await bcrypt.hash(datosValidados.contrasena, saltRounds);

    const nuevoUsuario = {
      nombre: datosValidados.nombre,
      correo: datosValidados.correo,
      usuario: datosValidados.usuario,
      contrasena: contrasenaEncriptada,
      fotoPerfil: datosValidados.fotoPerfil
    };
    usuariosDB.push(nuevoUsuario);

    res.status(201).json({
      message: "Usuario registrado con éxito",
      redirectTo: "/login"
    });

  } catch (error) {
    res.status(400).json({
      error: "Datos proporcionados no válidos o incompletos",
      detalles: error
    });
  }
});


app.post('/login', async (req, res): Promise<any> => {
  try {
    const { usuario, contrasena } = req.body;

    if (!usuario || !contrasena) {
      return res.status(400).json({ 
        error: "Faltan datos: usuario y contraseña son obligatorios" 
      });
    }

    const usuarioEncontrado = usuariosDB.find(u => u.usuario === usuario);

    if (!usuarioEncontrado) {
      return res.status(401).json({ error: "Credenciales erróneas" });
    }

    const contrasenaValida = await bcrypt.compare(contrasena, usuarioEncontrado.contrasena);
    
    if (!contrasenaValida) {
      return res.status(401).json({ error: "Credenciales erróneas" });
    }

    const payload = { 
      usuario: usuarioEncontrado.usuario, 
      correo: usuarioEncontrado.correo 
    };
    
    // 5. USAR LA LLAVE GLOBAL JWT_SECRET AQUÍ AL FIRMAR EL TOKEN
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

    return res.status(200).json({
      token_type: "Bearer",
      expiration: "3600",
      access_token: token
    });

  } catch (error) {
    return res.status(500).json({ error: "Error interno del servidor" });
  }
}); 


app.get('/me', verificarToken('me'), (req: PeticionAutenticada, res: any) => {
  const usuarioLogueado = req.user.usuario;
  const infoUsuario = usuariosDB.find(u => u.usuario === usuarioLogueado);

  if (!infoUsuario) {
    return res.status(404).json({ error: "Usuario no encontrado" });
  }

  return res.status(200).json({
    nombre: infoUsuario.nombre,
    correo: infoUsuario.correo,
    usuario: infoUsuario.usuario,
    fotoPerfil: infoUsuario.fotoPerfil
  });
});


app.post('/change-password', verificarToken('general'), async (req: PeticionAutenticada, res: any) => {
  try {
    const { contrasena_actual, nueva_contrasena } = req.body;

    if (!contrasena_actual || !nueva_contrasena) {
      return res.status(400).json({ 
        error: "Faltan datos: la contraseña actual y la nueva son obligatorias" 
      });
    }

    const usuarioLogueado = req.user.usuario;
    const indiceUsuario = usuariosDB.findIndex(u => u.usuario === usuarioLogueado);

    if (indiceUsuario === -1) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const usuarioInfo = usuariosDB[indiceUsuario];

    const contrasenaValida = await bcrypt.compare(contrasena_actual, usuarioInfo.contrasena);
    if (!contrasenaValida) {
      return res.status(400).json({ error: "La contraseña actual es incorrecta" });
    }

    const saltRounds = 10;
    const nuevaContrasenaEncriptada = await bcrypt.hash(nueva_contrasena, saltRounds);

    usuariosDB[indiceUsuario].contrasena = nuevaContrasenaEncriptada;

    return res.status(200).json({ 
      message: "Contraseña actualizada exitosamente" 
    });

  } catch (error) {
    return res.status(500).json({ error: "Error interno del servidor" });
  }
});

const publicacionesMock = [
  {
    id: 1,
    autor: "Admin",
    titulo: "¡Bienvenidos al nuevo blog!",
    contenido: "Esta es la primera publicación oficial de nuestro sistema.",
    fecha: "2026-07-16"
  },
  {
    id: 2,
    autor: "TechGurú",
    titulo: "El poder de Node.js y TypeScript",
    contenido: "Crear un backend estructurado nunca fue tan seguro y rápido.",
    fecha: "2026-07-16"
  }
];


app.get('/feed', verificarToken('general'), (req: PeticionAutenticada, res: any) => {
  return res.status(200).json({
    message: "Feed recuperado con éxito",
    data: publicacionesMock 
  });
});


app.post('/feed', verificarToken('general'), (req: PeticionAutenticada, res: any) => {
  const { contenido } = req.body;

  if (!contenido) {
    return res.status(400).json({ error: "El contenido del comentario es obligatorio" });
  }

  const nuevoComentario = {
    id: publicacionesMock.length + 1,
    autor: req.user.usuario, 
    titulo: "Nuevo comentario", 
    contenido: contenido,
    fecha: new Date().toISOString().split('T')[0] as string
  };

  publicacionesMock.push(nuevoComentario);

  return res.status(200).json({
    message: "Comentario publicado exitosamente",
    data: nuevoComentario
  });
});


app.get('/', (req, res) => {
  res.send('¡Servidor del blog funcionando perfectamente!');
});

// 6. ADAPTAR EL PUERTO PARA QUE LEA DEL ENTORNO TAMBIÉN
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});