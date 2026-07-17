# Backend - API de Autenticación y Feed

Este es el servidor backend de la aplicación, construido con **Node.js**, **TypeScript** y **Express**. Se encarga de la gestión de usuarios, autenticación segura con **JWT** y la lógica del feed.

## Requisitos Previos

* [Node.js](https://nodejs.org/) (versión 18 o superior recomendada)
* npm (incluido con Node.js)

## Instalación y Configuración

1. Instala las dependencias necesarias:

   ```bash
   npm install
   ```

2. Configuración de Variables de Entorno:

   * Crea un archivo `.env` en la raíz del proyecto basándote en el archivo `.env.example`.
   * Asegúrate de definir el puerto (ej. `PORT=3000`) y una clave secreta segura (`JWT_SECRET`).

## Ejecución del Servidor

Para iniciar el servidor en modo desarrollo (con recarga automática):

```bash
npm run dev
```

El servidor estará escuchando peticiones en `http://localhost:3000` (o el puerto que hayas configurado en tus variables de entorno).

## 🤖 Uso de Inteligencia Artificial

Durante el desarrollo de este proyecto se utilizaron herramientas de inteligencia artificial (**Claude** y **Gemini**) como apoyo en las siguientes etapas:

- **Planificación:** Definición de la arquitectura del servidor y diseño del flujo de autenticación (registro, login, manejo de tokens JWT).
- **Pruebas:** Generación y revisión de casos de prueba para validar los endpoints de autenticación y feed, así como el manejo de errores.

Todo el código y las decisiones generadas con apoyo de IA fueron revisados, ajustados y validados manualmente antes de integrarse al proyecto.