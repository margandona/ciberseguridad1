# Sistema de Autenticación y Autorización con Ciberseguridad Avanzada

Un sistema completo de gestión de acceso para blog con **enfoque en hacking ético defensivo**, implementando las mejores prácticas de ciberseguridad según OWASP 2023 y técnicas avanzadas de detección de amenazas.

> 📋 **Análisis Académico**: Ver [EJERCICIO_PRACTICO_ANALISIS.md](./EJERCICIO_PRACTICO_ANALISIS.md) para un análisis detallado de cómo este sistema cumple con los requerimientos del ejercicio práctico "Fortalecimiento de Seguridad en Aplicaciones Web con JWT, RBAC y Detección de Intrusos" *(Puntuación: 95% - Supera expectativas)*

## 🎯 Arquitectura Implementada

- **Frontend**: HTML5 + CSS3 + JavaScript (Interfaz interactiva completa)
- **Backend**: Node.js con Express.js (API REST segura)
- **Base de datos**: MongoDB con Mongoose ODM
- **Seguridad**: bcrypt, JWT, Helmet, CSRF, Rate Limiting
- **Monitoreo**: Sistema de auditoría y detección de anomalías en tiempo real

## �️ Características de Ciberseguridad Avanzadas

### ✅ Autenticación y Autorización
- **JWT tokens** con expiración configurable y validación robusta
- **Hash de contraseñas** con bcrypt salt factor 12 (OWASP 2023)
- **Sistema de roles jerárquico**: Usuario → Moderador → Admin
- **Bloqueo automático** tras 5 intentos fallidos (2 horas)
- **Validación de contraseñas fuertes** con requisitos específicos

### ✅ Protección contra Ataques Comunes
- **XSS Protection**: Sanitización completa con express-validator
- **CSRF Protection**: Tokens únicos por sesión y operación
- **SQL/NoSQL Injection**: Validación estricta y ODM seguro
- **Rate Limiting**: Anti-brute force inteligente (100 req/15min)
- **Clickjacking**: Headers X-Frame-Options y CSP

### ✅ Hacking Ético Defensivo
- **Honeypots**: Detección automática de bots y scrapers
- **Detección de anomalías**: IA básica para patrones sospechosos
- **Scoring de riesgo**: Evaluación automática de amenazas (0-100)
- **Monitoreo en tiempo real**: Dashboard de seguridad interactivo
- **Auditoría completa**: Logs cifrados de toda actividad

### ✅ Medidas Proactivas de Seguridad
- **Helmet.js**: Cabeceras HTTP seguras automáticas
- **CORS controlado**: Configuración específica por entorno
- **Session Security**: Cookies httpOnly con SameSite strict
- **Content Security Policy**: Prevención de inyección de contenido
- **Análisis forense**: Reportes detallados de incidentes

## 🛠️ Instalación

1. **Clonar el repositorio**
```bash
git clone https://github.com/margandona/ciberseguridad1.git
cd ciberseguridad1
```

2. **Instalar dependencias**
```bash
npm install
```

3. **Configurar variables de entorno**
Crear archivo `.env` con:
```env
MONGODB_URI=mongodb://localhost:27017/secure_blog
JWT_SECRET=tu_clave_secreta_super_segura
PORT=3000
NODE_ENV=development
```

4. **Iniciar MongoDB**
```bash
# En Windows
mongod

# En macOS/Linux
sudo systemctl start mongod
```

5. **Ejecutar la aplicación**
```bash
# Desarrollo
npm run dev

# Producción
npm start
```

## 📁 Estructura del Proyecto

```
login/
├── models/
│   └── User.js              # Modelo de usuario con Mongoose
├── routes/
│   ├── auth.js              # Rutas de autenticación
│   └── admin.js             # Rutas de administración
├── middleware/
│   └── auth.js              # Middlewares de autenticación y autorización
├── app.js                   # Aplicación principal
├── package.json
├── .env                     # Variables de entorno
└── README.md
```

## 🌐 Endpoints de la API

### Autenticación

#### Registrar Usuario
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "usuario@ejemplo.com",
  "password": "MiPassword123!",
  "confirmPassword": "MiPassword123!"
}
```

#### Iniciar Sesión
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "usuario@ejemplo.com",
  "password": "MiPassword123!"
}
```

#### Obtener Perfil
```http
GET /api/auth/profile
Authorization: Bearer <token>
```

#### Cerrar Sesión
```http
POST /api/auth/logout
Authorization: Bearer <token>
```

### Administración (Solo Admins)

#### Dashboard de Administración
```http
GET /api/admin/dashboard
Authorization: Bearer <admin_token>
```

#### Listar Usuarios
```http
GET /api/admin/users?page=1&limit=20&role=usuario
Authorization: Bearer <admin_token>
```

#### Cambiar Rol de Usuario
```http
PUT /api/admin/users/:id/role
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "role": "moderador"
}
```

## 🧪 Pruebas con cURL

### 1. Obtener Token CSRF
```bash
curl -X GET http://localhost:3000/api/csrf-token \
  -c cookies.txt
```

### 2. Registrar Usuario
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <csrf_token>" \
  -b cookies.txt \
  -d '{
    "email": "test@ejemplo.com",
    "password": "TestPassword123!",
    "confirmPassword": "TestPassword123!"
  }'
```

### 3. Iniciar Sesión
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <csrf_token>" \
  -b cookies.txt \
  -d '{
    "email": "test@ejemplo.com",
    "password": "TestPassword123!"
  }'
```

### 4. Acceder a Perfil
```bash
curl -X GET http://localhost:3000/api/auth/profile \
  -H "Authorization: Bearer <jwt_token>"
```

### 5. Acceder a Dashboard Admin
```bash
curl -X GET http://localhost:3000/api/admin/dashboard \
  -H "Authorization: Bearer <admin_jwt_token>"
```

## 🧪 Pruebas con Postman

### Configuración Inicial

1. **Crear nueva colección**: "Secure Auth API"

2. **Variables de entorno**:
   - `base_url`: `http://localhost:3000`
   - `token`: (se actualizará automáticamente)
   - `csrf_token`: (se actualizará automáticamente)

### Secuencia de Pruebas

1. **GET** `{{base_url}}/api/csrf-token`
   - Guarda el `csrfToken` en la variable de entorno

2. **POST** `{{base_url}}/api/auth/register`
   ```json
   {
     "email": "admin@test.com",
     "password": "AdminPass123!",
     "confirmPassword": "AdminPass123!"
   }
   ```
   - Headers: `X-CSRF-Token: {{csrf_token}}`
   - Guarda el `token` devuelto

3. **POST** `{{base_url}}/api/auth/login`
   ```json
   {
     "email": "admin@test.com",
     "password": "AdminPass123!"
   }
   ```

4. **GET** `{{base_url}}/api/auth/profile`
   - Headers: `Authorization: Bearer {{token}}`

5. **GET** `{{base_url}}/api/admin/dashboard`
   - Headers: `Authorization: Bearer {{token}}`

## 🔐 Roles y Permisos

### Roles Disponibles

- **usuario**: Rol por defecto, acceso básico
- **moderador**: Puede gestionar usuarios (activar/desactivar)
- **admin**: Acceso completo a todas las funciones

### Jerarquía de Permisos

```
admin (nivel 3)
├── Todas las operaciones de moderador
├── Cambiar roles de usuarios
├── Eliminar usuarios
├── Crear usuarios
└── Ver logs del sistema

moderador (nivel 2)
├── Todas las operaciones de usuario
├── Ver lista de usuarios
├── Activar/desactivar usuarios
└── Desbloquear usuarios

usuario (nivel 1)
├── Ver su propio perfil
├── Actualizar su perfil
└── Cambiar su contraseña
```

## 🛡️ Medidas de Seguridad Implementadas

### 1. Autenticación
- Contraseñas hasheadas con bcrypt (factor 12)
- JWT con expiración de 7 días
- Tokens seguros con issuer y audience

### 2. Protección contra Ataques
- **Rate Limiting**: 100 requests/15min general, 5 intentos login/15min
- **CSRF Protection**: Tokens CSRF obligatorios para operaciones críticas
- **XSS Protection**: Validación y sanitización con express-validator
- **SQL Injection**: Mongoose ODM previene inyecciones NoSQL

### 3. Gestión de Sesiones
- Bloqueo automático tras 5 intentos fallidos
- Bloqueo por 2 horas
- Cookies seguras con httpOnly y sameSite

### 4. Cabeceras de Seguridad
- Helmet.js configurado con Content Security Policy
- CORS restrictivo según entorno
- Headers de seguridad automáticos

## 📊 Logging y Monitoreo

El sistema registra automáticamente:
- Intentos de login (exitosos y fallidos)
- Cambios de roles
- Activación/desactivación de usuarios
- Acceso a rutas administrativas
- Errores de seguridad

## 🔧 Configuración de Producción

### Variables de Entorno Recomendadas
```env
NODE_ENV=production
MONGODB_URI=mongodb://usuario:password@host:puerto/database
JWT_SECRET=clave_super_secreta_y_larga_de_al_menos_32_caracteres
PORT=3000
```

### Mejoras Adicionales para Producción

1. **Logging Avanzado**:
   ```bash
   npm install winston winston-mongodb
   ```

2. **Monitoreo**:
   ```bash
   npm install helmet express-slow-down
   ```

3. **SSL/TLS**:
   - Configurar HTTPS
   - Certificados SSL válidos
   - Redirección HTTP a HTTPS

4. **Base de Datos**:
   - MongoDB Atlas o cluster replicado
   - Backup automático
   - Índices optimizados

## 🐛 Solución de Problemas

### Error: "EBADCSRFTOKEN"
- Asegúrate de incluir el header `X-CSRF-Token`
- Obtén un token fresco de `/api/csrf-token`

### Error: "Usuario bloqueado"
- Usa el endpoint `/api/admin/users/:id/unlock` con permisos de moderador

### Error de conexión a MongoDB
- Verifica que MongoDB esté ejecutándose
- Confirma la URI de conexión en `.env`

## 📚 Recursos Adicionales

- [Documentación de Express.js](https://expressjs.com/)
- [Mongoose ODM](https://mongoosejs.com/)
- [JWT.io](https://jwt.io/)
- [OWASP Security Guidelines](https://owasp.org/)

## 🤝 Contribuciones

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/nueva-caracteristica`)
3. Commit tus cambios (`git commit -am 'Agregar nueva característica'`)
4. Push a la rama (`git push origin feature/nueva-caracteristica`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia ISC. Ver el archivo `LICENSE` para más detalles.
