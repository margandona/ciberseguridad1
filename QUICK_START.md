# 🚀 Guía de Inicio Rápido - Sistema de Autenticación Avanzado

## ✅ Sistema de Ciberseguridad Implementado

¡Tu sistema de autenticación y autorización con enfoque en **hacking ético defensivo** está listo! 

### 🛡️ Características de Ciberseguridad Avanzadas

✅ **Autenticación Robusta** - JWT con bcrypt salt factor 12  
✅ **Sistema de Roles** - Usuario, Moderador, Admin con jerarquía  
✅ **Protección XSS** - Sanitización con express-validator  
✅ **Protección CSRF** - Tokens CSRF obligatorios  
✅ **Rate Limiting** - Anti-brute force inteligente  
✅ **Honeypot** - Detección automática de bots  
✅ **Auditoría Completa** - Logs cifrados de todas las actividades  
✅ **Detección de Anomalías** - IA para patrones sospechosos  
✅ **Monitoreo en Tiempo Real** - Dashboard de seguridad  
✅ **Análisis de Riesgo** - Scoring automático de amenazas  
✅ **Cabeceras Seguras** - Helmet.js con CSP  

### 🎯 Frontend Interactivo Incluido

- **HTML5 + CSS3 + JavaScript** completamente funcional
- **Dashboard de administración** con gestión de usuarios
- **Panel de blog** con CRUD de posts
- **Sistema de alertas** en tiempo real
- **Monitoreo de seguridad** visual

## 📋 Pasos para Ejecutar

### 1. Verificar Instalación
Las dependencias ya están instaladas. Si necesitas reinstalarlas:
```bash
npm install
```

### 2. Configurar Base de Datos
Asegúrate de que MongoDB esté ejecutándose:

**Windows:**
```bash
mongod
# O si está instalado como servicio:
net start MongoDB
```

**macOS:**
```bash
brew services start mongodb-community
```

**Linux:**
```bash
sudo systemctl start mongod
```

### 3. Crear Usuario Administrador
```bash
node setup-admin.js
```
Esto creará un admin con:
- Email: `admin@sistema.com`
- Password: `AdminSecure123!`

### 4. Iniciar el Servidor
```bash
npm start
# O para desarrollo con auto-reload:
npm run dev
```

### 5. Probar el Sistema
```bash
npm test
```

## 🌐 Endpoints Principales

### Frontend
- **Aplicación Web**: `http://localhost:3000/` (Acceso completo con interfaz)

### API Backend
- **Health Check**: `GET /api/health`
- **CSRF Token**: `GET /api/csrf-token`
- **Registro**: `POST /api/auth/register`
- **Login**: `POST /api/auth/login`
- **Perfil**: `GET /api/auth/profile`
- **Admin Dashboard**: `GET /api/admin/dashboard`
- **Gestión de usuarios**: `/api/admin/users/*`
- **Blog Posts**: `/api/blog/posts` y `/api/admin/posts`
- **Logs de Seguridad**: `GET /api/admin/logs`
- **Reporte de Seguridad**: `GET /api/admin/security-report`

## 🧪 Ejemplos de Uso

### Acceso Web Completo
1. Abrir navegador en `http://localhost:3000`
2. Usar la interfaz para registro/login
3. Explorar dashboard según tu rol
4. Los administradores verán panel completo con:
   - Estadísticas del sistema
   - Gestión de usuarios
   - Logs de seguridad en tiempo real
   - Reportes de ciberseguridad

### Pruebas de Hacking Ético (API)

#### Test de Honeypot (Detección de Bots)
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $(curl -s http://localhost:3000/api/csrf-token | jq -r .csrfToken)" \
  -d '{
    "email": "test@bot.com",
    "password": "Password123!",
    "confirmPassword": "Password123!",
    "website": "http://malicious.com"
  }'
# Esperado: 403 Forbidden (Honeypot activado)
```

#### Test de Rate Limiting
```bash
for i in {1..6}; do
  curl -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $(curl -s http://localhost:3000/api/csrf-token | jq -r .csrfToken)" \
    -d '{"email": "fake@test.com", "password": "wrong"}' &
done
# Esperado: Bloqueo después del 5to intento
```

#### Test de Escalada de Privilegios
```bash
# Intentar acceder a admin sin permisos
curl -X GET http://localhost:3000/api/admin/dashboard \
  -H "Authorization: Bearer USER_TOKEN"
# Esperado: 403 Forbidden
```

## 🔧 Comandos Útiles

```bash
# Listar usuarios en la base de datos
node setup-admin.js list

# Ejecutar tests de seguridad automatizados
npm test

# Ver logs en tiempo real (desarrollo)
npm run dev

# Verificar vulnerabilidades
npm audit

# Generar reporte de seguridad (requiere admin token)
curl -X GET http://localhost:3000/api/admin/security-report \
  -H "Authorization: Bearer ADMIN_TOKEN"

# Ver logs de auditoría
curl -X GET "http://localhost:3000/api/admin/logs?severity=high" \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

## 🛡️ Características de Seguridad

✅ **Autenticación JWT** con expiración configurable  
✅ **Hash de contraseñas** con bcrypt salt factor 12  
✅ **Protección CSRF** con tokens únicos por sesión  
✅ **Rate limiting** anti-brute force inteligente  
✅ **Validación robusta** con express-validator  
✅ **Cabeceras seguras** con Helmet.js y CSP  
✅ **Control de acceso** por roles jerárquicos  
✅ **Bloqueo automático** tras intentos fallidos  
✅ **CORS configurado** según entorno  
✅ **Honeypots** para detección de bots  
✅ **Auditoría completa** con logs cifrados  
✅ **Detección de anomalías** con IA básica  
✅ **Monitoreo en tiempo real** de amenazas  
✅ **Análisis de riesgo** automático  
✅ **Reportes de seguridad** detallados  

### 🔍 Hacking Ético Defensivo Implementado

1. **Simulación de Ataques**: El sistema detecta y bloquea:
   - Inyección SQL/NoSQL
   - Cross-Site Scripting (XSS)
   - Cross-Site Request Forgery (CSRF)
   - Escalada de privilegios
   - Ataques de fuerza bruta
   - Actividad de bots maliciosos

2. **Monitoreo Proactivo**:
   - Scoring de riesgo en tiempo real
   - Detección de patrones anómalos
   - Alertas automáticas de seguridad
   - Honeypots para análisis de amenazas

3. **Auditoría Completa**:
   - Todos los eventos registrados
   - Análisis forense disponible
   - Reportes de seguridad automatizados
   - Cumplimiento con estándares OWASP  

## 📂 Archivos Importantes

- `app.js` - Aplicación principal con seguridad avanzada
- `public/index.html` - Frontend interactivo completo
- `public/app.js` - JavaScript con monitoreo de seguridad
- `public/styles.css` - Estilos responsivos y seguros
- `models/User.js` - Modelo de usuario con validaciones
- `models/BlogPost.js` - Modelo de posts con sanitización
- `models/AuditLog.js` - Sistema de auditoría avanzado
- `routes/auth.js` - Rutas de autenticación con honeypots
- `routes/admin.js` - Panel de administración completo
- `routes/blog.js` - API del blog público
- `middleware/auth.js` - Middlewares de seguridad avanzados
- `setup-admin.js` - Creación de usuarios admin
- `test-security.js` - Suite de tests de penetración
- `.env` - Configuración segura del entorno

## 🆘 Solución de Problemas

### MongoDB no conecta
- Verificar que MongoDB esté ejecutándose
- Revisar la URI en `.env`
- Comprobar permisos de base de datos

### Error CSRF Token
- Obtener token de `/api/csrf-token` primero
- Incluir header `X-CSRF-Token` en requests POST

### Usuario no puede acceder a admin
- Verificar que el rol sea 'admin'
- Usar el script `setup-admin.js` para crear admin

## 📚 Próximos Pasos

1. **Personalizar roles**: Edita el modelo User para roles específicos
2. **Agregar más endpoints**: Extiende las rutas según tu aplicación
3. **Configurar HTTPS**: Para producción, usar certificados SSL
4. **Implementar logging**: Usar Winston para logs estructurados
5. **Agregar tests**: Expandir la suite de tests

## 🤝 Necesitas Ayuda?

- Revisa el archivo `README.md` para documentación completa
- Ejecuta `npm test` para verificar que todo funciona
- Usa `node setup-admin.js list` para ver usuarios creados

¡Tu sistema está listo para usar! 🎉
