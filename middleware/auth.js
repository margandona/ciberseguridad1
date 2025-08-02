const jwt = require('jsonwebtoken');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

// Middleware para verificar el token JWT
const verifyToken = async (req, res, next) => {
  try {
    // Buscar el token en diferentes lugares
    let token = req.header('Authorization');
    
    if (!token) {
      // También buscar en cookies si no está en headers
      token = req.cookies?.token;
    }
    
    if (!token) {
      return res.status(401).json({
        error: 'Acceso denegado',
        message: 'No se proporcionó token de autenticación'
      });
    }
    
    // Remover 'Bearer ' si está presente
    if (token.startsWith('Bearer ')) {
      token = token.substring(7);
    }
    
    // Verificar el token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Buscar el usuario en la base de datos
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({
        error: 'Token inválido',
        message: 'El usuario asociado al token no existe'
      });
    }
    
    // Verificar si el usuario está activo
    if (!user.isActive) {
      return res.status(401).json({
        error: 'Cuenta desactivada',
        message: 'Tu cuenta ha sido desactivada'
      });
    }
    
    // Verificar si la cuenta está bloqueada
    if (user.isLocked) {
      return res.status(423).json({
        error: 'Cuenta bloqueada',
        message: 'Tu cuenta está temporalmente bloqueada debido a múltiples intentos fallidos'
      });
    }
    
    // Agregar información del usuario al request
    req.user = user;
    req.userId = user._id;
    next();
    
  } catch (error) {
    console.error('Error en verificación de token:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Token inválido',
        message: 'El token proporcionado no es válido'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expirado',
        message: 'El token ha expirado, inicia sesión nuevamente'
      });
    }
    
    return res.status(500).json({
      error: 'Error interno',
      message: 'Error al verificar la autenticación'
    });
  }
};

// Middleware para verificar roles específicos
const requireRole = (roles) => {
  // Normalizar roles a array
  if (typeof roles === 'string') {
    roles = [roles];
  }
  
  return (req, res, next) => {
    // Verificar que el usuario esté autenticado
    if (!req.user) {
      return res.status(401).json({
        error: 'No autenticado',
        message: 'Debes estar autenticado para acceder a este recurso'
      });
    }
    
    // Verificar si el usuario tiene uno de los roles requeridos
    const hasRequiredRole = roles.some(role => req.user.hasPermission(role));
    
    if (!hasRequiredRole) {
      return res.status(403).json({
        error: 'Acceso denegado',
        message: `Se requiere uno de los siguientes roles: ${roles.join(', ')}`,
        userRole: req.user.role
      });
    }
    
    next();
  };
};

// Middleware específico para administradores
const requireAdmin = requireRole(['admin']);

// Middleware específico para moderadores o administradores
const requireModerator = requireRole(['moderador', 'admin']);

// Middleware para verificar que el usuario puede acceder a su propio recurso o es admin
const requireOwnerOrAdmin = (resourceUserIdField = 'userId') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'No autenticado',
        message: 'Debes estar autenticado para acceder a este recurso'
      });
    }
    
    // Si es admin, permitir acceso
    if (req.user.role === 'admin') {
      return next();
    }
    
    // Obtener el ID del recurso (puede estar en params, body, o query)
    const resourceUserId = req.params[resourceUserIdField] || 
                          req.body[resourceUserIdField] || 
                          req.query[resourceUserIdField];
    
    // Verificar que el usuario es propietario del recurso
    if (req.user._id.toString() !== resourceUserId) {
      return res.status(403).json({
        error: 'Acceso denegado',
        message: 'Solo puedes acceder a tus propios recursos'
      });
    }
    
    next();
  };
};

// Middleware para logging de actividad de usuarios con auditoría
const logUserActivity = (action) => {
  return async (req, res, next) => {
    try {
      // Capturar información de la request para logging
      const logData = {
        userId: req.user?._id,
        userEmail: req.user?.email || 'anonymous',
        action: action,
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || 'unknown',
        details: `${action} ejecutado en ${req.originalUrl}`,
        metadata: {
          httpMethod: req.method,
          endpoint: req.originalUrl,
          sessionId: req.sessionID
        }
      };

      // Determinar severidad basada en la acción
      if (['delete_user', 'change_user_role', 'security_violation'].includes(action)) {
        logData.severity = 'high';
      } else if (['admin_access', 'failed_login', 'user_created'].includes(action)) {
        logData.severity = 'medium';
      } else {
        logData.severity = 'low';
      }

      // Crear log de auditoría
      await AuditLog.createLog(logData);

      // Detectar anomalías si hay usuario
      if (req.user?._id) {
        const anomalies = await AuditLog.detectAnomalies(req.user._id);
        if (anomalies.length > 0) {
          console.warn(`⚠️ Anomalías detectadas para usuario ${req.user.email}:`, anomalies);
          
          // Marcar como anomalía si es crítica
          const criticalAnomalies = anomalies.filter(a => a.severity === 'high');
          if (criticalAnomalies.length > 0) {
            await AuditLog.createLog({
              ...logData,
              action: 'suspicious_activity',
              severity: 'critical',
              details: `Anomalías detectadas: ${JSON.stringify(anomalies)}`,
              isAnomaly: true
            });
          }
        }
      }

      // En un entorno de producción, esto se guardaría en una base de datos de auditoría
      console.log('User Activity:', JSON.stringify(logData, null, 2));
      
      next();
    } catch (error) {
      console.error('Error en logging de actividad:', error);
      // No bloquear la request si falla el logging
      next();
    }
  };
};

// Middleware para validar que el usuario no esté bloqueado
const checkUserLock = async (req, res, next) => {
  try {
    if (!req.user) {
      return next();
    }
    
    const user = await User.findById(req.user._id);
    
    if (user && user.isLocked) {
      return res.status(423).json({
        error: 'Cuenta bloqueada',
        message: 'Tu cuenta está temporalmente bloqueada. Intenta más tarde.',
        lockUntil: user.lockUntil
      });
    }
    
    next();
  } catch (error) {
    console.error('Error checking user lock:', error);
    next();
  }
};

module.exports = {
  verifyToken,
  requireRole,
  requireAdmin,
  requireModerator,
  requireOwnerOrAdmin,
  logUserActivity,
  checkUserLock
};
