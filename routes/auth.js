const express = require('express');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { verifyToken, logUserActivity } = require('../middleware/auth');

const router = express.Router();

// Validaciones para registro
const registerValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Debe ser un email válido'),
  
  body('password')
    .isLength({ min: 8 })
    .withMessage('La contraseña debe tener al menos 8 caracteres')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('La contraseña debe contener al menos una mayúscula, una minúscula, un número y un carácter especial'),
  
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Las contraseñas no coinciden');
      }
      return true;
    })
];

// Validaciones para login
const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Debe ser un email válido'),
  
  body('password')
    .notEmpty()
    .withMessage('La contraseña es requerida')
];

// Middleware para detectar honeypot
const detectHoneypot = async (req, res, next) => {
  const honeypotField = req.body.website || req.body.url || req.body.homepage;
  
  if (honeypotField && honeypotField.trim() !== '') {
    // Bot detectado - registrar en auditoría
    await AuditLog.createLog({
      userId: null,
      userEmail: req.body.email || 'unknown',
      action: 'honeypot_triggered',
      severity: 'high',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: `Honeypot activado con valor: ${honeypotField}`,
      metadata: {
        httpMethod: req.method,
        endpoint: req.originalUrl,
        honeypotValue: honeypotField
      },
      isAnomaly: true,
      riskScore: 85
    });

    return res.status(403).json({
      error: 'Acceso denegado',
      message: 'Actividad sospechosa detectada'
    });
  }
  
  next();
};

// Función para calcular score de riesgo
const calculateRiskScore = (req, user = null) => {
  let score = 0;
  
  // Factores de riesgo
  const userAgent = req.get('User-Agent') || '';
  
  // User-Agent sospechoso
  if (!userAgent || userAgent.length < 10) score += 20;
  if (userAgent.includes('bot') || userAgent.includes('crawler')) score += 30;
  
  // Horario inusual (entre 2 AM y 6 AM)
  const hour = new Date().getHours();
  if (hour >= 2 && hour <= 6) score += 15;
  
  // Headers sospechosos
  if (!req.get('Accept-Language')) score += 10;
  if (!req.get('Accept-Encoding')) score += 10;
  
  return Math.min(score, 100);
};

// Función para generar JWT
const generateToken = (userId) => {
  return jwt.sign(
    { userId }, 
    process.env.JWT_SECRET, 
    { 
      expiresIn: '7d',
      issuer: 'secure-auth-app',
      audience: 'secure-auth-users'
    }
  );
};

// Función para manejar errores de validación
const handleValidationErrors = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Errores de validación',
      message: 'Los datos proporcionados no son válidos',
      details: errors.array()
    });
  }
  return null;
};

// POST /api/auth/register - Registro de nuevos usuarios
router.post('/register', detectHoneypot, registerValidation, async (req, res) => {
  try {
    // Verificar errores de validación
    const validationError = handleValidationErrors(req, res);
    if (validationError) return;
    
    const { email, password } = req.body;
    
    // Calcular score de riesgo
    const riskScore = calculateRiskScore(req);
    
    // Verificar si el usuario ya existe
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      // Log intento de registro duplicado
      await AuditLog.createLog({
        userId: null,
        userEmail: email,
        action: 'register',
        severity: 'low',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: 'Intento de registro con email existente',
        riskScore
      });

      return res.status(409).json({
        error: 'Usuario ya existe',
        message: 'Ya existe una cuenta con este email'
      });
    }
    
    // Crear nuevo usuario
    const user = new User({
      email,
      password, // Se hasheará automáticamente por el middleware pre-save
      role: 'usuario' // Rol por defecto
    });
    
    await user.save();
    
    // Generar token JWT
    const token = generateToken(user._id);
    
    // Log registro exitoso
    await AuditLog.createLog({
      userId: user._id,
      userEmail: email,
      action: 'register',
      severity: 'low',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: 'Registro de usuario exitoso',
      riskScore
    });
    
    // Configurar cookie segura (opcional)
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 días
    });
    
    // Log de actividad
    console.log(`Nuevo usuario registrado: ${email}`);
    
    res.status(201).json({
      message: 'Usuario registrado exitosamente',
      user: user.toSafeObject(),
      token
    });
    
  } catch (error) {
    console.error('Error en registro:', error);
    
    if (error.code === 11000) {
      return res.status(409).json({
        error: 'Email duplicado',
        message: 'Ya existe una cuenta con este email'
      });
    }
    
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al registrar usuario'
    });
  }
});

// POST /api/auth/login - Inicio de sesión
router.post('/login', detectHoneypot, loginValidation, async (req, res) => {
  try {
    // Verificar errores de validación
    const validationError = handleValidationErrors(req, res);
    if (validationError) return;
    
    const { email, password } = req.body;
    
    // Calcular score de riesgo
    const riskScore = calculateRiskScore(req);
    
    // Buscar usuario por email
    const user = await User.findOne({ email });
    if (!user) {
      // Log intento de login con usuario inexistente
      await AuditLog.createLog({
        userId: null,
        userEmail: email,
        action: 'failed_login',
        severity: 'medium',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: 'Intento de login con email inexistente',
        riskScore
      });

      return res.status(401).json({
        error: 'Credenciales inválidas',
        message: 'Email o contraseña incorrectos'
      });
    }
    
    // Verificar si la cuenta está bloqueada
    if (user.isLocked) {
      return res.status(423).json({
        error: 'Cuenta bloqueada',
        message: 'Tu cuenta está temporalmente bloqueada debido a múltiples intentos fallidos',
        lockUntil: user.lockUntil
      });
    }
    
    // Verificar si la cuenta está activa
    if (!user.isActive) {
      return res.status(401).json({
        error: 'Cuenta desactivada',
        message: 'Tu cuenta ha sido desactivada'
      });
    }
    
    // Verificar contraseña
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      // Incrementar intentos fallidos
      await user.incLoginAttempts();
      
      // Log intento de login fallido
      await AuditLog.createLog({
        userId: user._id,
        userEmail: email,
        action: 'failed_login',
        severity: 'medium',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: 'Contraseña incorrecta',
        riskScore
      });
      
      return res.status(401).json({
        error: 'Credenciales inválidas',
        message: 'Email o contraseña incorrectos'
      });
    }
    
    // Login exitoso - resetear intentos fallidos
    await user.resetLoginAttempts();
    
    // Generar token JWT
    const token = generateToken(user._id);
    
    // Log login exitoso
    await AuditLog.createLog({
      userId: user._id,
      userEmail: email,
      action: 'login',
      severity: 'low',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: 'Login exitoso',
      riskScore
    });
    
    // Configurar cookie segura
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 días
    });
    
    // Log de actividad
    console.log(`Usuario logueado: ${email} desde IP: ${req.ip}`);
    
    res.json({
      message: 'Inicio de sesión exitoso',
      user: user.toSafeObject(),
      token
    });
    
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al iniciar sesión'
    });
  }
});

// POST /api/auth/logout - Cerrar sesión
router.post('/logout', verifyToken, logUserActivity('logout'), (req, res) => {
  try {
    // Limpiar cookie
    res.clearCookie('token');
    
    // Log de actividad
    console.log(`Usuario cerró sesión: ${req.user.email}`);
    
    res.json({
      message: 'Sesión cerrada exitosamente'
    });
    
  } catch (error) {
    console.error('Error en logout:', error);
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al cerrar sesión'
    });
  }
});

// GET /api/auth/profile - Obtener perfil del usuario autenticado
router.get('/profile', verifyToken, async (req, res) => {
  try {
    // El usuario ya está disponible en req.user gracias al middleware verifyToken
    res.json({
      message: 'Perfil obtenido exitosamente',
      user: req.user.toSafeObject()
    });
    
  } catch (error) {
    console.error('Error obteniendo perfil:', error);
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al obtener perfil'
    });
  }
});

// PUT /api/auth/profile - Actualizar perfil del usuario
router.put('/profile', 
  verifyToken,
  [
    body('email')
      .optional()
      .isEmail()
      .normalizeEmail()
      .withMessage('Debe ser un email válido')
  ],
  logUserActivity('update_profile'),
  async (req, res) => {
    try {
      // Verificar errores de validación
      const validationError = handleValidationErrors(req, res);
      if (validationError) return;
      
      const { email } = req.body;
      const userId = req.user._id;
      
      // Verificar si el nuevo email ya existe (si se está cambiando)
      if (email && email !== req.user.email) {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          return res.status(409).json({
            error: 'Email ya existe',
            message: 'Ya existe una cuenta con este email'
          });
        }
      }
      
      // Actualizar usuario
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { ...(email && { email }) },
        { new: true, runValidators: true }
      );
      
      res.json({
        message: 'Perfil actualizado exitosamente',
        user: updatedUser.toSafeObject()
      });
      
    } catch (error) {
      console.error('Error actualizando perfil:', error);
      res.status(500).json({
        error: 'Error interno del servidor',
        message: 'Error al actualizar perfil'
      });
    }
  }
);

// POST /api/auth/change-password - Cambiar contraseña
router.put('/change-password',
  verifyToken,
  [
    body('currentPassword')
      .notEmpty()
      .withMessage('La contraseña actual es requerida'),
    
    body('newPassword')
      .isLength({ min: 8 })
      .withMessage('La nueva contraseña debe tener al menos 8 caracteres')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('La nueva contraseña debe contener al menos una mayúscula, una minúscula, un número y un carácter especial'),
    
    body('confirmNewPassword')
      .custom((value, { req }) => {
        if (value !== req.body.newPassword) {
          throw new Error('Las contraseñas no coinciden');
        }
        return true;
      })
  ],
  logUserActivity('change_password'),
  async (req, res) => {
    try {
      // Verificar errores de validación
      const validationError = handleValidationErrors(req, res);
      if (validationError) return;
      
      const { currentPassword, newPassword } = req.body;
      const userId = req.user._id;
      
      // Obtener usuario con contraseña
      const user = await User.findById(userId);
      
      // Verificar contraseña actual
      const isCurrentPasswordValid = await user.comparePassword(currentPassword);
      if (!isCurrentPasswordValid) {
        return res.status(401).json({
          error: 'Contraseña incorrecta',
          message: 'La contraseña actual es incorrecta'
        });
      }
      
      // Actualizar contraseña
      user.password = newPassword;
      await user.save();
      
      res.json({
        message: 'Contraseña cambiada exitosamente'
      });
      
    } catch (error) {
      console.error('Error cambiando contraseña:', error);
      res.status(500).json({
        error: 'Error interno del servidor',
        message: 'Error al cambiar contraseña'
      });
    }
  }
);

// GET /api/auth/verify - Verificar si el token es válido
router.get('/verify', verifyToken, (req, res) => {
  res.json({
    message: 'Token válido',
    user: req.user.toSafeObject(),
    isAuthenticated: true
  });
});

module.exports = router;
