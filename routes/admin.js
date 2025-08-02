const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const BlogPost = require('../models/BlogPost');
const AuditLog = require('../models/AuditLog');
const { 
  verifyToken, 
  requireAdmin, 
  requireModerator, 
  logUserActivity 
} = require('../middleware/auth');

const router = express.Router();

// Aplicar middleware de autenticación a todas las rutas admin
router.use(verifyToken);

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

// GET /api/admin/dashboard - Panel de administración
router.get('/dashboard', requireAdmin, logUserActivity('view_admin_dashboard'), async (req, res) => {
  try {
    // Obtener estadísticas generales
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ isActive: true });
    const adminUsers = await User.countDocuments({ role: 'admin' });
    const moderatorUsers = await User.countDocuments({ role: 'moderador' });
    const regularUsers = await User.countDocuments({ role: 'usuario' });
    const lockedUsers = await User.countDocuments({ 
      lockUntil: { $exists: true, $gt: new Date() } 
    });
    
    // Usuarios registrados en los últimos 30 días
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const recentUsers = await User.countDocuments({ 
      createdAt: { $gte: thirtyDaysAgo } 
    });
    
    // Usuarios con login reciente (últimos 7 días)
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const activeLastWeek = await User.countDocuments({
      lastLogin: { $gte: sevenDaysAgo }
    });

    // Estadísticas de blog posts
    const totalPosts = await BlogPost.countDocuments();
    const publishedPosts = await BlogPost.countDocuments({ status: 'published' });
    const draftPosts = await BlogPost.countDocuments({ status: 'draft' });
    
    res.json({
      message: 'Dashboard de administración',
      statistics: {
        totalUsers,
        activeUsers,
        inactiveUsers: totalUsers - activeUsers,
        lockedUsers,
        recentUsers,
        activeLastWeek,
        usersByRole: {
          admin: adminUsers,
          moderador: moderatorUsers,
          usuario: regularUsers
        },
        blogStats: {
          totalPosts,
          publishedPosts,
          draftPosts
        }
      },
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Error en dashboard admin:', error);
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al obtener estadísticas del dashboard'
    });
  }
});

// GET /api/admin/users - Listar todos los usuarios (solo admin)
router.get('/users', requireAdmin, logUserActivity('view_all_users'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    // Filtros opcionales
    const filters = {};
    if (req.query.role) filters.role = req.query.role;
    if (req.query.isActive !== undefined) filters.isActive = req.query.isActive === 'true';
    if (req.query.search) {
      filters.email = { $regex: req.query.search, $options: 'i' };
    }
    
    // Obtener usuarios con paginación
    const users = await User.find(filters)
      .select('-password -loginAttempts')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await User.countDocuments(filters);
    
    res.json({
      message: 'Lista de usuarios',
      users: users.map(user => user.toSafeObject()),
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
    
  } catch (error) {
    console.error('Error listando usuarios:', error);
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al obtener lista de usuarios'
    });
  }
});

// GET /api/admin/users/:id - Obtener usuario específico
router.get('/users/:id', requireModerator, logUserActivity('view_user_details'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    
    if (!user) {
      return res.status(404).json({
        error: 'Usuario no encontrado',
        message: 'No existe un usuario con el ID proporcionado'
      });
    }
    
    res.json({
      message: 'Detalles del usuario',
      user: user.toSafeObject()
    });
    
  } catch (error) {
    console.error('Error obteniendo usuario:', error);
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al obtener detalles del usuario'
    });
  }
});

// PUT /api/admin/users/:id/role - Cambiar rol de usuario (solo admin)
router.put('/users/:id/role', 
  requireAdmin,
  [
    body('role')
      .isIn(['usuario', 'moderador', 'admin'])
      .withMessage('Rol inválido. Debe ser: usuario, moderador o admin')
  ],
  logUserActivity('change_user_role'),
  async (req, res) => {
    try {
      // Verificar errores de validación
      const validationError = handleValidationErrors(req, res);
      if (validationError) return;
      
      const { role } = req.body;
      const userId = req.params.id;
      
      // No permitir que un admin se quite sus propios permisos
      if (userId === req.user._id.toString() && role !== 'admin') {
        return res.status(400).json({
          error: 'Operación no permitida',
          message: 'No puedes cambiar tu propio rol de administrador'
        });
      }
      
      const user = await User.findByIdAndUpdate(
        userId,
        { role },
        { new: true, runValidators: true }
      ).select('-password');
      
      if (!user) {
        return res.status(404).json({
          error: 'Usuario no encontrado',
          message: 'No existe un usuario con el ID proporcionado'
        });
      }
      
      console.log(`Admin ${req.user.email} cambió rol de ${user.email} a ${role}`);
      
      res.json({
        message: 'Rol actualizado exitosamente',
        user: user.toSafeObject()
      });
      
    } catch (error) {
      console.error('Error cambiando rol:', error);
      res.status(500).json({
        error: 'Error interno del servidor',
        message: 'Error al cambiar rol del usuario'
      });
    }
  }
);

// PUT /api/admin/users/:id/status - Activar/desactivar usuario
router.put('/users/:id/status',
  requireModerator,
  [
    body('isActive')
      .isBoolean()
      .withMessage('isActive debe ser un valor booleano')
  ],
  logUserActivity('change_user_status'),
  async (req, res) => {
    try {
      // Verificar errores de validación
      const validationError = handleValidationErrors(req, res);
      if (validationError) return;
      
      const { isActive } = req.body;
      const userId = req.params.id;
      
      // No permitir que un usuario se desactive a sí mismo
      if (userId === req.user._id.toString() && !isActive) {
        return res.status(400).json({
          error: 'Operación no permitida',
          message: 'No puedes desactivar tu propia cuenta'
        });
      }
      
      const user = await User.findByIdAndUpdate(
        userId,
        { isActive },
        { new: true, runValidators: true }
      ).select('-password');
      
      if (!user) {
        return res.status(404).json({
          error: 'Usuario no encontrado',
          message: 'No existe un usuario con el ID proporcionado'
        });
      }
      
      console.log(`${req.user.email} ${isActive ? 'activó' : 'desactivó'} cuenta de ${user.email}`);
      
      res.json({
        message: `Usuario ${isActive ? 'activado' : 'desactivado'} exitosamente`,
        user: user.toSafeObject()
      });
      
    } catch (error) {
      console.error('Error cambiando status:', error);
      res.status(500).json({
        error: 'Error interno del servidor',
        message: 'Error al cambiar status del usuario'
      });
    }
  }
);

// POST /api/admin/users/:id/unlock - Desbloquear usuario
router.post('/users/:id/unlock',
  requireModerator,
  logUserActivity('unlock_user'),
  async (req, res) => {
    try {
      const userId = req.params.id;
      
      const user = await User.findByIdAndUpdate(
        userId,
        { 
          $unset: { lockUntil: 1, loginAttempts: 1 }
        },
        { new: true }
      ).select('-password');
      
      if (!user) {
        return res.status(404).json({
          error: 'Usuario no encontrado',
          message: 'No existe un usuario con el ID proporcionado'
        });
      }
      
      console.log(`${req.user.email} desbloqueó cuenta de ${user.email}`);
      
      res.json({
        message: 'Usuario desbloqueado exitosamente',
        user: user.toSafeObject()
      });
      
    } catch (error) {
      console.error('Error desbloqueando usuario:', error);
      res.status(500).json({
        error: 'Error interno del servidor',
        message: 'Error al desbloquear usuario'
      });
    }
  }
);

// DELETE /api/admin/users/:id - Eliminar usuario (solo admin)
router.delete('/users/:id',
  requireAdmin,
  logUserActivity('delete_user'),
  async (req, res) => {
    try {
      const userId = req.params.id;
      
      // No permitir que un admin se elimine a sí mismo
      if (userId === req.user._id.toString()) {
        return res.status(400).json({
          error: 'Operación no permitida',
          message: 'No puedes eliminar tu propia cuenta'
        });
      }
      
      const user = await User.findByIdAndDelete(userId);
      
      if (!user) {
        return res.status(404).json({
          error: 'Usuario no encontrado',
          message: 'No existe un usuario con el ID proporcionado'
        });
      }
      
      console.log(`Admin ${req.user.email} eliminó cuenta de ${user.email}`);
      
      res.json({
        message: 'Usuario eliminado exitosamente',
        deletedUser: {
          id: user._id,
          email: user.email
        }
      });
      
    } catch (error) {
      console.error('Error eliminando usuario:', error);
      res.status(500).json({
        error: 'Error interno del servidor',
        message: 'Error al eliminar usuario'
      });
    }
  }
);

// POST /api/admin/create-user - Crear nuevo usuario (solo admin)
router.post('/create-user',
  requireAdmin,
  [
    body('email')
      .isEmail()
      .normalizeEmail()
      .withMessage('Debe ser un email válido'),
    
    body('password')
      .isLength({ min: 8 })
      .withMessage('La contraseña debe tener al menos 8 caracteres')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('La contraseña debe contener al menos una mayúscula, una minúscula, un número y un carácter especial'),
    
    body('role')
      .optional()
      .isIn(['usuario', 'moderador', 'admin'])
      .withMessage('Rol inválido. Debe ser: usuario, moderador o admin')
  ],
  logUserActivity('create_user'),
  async (req, res) => {
    try {
      // Verificar errores de validación
      const validationError = handleValidationErrors(req, res);
      if (validationError) return;
      
      const { email, password, role = 'usuario' } = req.body;
      
      // Verificar si el usuario ya existe
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({
          error: 'Usuario ya existe',
          message: 'Ya existe una cuenta con este email'
        });
      }
      
      // Crear nuevo usuario
      const user = new User({
        email,
        password,
        role
      });
      
      await user.save();
      
      console.log(`Admin ${req.user.email} creó nueva cuenta para ${email} con rol ${role}`);
      
      res.status(201).json({
        message: 'Usuario creado exitosamente',
        user: user.toSafeObject()
      });
      
    } catch (error) {
      console.error('Error creando usuario:', error);
      res.status(500).json({
        error: 'Error interno del servidor',
        message: 'Error al crear usuario'
      });
    }
  }
);

// === GESTIÓN DE BLOG POSTS ===

// POST /api/admin/posts - Crear nuevo post (solo admin/moderador)
router.post('/posts',
  requireModerator,
  [
    body('title')
      .trim()
      .isLength({ min: 1, max: 200 })
      .withMessage('El título debe tener entre 1 y 200 caracteres')
      .matches(/^[^<>]*$/)
      .withMessage('El título contiene caracteres no permitidos'),
    
    body('content')
      .trim()
      .isLength({ min: 1, max: 10000 })
      .withMessage('El contenido debe tener entre 1 y 10,000 caracteres')
      .custom((value) => {
        if (/<script|javascript:|on\w+\s*=/gi.test(value)) {
          throw new Error('El contenido contiene elementos no permitidos');
        }
        return true;
      })
  ],
  logUserActivity('create_blog_post'),
  async (req, res) => {
    try {
      // Verificar errores de validación
      const validationError = handleValidationErrors(req, res);
      if (validationError) return;
      
      const { title, content } = req.body;
      
      // Crear nuevo post
      const post = new BlogPost({
        title,
        content,
        author: req.user._id,
        authorEmail: req.user.email,
        status: 'published',
        metadata: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          createdFrom: 'admin_panel'
        }
      });
      
      await post.save();
      
      console.log(`${req.user.email} creó nuevo post: ${title}`);
      
      res.status(201).json({
        message: 'Post creado exitosamente',
        post: post.toSafeObject()
      });
      
    } catch (error) {
      console.error('Error creando post:', error);
      res.status(500).json({
        error: 'Error interno del servidor',
        message: 'Error al crear el post'
      });
    }
  }
);

// GET /api/admin/posts - Listar todos los posts (solo admin/moderador)
router.get('/posts', requireModerator, logUserActivity('view_blog_posts'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    // Filtros opcionales
    const filters = {};
    if (req.query.status) filters.status = req.query.status;
    if (req.query.author) filters.author = req.query.author;
    
    // Obtener posts con paginación
    const posts = await BlogPost.find(filters)
      .populate('author', 'email role')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await BlogPost.countDocuments(filters);
    
    res.json({
      message: 'Lista de posts',
      posts: posts.map(post => post.toSafeObject()),
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
    
  } catch (error) {
    console.error('Error listando posts:', error);
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al obtener lista de posts'
    });
  }
});

// PUT /api/admin/posts/:id - Actualizar post
router.put('/posts/:id',
  requireModerator,
  [
    body('title')
      .optional()
      .trim()
      .isLength({ min: 1, max: 200 })
      .withMessage('El título debe tener entre 1 y 200 caracteres'),
    
    body('content')
      .optional()
      .trim()
      .isLength({ min: 1, max: 10000 })
      .withMessage('El contenido debe tener entre 1 y 10,000 caracteres'),
      
    body('status')
      .optional()
      .isIn(['draft', 'published', 'archived'])
      .withMessage('Estado inválido')
  ],
  logUserActivity('update_blog_post'),
  async (req, res) => {
    try {
      // Verificar errores de validación
      const validationError = handleValidationErrors(req, res);
      if (validationError) return;
      
      const postId = req.params.id;
      const updates = req.body;
      
      const post = await BlogPost.findByIdAndUpdate(
        postId,
        updates,
        { new: true, runValidators: true }
      ).populate('author', 'email role');
      
      if (!post) {
        return res.status(404).json({
          error: 'Post no encontrado',
          message: 'No existe un post con el ID proporcionado'
        });
      }
      
      console.log(`${req.user.email} actualizó post: ${post.title}`);
      
      res.json({
        message: 'Post actualizado exitosamente',
        post: post.toSafeObject()
      });
      
    } catch (error) {
      console.error('Error actualizando post:', error);
      res.status(500).json({
        error: 'Error interno del servidor',
        message: 'Error al actualizar el post'
      });
    }
  }
);

// DELETE /api/admin/posts/:id - Eliminar post
router.delete('/posts/:id',
  requireAdmin,
  logUserActivity('delete_blog_post'),
  async (req, res) => {
    try {
      const postId = req.params.id;
      
      const post = await BlogPost.findByIdAndDelete(postId);
      
      if (!post) {
        return res.status(404).json({
          error: 'Post no encontrado',
          message: 'No existe un post con el ID proporcionado'
        });
      }
      
      console.log(`Admin ${req.user.email} eliminó post: ${post.title}`);
      
      res.json({
        message: 'Post eliminado exitosamente',
        deletedPost: {
          id: post._id,
          title: post.title
        }
      });
      
    } catch (error) {
      console.error('Error eliminando post:', error);
      res.status(500).json({
        error: 'Error interno del servidor',
        message: 'Error al eliminar el post'
      });
    }
  }
);

// GET /api/admin/logs - Ver logs de actividad (solo admin)
router.get('/logs', requireAdmin, logUserActivity('view_logs'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
    
    // Filtros opcionales
    const filters = {};
    if (req.query.action) filters.action = req.query.action;
    if (req.query.severity) filters.severity = req.query.severity;
    if (req.query.userId) filters.userId = req.query.userId;
    if (req.query.anomalies === 'true') filters.isAnomaly = true;
    
    // Rango de fechas
    if (req.query.startDate || req.query.endDate) {
      filters.createdAt = {};
      if (req.query.startDate) {
        filters.createdAt.$gte = new Date(req.query.startDate);
      }
      if (req.query.endDate) {
        filters.createdAt.$lte = new Date(req.query.endDate);
      }
    }
    
    const logs = await AuditLog.find(filters)
      .populate('userId', 'email role')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await AuditLog.countDocuments(filters);
    
    res.json({
      message: 'Logs de auditoría del sistema',
      logs: logs.map(log => ({
        _id: log._id,
        userEmail: log.userEmail,
        action: log.action,
        severity: log.severity,
        details: log.details,
        ipAddress: log.ipAddress,
        riskScore: log.riskScore,
        isAnomaly: log.isAnomaly,
        createdAt: log.createdAt,
        metadata: log.metadata
      })),
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
    
  } catch (error) {
    console.error('Error obteniendo logs:', error);
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al obtener logs'
    });
  }
});

// GET /api/admin/security-report - Generar reporte de seguridad (solo admin)
router.get('/security-report', requireAdmin, logUserActivity('view_security_report'), async (req, res) => {
  try {
    const timeframe = parseInt(req.query.hours) || 24;
    
    // Generar reporte automático
    const report = await AuditLog.generateSecurityReport(timeframe);
    
    // Estadísticas adicionales de usuarios
    const userStats = await User.aggregate([
      {
        $group: {
          _id: '$role',
          count: { $sum: 1 },
          active: {
            $sum: { $cond: ['$isActive', 1, 0] }
          },
          locked: {
            $sum: { $cond: [{ $ne: ['$lockUntil', null] }, 1, 0] }
          }
        }
      }
    ]);
    
    // IPs más activas
    const timeStart = new Date(Date.now() - timeframe * 60 * 60 * 1000);
    const topIPs = await AuditLog.aggregate([
      { $match: { createdAt: { $gte: timeStart } } },
      {
        $group: {
          _id: '$ipAddress',
          count: { $sum: 1 },
          users: { $addToSet: '$userEmail' },
          actions: { $addToSet: '$action' },
          maxRiskScore: { $max: '$riskScore' }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    // Amenazas recientes
    const recentThreats = await AuditLog.find({
      createdAt: { $gte: timeStart },
      $or: [
        { severity: { $in: ['high', 'critical'] } },
        { isAnomaly: true },
        { riskScore: { $gte: 70 } }
      ]
    })
    .sort({ createdAt: -1 })
    .limit(20)
    .populate('userId', 'email role');
    
    res.json({
      message: 'Reporte de seguridad generado',
      report: {
        ...report,
        userStatistics: userStats,
        topIPs: topIPs.map(ip => ({
          ipAddress: ip._id,
          requestCount: ip.count,
          uniqueUsers: ip.users.length,
          uniqueActions: ip.actions.length,
          maxRiskScore: ip.maxRiskScore || 0,
          riskLevel: ip.maxRiskScore >= 70 ? 'HIGH' : ip.maxRiskScore >= 40 ? 'MEDIUM' : 'LOW'
        })),
        recentThreats: recentThreats.map(threat => ({
          id: threat._id,
          userEmail: threat.userEmail,
          action: threat.action,
          severity: threat.severity,
          details: threat.details,
          ipAddress: threat.ipAddress,
          riskScore: threat.riskScore,
          isAnomaly: threat.isAnomaly,
          timestamp: threat.createdAt
        })),
        recommendations: this.generateSecurityRecommendations(report, recentThreats)
      }
    });
    
  } catch (error) {
    console.error('Error generando reporte de seguridad:', error);
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al generar reporte de seguridad'
    });
  }
});

// Función para generar recomendaciones de seguridad
function generateSecurityRecommendations(report, threats) {
  const recommendations = [];
  
  if (report.summary.criticalEvents > 10) {
    recommendations.push({
      priority: 'HIGH',
      category: 'Incident Response',
      message: 'Alto número de eventos críticos detectados. Considere implementar monitoreo en tiempo real.',
      action: 'Revisar logs críticos y establecer alertas automáticas'
    });
  }
  
  if (report.summary.anomalies > 5) {
    recommendations.push({
      priority: 'MEDIUM',
      category: 'Anomaly Detection',
      message: 'Múltiples anomalías detectadas. Revisar patrones de comportamiento.',
      action: 'Implementar machine learning para detección de anomalías'
    });
  }
  
  const honeypotEvents = threats.filter(t => t.action === 'honeypot_triggered');
  if (honeypotEvents.length > 0) {
    recommendations.push({
      priority: 'HIGH',
      category: 'Bot Detection',
      message: `${honeypotEvents.length} intentos de bots detectados via honeypot.`,
      action: 'Considerar implementar CAPTCHA o bloqueo de IPs'
    });
  }
  
  const failedLogins = report.actionBreakdown.find(a => a.action === 'failed_login');
  if (failedLogins && failedLogins.count > 20) {
    recommendations.push({
      priority: 'MEDIUM',
      category: 'Authentication',
      message: 'Alto número de intentos de login fallidos detectados.',
      action: 'Considerar implementar MFA o bloqueo temporal más agresivo'
    });
  }
  
  return recommendations;
}

module.exports = router;
