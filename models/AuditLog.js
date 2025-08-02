const mongoose = require('mongoose');

// Esquema para auditoría y logs de seguridad
const auditLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  userEmail: {
    type: String,
    required: true
  },
  action: {
    type: String,
    required: true,
    enum: [
      'login', 'logout', 'register', 'failed_login',
      'password_change', 'role_change', 'user_created',
      'user_deleted', 'user_activated', 'user_deactivated',
      'post_created', 'post_updated', 'post_deleted',
      'admin_access', 'suspicious_activity', 'security_violation',
      'honeypot_triggered', 'rate_limit_exceeded', 'csrf_violation'
    ]
  },
  details: {
    type: String,
    maxlength: 1000
  },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: {
    type: String,
    required: true
  },
  metadata: {
    targetUserId: mongoose.Schema.Types.ObjectId,
    targetResource: String,
    httpMethod: String,
    endpoint: String,
    statusCode: Number,
    responseTime: Number,
    sessionId: String
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },
  isAnomaly: {
    type: Boolean,
    default: false
  },
  location: {
    country: String,
    city: String,
    coordinates: [Number] // [longitude, latitude]
  }
}, {
  timestamps: true
});

// Índices para optimizar consultas de auditoría
auditLogSchema.index({ userId: 1 });
auditLogSchema.index({ action: 1 });
auditLogSchema.index({ severity: 1 });
auditLogSchema.index({ createdAt: -1 });
auditLogSchema.index({ ipAddress: 1 });
auditLogSchema.index({ isAnomaly: 1 });
auditLogSchema.index({ riskScore: -1 });

// Índice TTL para eliminar logs antiguos automáticamente (opcional)
auditLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 365 * 24 * 60 * 60 }); // 1 año

// Método estático para crear log de auditoría
auditLogSchema.statics.createLog = async function(logData) {
  try {
    const log = new this(logData);
    await log.save();
    
    // Si es una actividad de alto riesgo, enviar alerta
    if (log.severity === 'high' || log.severity === 'critical') {
      console.warn(`🚨 ALERTA DE SEGURIDAD: ${log.action} - ${log.details}`);
      // Aquí se podría integrar con servicios de alertas (email, Slack, etc.)
    }
    
    return log;
  } catch (error) {
    console.error('Error creando log de auditoría:', error);
    throw error;
  }
};

// Método estático para detectar anomalías
auditLogSchema.statics.detectAnomalies = async function(userId, timeWindow = 60) {
  try {
    const windowStart = new Date(Date.now() - timeWindow * 60 * 1000);
    
    // Buscar patrones sospechosos
    const recentLogs = await this.find({
      userId,
      createdAt: { $gte: windowStart }
    }).sort({ createdAt: -1 });
    
    let anomalies = [];
    
    // Detectar múltiples intentos de login fallidos
    const failedLogins = recentLogs.filter(log => log.action === 'failed_login');
    if (failedLogins.length >= 3) {
      anomalies.push({
        type: 'multiple_failed_logins',
        count: failedLogins.length,
        severity: 'high'
      });
    }
    
    // Detectar accesos desde múltiples IPs
    const uniqueIPs = [...new Set(recentLogs.map(log => log.ipAddress))];
    if (uniqueIPs.length > 3) {
      anomalies.push({
        type: 'multiple_ip_access',
        count: uniqueIPs.length,
        severity: 'medium'
      });
    }
    
    // Detectar actividad fuera de horarios normales
    const currentHour = new Date().getHours();
    if (currentHour < 6 || currentHour > 23) {
      const nightActivity = recentLogs.filter(log => {
        const logHour = log.createdAt.getHours();
        return logHour < 6 || logHour > 23;
      });
      
      if (nightActivity.length > 0) {
        anomalies.push({
          type: 'unusual_time_access',
          count: nightActivity.length,
          severity: 'low'
        });
      }
    }
    
    return anomalies;
  } catch (error) {
    console.error('Error detectando anomalías:', error);
    return [];
  }
};

// Método estático para generar reporte de seguridad
auditLogSchema.statics.generateSecurityReport = async function(timeframe = 24) {
  try {
    const timeStart = new Date(Date.now() - timeframe * 60 * 60 * 1000);
    
    const report = await this.aggregate([
      { $match: { createdAt: { $gte: timeStart } } },
      {
        $group: {
          _id: '$action',
          count: { $sum: 1 },
          severityBreakdown: {
            $push: '$severity'
          },
          uniqueUsers: { $addToSet: '$userId' },
          uniqueIPs: { $addToSet: '$ipAddress' }
        }
      },
      {
        $project: {
          action: '$_id',
          count: 1,
          uniqueUserCount: { $size: '$uniqueUsers' },
          uniqueIPCount: { $size: '$uniqueIPs' },
          severityBreakdown: {
            $reduce: {
              input: '$severityBreakdown',
              initialValue: { low: 0, medium: 0, high: 0, critical: 0 },
              in: {
                low: { $cond: [{ $eq: ['$$this', 'low'] }, { $add: ['$$value.low', 1] }, '$$value.low'] },
                medium: { $cond: [{ $eq: ['$$this', 'medium'] }, { $add: ['$$value.medium', 1] }, '$$value.medium'] },
                high: { $cond: [{ $eq: ['$$this', 'high'] }, { $add: ['$$value.high', 1] }, '$$value.high'] },
                critical: { $cond: [{ $eq: ['$$this', 'critical'] }, { $add: ['$$value.critical', 1] }, '$$value.critical'] }
              }
            }
          }
        }
      },
      { $sort: { count: -1 } }
    ]);
    
    // Estadísticas adicionales
    const totalLogs = await this.countDocuments({ createdAt: { $gte: timeStart } });
    const criticalEvents = await this.countDocuments({ 
      createdAt: { $gte: timeStart },
      severity: { $in: ['high', 'critical'] }
    });
    const anomalies = await this.countDocuments({
      createdAt: { $gte: timeStart },
      isAnomaly: true
    });
    
    return {
      timeframe: `${timeframe} horas`,
      generatedAt: new Date().toISOString(),
      summary: {
        totalLogs,
        criticalEvents,
        anomalies,
        riskLevel: criticalEvents > 10 ? 'HIGH' : criticalEvents > 5 ? 'MEDIUM' : 'LOW'
      },
      actionBreakdown: report
    };
  } catch (error) {
    console.error('Error generando reporte de seguridad:', error);
    throw error;
  }
};

module.exports = mongoose.model('AuditLog', auditLogSchema);
