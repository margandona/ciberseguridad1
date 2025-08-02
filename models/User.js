const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Esquema del usuario con validaciones de seguridad
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'El email es requerido'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: function(email) {
        // Validación básica de email usando regex
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
      },
      message: 'Formato de email inválido'
    }
  },
  password: {
    type: String,
    required: [true, 'La contraseña es requerida'],
    minlength: [8, 'La contraseña debe tener al menos 8 caracteres'],
    validate: {
      validator: function(password) {
        // Validación de contraseña fuerte:
        // - Al menos 8 caracteres
        // - Al menos una mayúscula
        // - Al menos una minúscula
        // - Al menos un número
        // - Al menos un carácter especial
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(password);
      },
      message: 'La contraseña debe contener al menos una mayúscula, una minúscula, un número y un carácter especial'
    }
  },
  role: {
    type: String,
    enum: ['usuario', 'admin', 'moderador'],
    default: 'usuario'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  }
}, {
  timestamps: true // Agrega createdAt y updatedAt automáticamente
});

// Índices para optimizar consultas
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });

// Virtual para verificar si la cuenta está bloqueada
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Middleware pre-save para hashear la contraseña
userSchema.pre('save', async function(next) {
  // Solo hashear la contraseña si ha sido modificada (o es nueva)
  if (!this.isModified('password')) return next();
  
  try {
    // Generar salt con factor de costo 12 (recomendado para 2024)
    const salt = await bcrypt.genSalt(12);
    
    // Hashear la contraseña
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Método para comparar contraseñas
userSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw new Error('Error al comparar contraseñas');
  }
};

// Método para incrementar intentos de login fallidos
userSchema.methods.incLoginAttempts = function() {
  // Si tenemos un bloqueo anterior y ha expirado, resetear
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Si llegamos al máximo de intentos (5) y no estamos bloqueados, bloquear por 2 horas
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 horas
  }
  
  return this.updateOne(updates);
};

// Método para resetear intentos de login después de login exitoso
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 },
    $set: { lastLogin: new Date() }
  });
};

// Método para verificar permisos
userSchema.methods.hasPermission = function(requiredRole) {
  const roleHierarchy = {
    'usuario': 1,
    'moderador': 2,
    'admin': 3
  };
  
  const userLevel = roleHierarchy[this.role] || 0;
  const requiredLevel = roleHierarchy[requiredRole] || 0;
  
  return userLevel >= requiredLevel;
};

// Método para obtener información segura del usuario (sin contraseña)
userSchema.methods.toSafeObject = function() {
  const userObject = this.toObject();
  delete userObject.password;
  delete userObject.loginAttempts;
  delete userObject.lockUntil;
  return userObject;
};

// Eliminar la contraseña del JSON por defecto
userSchema.methods.toJSON = function() {
  return this.toSafeObject();
};

module.exports = mongoose.model('User', userSchema);
