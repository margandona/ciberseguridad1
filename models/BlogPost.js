const mongoose = require('mongoose');

// Esquema para los posts del blog con seguridad integrada
const blogPostSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'El título es requerido'],
    maxlength: [200, 'El título no puede exceder 200 caracteres'],
    trim: true,
    validate: {
      validator: function(title) {
        // Prevenir títulos con contenido malicioso
        return !/[<>]/.test(title);
      },
      message: 'El título contiene caracteres no permitidos'
    }
  },
  content: {
    type: String,
    required: [true, 'El contenido es requerido'],
    maxlength: [10000, 'El contenido no puede exceder 10,000 caracteres'],
    validate: {
      validator: function(content) {
        // Prevenir contenido con scripts maliciosos
        return !/(<script|javascript:|on\w+\s*=)/gi.test(content);
      },
      message: 'El contenido contiene elementos no permitidos'
    }
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  authorEmail: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['draft', 'published', 'archived'],
    default: 'draft'
  },
  isVisible: {
    type: Boolean,
    default: true
  },
  tags: [{
    type: String,
    maxlength: 50
  }],
  viewCount: {
    type: Number,
    default: 0
  },
  metadata: {
    ipAddress: String,
    userAgent: String,
    createdFrom: String
  }
}, {
  timestamps: true
});

// Índices para optimizar consultas
blogPostSchema.index({ author: 1 });
blogPostSchema.index({ status: 1 });
blogPostSchema.index({ createdAt: -1 });
blogPostSchema.index({ title: 'text', content: 'text' });

// Middleware pre-save para sanitización adicional
blogPostSchema.pre('save', function(next) {
  // Sanitizar título y contenido
  this.title = this.title.replace(/[<>]/g, '');
  this.content = this.content.replace(/<script.*?>.*?<\/script>/gi, '');
  
  next();
});

// Método para obtener versión segura del post
blogPostSchema.methods.toSafeObject = function() {
  const postObject = this.toObject();
  delete postObject.metadata.ipAddress;
  return postObject;
};

// Método para incrementar conteo de vistas
blogPostSchema.methods.incrementView = function() {
  this.viewCount += 1;
  return this.save();
};

// Método virtual para excerpt
blogPostSchema.virtual('excerpt').get(function() {
  return this.content.length > 150 
    ? this.content.substring(0, 150) + '...' 
    : this.content;
});

// Incluir virtuals en JSON
blogPostSchema.set('toJSON', { virtuals: true });

module.exports = mongoose.model('BlogPost', blogPostSchema);
