const express = require('express');
const BlogPost = require('../models/BlogPost');
const { verifyToken } = require('../middleware/auth');

const router = express.Router();

// GET /api/blog/posts - Obtener posts públicos (no requiere autenticación)
router.get('/posts', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    // Solo mostrar posts publicados y visibles
    const posts = await BlogPost.find({ 
      status: 'published',
      isVisible: true 
    })
    .populate('author', 'email')
    .select('-metadata') // No incluir metadatos sensibles
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);
    
    const total = await BlogPost.countDocuments({ 
      status: 'published',
      isVisible: true 
    });
    
    res.json({
      message: 'Posts del blog',
      posts: posts.map(post => ({
        _id: post._id,
        title: post.title,
        content: post.content,
        excerpt: post.excerpt,
        author: post.author.email,
        createdAt: post.createdAt,
        viewCount: post.viewCount,
        tags: post.tags
      })),
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
    
  } catch (error) {
    console.error('Error obteniendo posts:', error);
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al obtener posts del blog'
    });
  }
});

// GET /api/blog/posts/:id - Obtener post específico y incrementar vista
router.get('/posts/:id', async (req, res) => {
  try {
    const postId = req.params.id;
    
    const post = await BlogPost.findOne({
      _id: postId,
      status: 'published',
      isVisible: true
    }).populate('author', 'email');
    
    if (!post) {
      return res.status(404).json({
        error: 'Post no encontrado',
        message: 'El post solicitado no existe o no está disponible'
      });
    }
    
    // Incrementar contador de vistas (sin await para no bloquear respuesta)
    post.incrementView().catch(err => 
      console.error('Error incrementando vista:', err)
    );
    
    res.json({
      message: 'Post obtenido exitosamente',
      post: {
        _id: post._id,
        title: post.title,
        content: post.content,
        author: post.author.email,
        createdAt: post.createdAt,
        updatedAt: post.updatedAt,
        viewCount: post.viewCount + 1, // Mostrar el contador actualizado
        tags: post.tags
      }
    });
    
  } catch (error) {
    console.error('Error obteniendo post:', error);
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al obtener el post'
    });
  }
});

// GET /api/blog/posts/search/:query - Buscar posts
router.get('/search/:query', async (req, res) => {
  try {
    const query = req.params.query;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    // Sanitizar query de búsqueda
    const sanitizedQuery = query.replace(/[<>]/g, '').trim();
    
    if (sanitizedQuery.length < 2) {
      return res.status(400).json({
        error: 'Query muy corto',
        message: 'La búsqueda debe tener al menos 2 caracteres'
      });
    }
    
    const posts = await BlogPost.find({
      status: 'published',
      isVisible: true,
      $or: [
        { title: { $regex: sanitizedQuery, $options: 'i' } },
        { content: { $regex: sanitizedQuery, $options: 'i' } },
        { tags: { $in: [new RegExp(sanitizedQuery, 'i')] } }
      ]
    })
    .populate('author', 'email')
    .select('-metadata')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);
    
    const total = await BlogPost.countDocuments({
      status: 'published',
      isVisible: true,
      $or: [
        { title: { $regex: sanitizedQuery, $options: 'i' } },
        { content: { $regex: sanitizedQuery, $options: 'i' } },
        { tags: { $in: [new RegExp(sanitizedQuery, 'i')] } }
      ]
    });
    
    res.json({
      message: `Resultados de búsqueda para: "${sanitizedQuery}"`,
      query: sanitizedQuery,
      posts: posts.map(post => ({
        _id: post._id,
        title: post.title,
        excerpt: post.excerpt,
        author: post.author.email,
        createdAt: post.createdAt,
        viewCount: post.viewCount,
        tags: post.tags
      })),
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
    
  } catch (error) {
    console.error('Error en búsqueda:', error);
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al realizar la búsqueda'
    });
  }
});

// GET /api/blog/stats - Estadísticas públicas del blog
router.get('/stats', async (req, res) => {
  try {
    const totalPosts = await BlogPost.countDocuments({
      status: 'published',
      isVisible: true
    });
    
    const totalViews = await BlogPost.aggregate([
      { $match: { status: 'published', isVisible: true } },
      { $group: { _id: null, totalViews: { $sum: '$viewCount' } } }
    ]);
    
    const recentPosts = await BlogPost.countDocuments({
      status: 'published',
      isVisible: true,
      createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
    });
    
    res.json({
      message: 'Estadísticas del blog',
      stats: {
        totalPosts,
        totalViews: totalViews[0]?.totalViews || 0,
        recentPosts,
        lastUpdated: new Date().toISOString()
      }
    });
    
  } catch (error) {
    console.error('Error obteniendo estadísticas:', error);
    res.status(500).json({
      error: 'Error interno del servidor',
      message: 'Error al obtener estadísticas'
    });
  }
});

module.exports = router;
