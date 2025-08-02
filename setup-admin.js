const mongoose = require('mongoose');
const User = require('./models/User');
require('dotenv').config();

// Función para crear un usuario administrador
async function createAdminUser() {
  try {
    // Conectar a la base de datos
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    console.log('✅ Conectado a MongoDB');
    
    // Datos del administrador
    const adminData = {
      email: 'admin@sistema.com',
      password: 'AdminSecure123!',
      role: 'admin'
    };
    
    // Verificar si ya existe un admin
    const existingAdmin = await User.findOne({ email: adminData.email });
    if (existingAdmin) {
      console.log('⚠️  El usuario administrador ya existe');
      console.log(`📧 Email: ${existingAdmin.email}`);
      console.log(`👤 Rol: ${existingAdmin.role}`);
      return;
    }
    
    // Crear el usuario administrador
    const admin = new User(adminData);
    await admin.save();
    
    console.log('🎉 Usuario administrador creado exitosamente');
    console.log(`📧 Email: ${admin.email}`);
    console.log(`👤 Rol: ${admin.role}`);
    console.log(`🆔 ID: ${admin._id}`);
    console.log('');
    console.log('🔐 Credenciales de acceso:');
    console.log(`Email: ${adminData.email}`);
    console.log(`Password: ${adminData.password}`);
    
  } catch (error) {
    console.error('❌ Error creando usuario administrador:', error.message);
    
    if (error.name === 'ValidationError') {
      console.error('Errores de validación:');
      Object.keys(error.errors).forEach(key => {
        console.error(`- ${key}: ${error.errors[key].message}`);
      });
    }
  } finally {
    // Cerrar conexión
    await mongoose.disconnect();
    console.log('🔌 Desconectado de MongoDB');
  }
}

// Función para listar todos los usuarios
async function listAllUsers() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    console.log('✅ Conectado a MongoDB');
    
    const users = await User.find({}).select('-password').sort({ createdAt: -1 });
    
    console.log(`\n📋 Total de usuarios: ${users.length}`);
    console.log('='.repeat(60));
    
    users.forEach((user, index) => {
      console.log(`${index + 1}. Email: ${user.email}`);
      console.log(`   Rol: ${user.role}`);
      console.log(`   Activo: ${user.isActive ? 'Sí' : 'No'}`);
      console.log(`   Creado: ${user.createdAt.toLocaleDateString()}`);
      console.log(`   ID: ${user._id}`);
      console.log('-'.repeat(40));
    });
    
  } catch (error) {
    console.error('❌ Error listando usuarios:', error.message);
  } finally {
    await mongoose.disconnect();
  }
}

// Función principal
async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  
  if (command === 'list') {
    await listAllUsers();
  } else if (command === 'create-admin' || !command) {
    await createAdminUser();
  } else {
    console.log('Comandos disponibles:');
    console.log('  node setup-admin.js create-admin  - Crear usuario administrador');
    console.log('  node setup-admin.js list          - Listar todos los usuarios');
  }
}

// Ejecutar si es llamado directamente
if (require.main === module) {
  main().catch(console.error);
}

module.exports = { createAdminUser, listAllUsers };
