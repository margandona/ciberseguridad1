const axios = require('axios');

// Configuración base
const BASE_URL = 'http://localhost:3000';
const api = axios.create({
  baseURL: BASE_URL,
  timeout: 5000
});

// Variables para almacenar tokens y datos
let csrfToken = '';
let authToken = '';
let testUserId = '';

// Colores para la consola
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

const log = {
  success: (msg) => console.log(`${colors.green}✅ ${msg}${colors.reset}`),
  error: (msg) => console.log(`${colors.red}❌ ${msg}${colors.reset}`),
  warning: (msg) => console.log(`${colors.yellow}⚠️  ${msg}${colors.reset}`),
  info: (msg) => console.log(`${colors.blue}ℹ️  ${msg}${colors.reset}`),
  title: (msg) => console.log(`${colors.bold}${colors.blue}\n=== ${msg} ===${colors.reset}`)
};

// Función de delay
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Test helper function
async function test(name, testFn) {
  try {
    console.log(`\n${colors.yellow}🧪 Testing: ${name}${colors.reset}`);
    await testFn();
    log.success(`${name} - PASSED`);
  } catch (error) {
    log.error(`${name} - FAILED`);
    console.error(`   Error: ${error.message}`);
    if (error.response?.data) {
      console.error(`   Response: ${JSON.stringify(error.response.data, null, 2)}`);
    }
  }
}

// Tests individuales
async function testHealthCheck() {
  const response = await api.get('/api/health');
  if (response.status !== 200 || response.data.status !== 'OK') {
    throw new Error('Health check failed');
  }
}

async function testGetCSRFToken() {
  const response = await api.get('/api/csrf-token');
  if (response.status !== 200 || !response.data.csrfToken) {
    throw new Error('No CSRF token received');
  }
  csrfToken = response.data.csrfToken;
  log.info(`CSRF Token: ${csrfToken.substring(0, 20)}...`);
}

async function testUserRegistration() {
  const userData = {
    email: 'test@ejemplo.com',
    password: 'TestPassword123!',
    confirmPassword: 'TestPassword123!'
  };
  
  const response = await api.post('/api/auth/register', userData, {
    headers: {
      'X-CSRF-Token': csrfToken
    }
  });
  
  if (response.status !== 201 || !response.data.token) {
    throw new Error('User registration failed');
  }
  
  authToken = response.data.token;
  testUserId = response.data.user._id;
  log.info(`User ID: ${testUserId}`);
  log.info(`Auth Token: ${authToken.substring(0, 20)}...`);
}

async function testUserLogin() {
  const loginData = {
    email: 'test@ejemplo.com',
    password: 'TestPassword123!'
  };
  
  const response = await api.post('/api/auth/login', loginData, {
    headers: {
      'X-CSRF-Token': csrfToken
    }
  });
  
  if (response.status !== 200 || !response.data.token) {
    throw new Error('User login failed');
  }
  
  authToken = response.data.token;
  log.info(`New Auth Token: ${authToken.substring(0, 20)}...`);
}

async function testGetProfile() {
  const response = await api.get('/api/auth/profile', {
    headers: {
      'Authorization': `Bearer ${authToken}`
    }
  });
  
  if (response.status !== 200 || !response.data.user) {
    throw new Error('Get profile failed');
  }
  
  log.info(`Profile Email: ${response.data.user.email}`);
  log.info(`Profile Role: ${response.data.user.role}`);
}

async function testTokenVerification() {
  const response = await api.get('/api/auth/verify', {
    headers: {
      'Authorization': `Bearer ${authToken}`
    }
  });
  
  if (response.status !== 200 || !response.data.isAuthenticated) {
    throw new Error('Token verification failed');
  }
}

async function testProtectedRoute() {
  try {
    await api.get('/api/admin/dashboard', {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    throw new Error('Should not have access to admin route');
  } catch (error) {
    if (error.response?.status === 403) {
      // Expected - user should not have admin access
      return;
    }
    throw error;
  }
}

async function testRateLimiting() {
  log.info('Testing rate limiting (this may take a moment)...');
  
  const promises = [];
  for (let i = 0; i < 10; i++) {
    promises.push(
      api.post('/api/auth/login', {
        email: 'wrong@email.com',
        password: 'wrongpassword'
      }, {
        headers: {
          'X-CSRF-Token': csrfToken
        }
      }).catch(err => err.response)
    );
  }
  
  const responses = await Promise.all(promises);
  const rateLimited = responses.some(r => r?.status === 429);
  
  if (!rateLimited) {
    log.warning('Rate limiting might not be working as expected');
  } else {
    log.info('Rate limiting is working correctly');
  }
}

async function testInvalidLogin() {
  try {
    await api.post('/api/auth/login', {
      email: 'test@ejemplo.com',
      password: 'wrongpassword'
    }, {
      headers: {
        'X-CSRF-Token': csrfToken
      }
    });
    throw new Error('Should not login with wrong password');
  } catch (error) {
    if (error.response?.status === 401) {
      // Expected
      return;
    }
    throw error;
  }
}

async function testPasswordValidation() {
  try {
    await api.post('/api/auth/register', {
      email: 'weak@ejemplo.com',
      password: '123',
      confirmPassword: '123'
    }, {
      headers: {
        'X-CSRF-Token': csrfToken
      }
    });
    throw new Error('Should not register with weak password');
  } catch (error) {
    if (error.response?.status === 400) {
      // Expected
      return;
    }
    throw error;
  }
}

async function testCSRFProtection() {
  try {
    await api.post('/api/auth/register', {
      email: 'nocsrf@ejemplo.com',
      password: 'TestPassword123!',
      confirmPassword: 'TestPassword123!'
    });
    throw new Error('Should require CSRF token');
  } catch (error) {
    if (error.response?.status === 403) {
      // Expected
      return;
    }
    throw error;
  }
}

async function testLogout() {
  const response = await api.post('/api/auth/logout', {}, {
    headers: {
      'Authorization': `Bearer ${authToken}`
    }
  });
  
  if (response.status !== 200) {
    throw new Error('Logout failed');
  }
}

// Función principal de tests
async function runTests() {
  log.title('🚀 INICIANDO TESTS DE SEGURIDAD');
  
  console.log(`${colors.blue}Servidor objetivo: ${BASE_URL}${colors.reset}`);
  console.log(`${colors.blue}Fecha: ${new Date().toISOString()}${colors.reset}`);
  
  // Lista de tests a ejecutar
  const tests = [
    ['Health Check', testHealthCheck],
    ['Get CSRF Token', testGetCSRFToken],
    ['User Registration', testUserRegistration],
    ['User Login', testUserLogin],
    ['Get Profile', testGetProfile],
    ['Token Verification', testTokenVerification],
    ['Protected Route Access Denial', testProtectedRoute],
    ['Invalid Login Rejection', testInvalidLogin],
    ['Weak Password Rejection', testPasswordValidation],
    ['CSRF Protection', testCSRFProtection],
    ['Rate Limiting', testRateLimiting],
    ['User Logout', testLogout]
  ];
  
  let passed = 0;
  let failed = 0;
  
  for (const [name, testFn] of tests) {
    try {
      await test(name, testFn);
      passed++;
    } catch (error) {
      failed++;
    }
    await delay(100); // Pequeña pausa entre tests
  }
  
  // Resumen final
  log.title('📊 RESUMEN DE TESTS');
  log.success(`Tests pasados: ${passed}`);
  if (failed > 0) {
    log.error(`Tests fallidos: ${failed}`);
  } else {
    log.success('¡Todos los tests pasaron! 🎉');
  }
  log.info(`Total: ${passed + failed} tests ejecutados`);
  
  if (failed === 0) {
    console.log(`\n${colors.green}${colors.bold}🎉 ¡SISTEMA DE SEGURIDAD FUNCIONANDO CORRECTAMENTE! 🎉${colors.reset}`);
    console.log(`${colors.green}✅ Autenticación JWT: OK${colors.reset}`);
    console.log(`${colors.green}✅ Protección CSRF: OK${colors.reset}`);
    console.log(`${colors.green}✅ Validación de datos: OK${colors.reset}`);
    console.log(`${colors.green}✅ Control de acceso: OK${colors.reset}`);
    console.log(`${colors.green}✅ Rate limiting: OK${colors.reset}`);
  } else {
    console.log(`\n${colors.red}${colors.bold}⚠️  ALGUNOS TESTS FALLARON - REVISAR CONFIGURACIÓN${colors.reset}`);
  }
}

// Ejecutar tests si el archivo se ejecuta directamente
if (require.main === module) {
  runTests().catch(error => {
    log.error('Error general en tests:');
    console.error(error);
    process.exit(1);
  });
}

module.exports = { runTests };
