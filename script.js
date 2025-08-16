// ============================================
// LISIUM CORP -  SECURE VERSION 3.0
// ============================================

// Import Firebase modules
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.7.0/firebase-app.js";
import { 
    getAuth, 
    createUserWithEmailAndPassword, 
    signInWithEmailAndPassword,
    signOut,
    onAuthStateChanged,
    sendEmailVerification,
    updateProfile,
    deleteUser,
    reauthenticateWithCredential,
    EmailAuthProvider,
    updatePassword
} from "https://www.gstatic.com/firebasejs/10.7.0/firebase-auth.js";
import { 
    getFirestore, 
    doc, 
    setDoc, 
    getDoc,
    updateDoc,
    deleteDoc,
    serverTimestamp,
    enableNetwork,
    disableNetwork
} from "https://www.gstatic.com/firebasejs/10.7.0/firebase-firestore.js";
import { 
    initializeAppCheck, 
    ReCaptchaV3Provider 
} from "https://www.gstatic.com/firebasejs/10.7.0/firebase-app-check.js";

// CONFIGURACIÓN SEGURA CON VARIABLES DE ENTORNO
const firebaseConfig = {
    apiKey: import.meta.env?.VITE_FIREBASE_API_KEY || window.ENV?.FIREBASE_API_KEY || "AIzaSyB4TDikVw6mM0QtwTyCszZIoNtyr72E4Nk",
    authDomain: import.meta.env?.VITE_FIREBASE_AUTH_DOMAIN || window.ENV?.FIREBASE_AUTH_DOMAIN || "lisium-corp.firebaseapp.com",
    projectId: import.meta.env?.VITE_FIREBASE_PROJECT_ID || window.ENV?.FIREBASE_PROJECT_ID || "lisium-corp",
    storageBucket: import.meta.env?.VITE_FIREBASE_STORAGE_BUCKET || window.ENV?.FIREBASE_STORAGE_BUCKET || "lisium-corp.firebasestorage.app",
    messagingSenderId: import.meta.env?.VITE_FIREBASE_MESSAGING_SENDER_ID || window.ENV?.FIREBASE_MESSAGING_SENDER_ID || "1086369040682",
    appId: import.meta.env?.VITE_FIREBASE_APP_ID || window.ENV?.FIREBASE_APP_ID || "1:1086369040682:web:c5c6b081f96c9e9582b653"
};

// Inicializar Firebase
const app = initializeApp(firebaseConfig);

// CONFIGURAR APP CHECK CON EL RECAPTCHA 
let appCheckInitialized = false;
const recaptchaKey = import.meta.env?.VITE_RECAPTCHA_SITE_KEY || window.ENV?.RECAPTCHA_SITE_KEY || '6LchpKcrAAAAAIGQzn5lByfy2PcL3uXO7fUfykoa';

try {
    const appCheck = initializeAppCheck(app, {
        provider: new ReCaptchaV3Provider(recaptchaKey),
        isTokenAutoRefreshEnabled: true
    });
    appCheckInitialized = true;
    console.log('✅ App Check configurado - Protección máxima activa');
} catch (error) {
    console.warn('⚠️ App Check no disponible:', error.message);
    if (!isDevelopment()) {
        mostrarNotificacion('Error Crítico', 'Verificación de seguridad requerida. Contacta soporte.', 'error');
    }
}

const auth = getAuth(app);
const db = getFirestore(app);

//VARIABLES DE SEGURIDAD 
let ultimoIntento = 0;
let intentosFallidos = 0;
let intentosLogin = new Map();
let sesionExpirada = false;
const TIEMPO_COOLDOWN = 3000; // 3 segundos
const MAX_INTENTOS_FALLIDOS = 5;
const TIEMPO_SESION_MAX = 3600000; // 1 hora
const INTENTOS_MAXIMOS_POR_HORA = 15;

// DETECCIÓN DE ATAQUES AVANZADOS
const patronesAtaque = {
    sqlInjection: /(\b(union|select|insert|delete|drop|create|alter|exec|script)\b)|['"`;()]/gi,
    xss: /<[^>]*script|javascript:|on\w+\s*=/gi,
    pathTraversal: /\.\.[\/\\]/g,
    comandos: /(\b(rm|del|format|shutdown|passwd|sudo|chmod)\b)/gi,
    encoding: /(%3C|%3E|%22|%27|%3B|%28|%29)/gi
};

// ============================================
// UTILIDADES DE SEGURIDAD
// ============================================

function isDevelopment() {
    return window.location.hostname === 'localhost' || 
           window.location.hostname === '127.0.0.1' || 
           window.location.hostname.includes('localhost');
}

function detectarAtaque(input) {
    if (typeof input !== 'string') return false;
    
    for (let [tipo, patron] of Object.entries(patronesAtaque)) {
        if (patron.test(input)) {
            console.warn(`🚨 Intento de ${tipo} detectado:`, input.substring(0, 50));
            registrarIntentoMalicioso(tipo, input);
            return true;
        }
    }
    return false;
}

function registrarIntentoMalicioso(tipo, input) {
    const incidente = {
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        input: input.substring(0, 100),
        url: window.location.href,
        tipo: tipo,
        ip: 'client-side' // En producción usar server-side logging
    };
    
    console.error(`🚨 ATAQUE DETECTADO - ${tipo}:`, incidente);
    
    // Enviar a servicio de logging (implementar según necesidades)
    if (!isDevelopment()) {
        try {
            // Aquí se podría enviar a un servicio de logging, para prevenir 
            // fetch('/api/security-log', { method: 'POST', body: JSON.stringify(incidente) });
        } catch (e) {
            console.warn('Error enviando log de seguridad:', e);
        }
    }
    
    intentosFallidos += 5;
    mostrarNotificacion('Actividad Sospechosa', 'Se detectó actividad maliciosa. Acceso restringido.', 'error');
}

function sanitizarInput(input) {
    if (typeof input !== 'string') return '';
    
    if (detectarAtaque(input)) {
        return '';
    }
    
    return input
        .replace(/[<>'"]/g, '')
        .trim()
        .substring(0, 500);
}

function verificarRateLimit(accion = 'general') {
    const ahora = Date.now();
    
    if (sesionExpirada) {
        logout();
        return false;
    }
    
    if (!intentosLogin.has(accion)) {
        intentosLogin.set(accion, []);
    }
    
    const intentosAccion = intentosLogin.get(accion);
    const unaHoraAtras = ahora - 3600000;
    
    const intentosRecientes = intentosAccion.filter(tiempo => tiempo > unaHoraAtras);
    intentosLogin.set(accion, intentosRecientes);
    
    if (intentosRecientes.length >= INTENTOS_MAXIMOS_POR_HORA) {
        mostrarNotificacion('Límite Excedido', `Demasiados intentos de ${accion}. Intenta en 1 hora.`, 'warning');
        return false;
    }
    
    const tiempoCooldown = TIEMPO_COOLDOWN * Math.pow(1.5, Math.min(intentosFallidos, 8));
    
    if (intentosFallidos >= MAX_INTENTOS_FALLIDOS) {
        const tiempoRestante = Math.ceil((ultimoIntento + tiempoCooldown - ahora) / 1000);
        if (tiempoRestante > 0) {
            mostrarNotificacion('Acceso Bloqueado', `Espera ${tiempoRestante}s antes de intentar nuevamente`, 'warning');
            return false;
        } else {
            intentosFallidos = Math.floor(intentosFallidos * 0.7);
        }
    }
    
    if (ahora - ultimoIntento < TIEMPO_COOLDOWN) {
        mostrarNotificacion('Espera', 'Acción muy rápida, espera un momento', 'warning');
        return false;
    }
    
    ultimoIntento = ahora;
    intentosRecientes.push(ahora);
    intentosLogin.set(accion, intentosRecientes);
    
    return true;
}

// ============================================
// VARIABLES GLOBALES
// ============================================
let usuario = null;
let editando = false;
let seccionActual = 'overview';
let timerSesion = null;
let timerInactividad = null;

// ============================================
// GESTIONAMIENTO DE SESIÓN
// ============================================

function iniciarTemporizadorSesion() {
    if (timerSesion) clearTimeout(timerSesion);
    if (timerInactividad) clearTimeout(timerInactividad);
    
    // Timer principal de sesión
    timerSesion = setTimeout(() => {
        mostrarNotificacion('Sesión Expirada', 'Tu sesión ha expirado por seguridad.', 'warning');
        logout();
    }, TIEMPO_SESION_MAX);
    
    // Timer de inactividad (30 minutos)
    timerInactividad = setTimeout(() => {
        if (usuario) {
            mostrarNotificacion('Inactividad Detectada', 'Sesión cerrada por inactividad.', 'warning');
            logout();
        }
    }, 1800000); // 30 minutos
}

function reiniciarTimerInactividad() {
    if (timerInactividad && usuario) {
        clearTimeout(timerInactividad);
        timerInactividad = setTimeout(() => {
            mostrarNotificacion('Inactividad Detectada', 'Sesión cerrada por inactividad.', 'warning');
            logout();
        }, 1800000);
    }
}

// Detectar actividad del usuario
['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click'].forEach(event => {
    document.addEventListener(event, reiniciarTimerInactividad, { passive: true });
});

// ============================================
//AUTENTICACIÓN
// ============================================

onAuthStateChanged(auth, async (user) => {
    if (user) {
        if (user.emailVerified) {
            await cargarDatosUsuario(user);
            actualizarInterfaz();
            iniciarTemporizadorSesion();
            console.log('✅ Usuario autenticado:', user.email);
        } else {
            console.log('⚠️ Usuario no verificado:', user.email);
            mostrarNotificacion('Verificación Requerida', 'Debes verificar tu email para acceder completamente', 'warning');
        }
    } else {
        usuario = null;
        sesionExpirada = false;
        if (timerSesion) clearTimeout(timerSesion);
        if (timerInactividad) clearTimeout(timerInactividad);
        actualizarInterfaz();
    }
});

async function cargarDatosUsuario(user) {
    try {
        const docRef = doc(db, 'users', user.uid);
        const docSnap = await getDoc(docRef);
        
        if (docSnap.exists()) {
            const userData = docSnap.data();
            
            usuario = {
                uid: user.uid,
                username: sanitizarInput(userData.username || ''),
                email: user.email,
                birthDate: sanitizarInput(userData.birthDate || ''),
                registrationDate: userData.registrationDate,
                profilePhoto: userData.profilePhoto || null,
                emailVerified: user.emailVerified,
                lastLogin: new Date().toISOString()
            };
            
            try {
                await updateDoc(docRef, {
                    lastLogin: serverTimestamp()
                });
            } catch (error) {
                console.warn('Error actualizando último login:', error);
            }
        }
    } catch (error) {
        console.error('❌ Error cargando datos:', error);
        manejarErrorFirebase(error, 'Error cargando datos del usuario');
    }
}

function manejarErrorFirebase(error, contexto) {
    console.error(`❌ ${contexto}:`, error);
    
    const errores = {
        'app-check/token-error': 'Error de verificación de seguridad. Recarga la página.',
        'auth/email-already-in-use': 'Este email ya está registrado',
        'auth/weak-password': 'Contraseña muy débil (min 10 caracteres)',
        'auth/user-not-found': 'No existe una cuenta con este email',
        'auth/wrong-password': 'Contraseña incorrecta',
        'auth/invalid-email': 'Formato de email inválido',
        'auth/network-request-failed': 'Sin conexión a internet',
        'auth/too-many-requests': 'Demasiados intentos. Intenta más tarde.',
        'permission-denied': 'Acceso denegado. Verifica tu cuenta.',
        'quota-exceeded': 'Límite de uso excedido. Intenta más tarde.',
        'auth/requires-recent-login': 'Acción sensible. Inicia sesión nuevamente.',
        'auth/user-token-expired': 'Sesión expirada. Inicia sesión nuevamente.'
    };
    
    const mensaje = errores[error.code] || 'Error interno. Si persiste, contacta soporte.';
    mostrarNotificacion('Error', mensaje, 'error');
    
    if (['app-check/token-error', 'quota-exceeded', 'permission-denied'].includes(error.code)) {
        registrarIntentoFallido();
    }
    
    if (['auth/user-token-expired', 'auth/requires-recent-login'].includes(error.code)) {
        sesionExpirada = true;
        setTimeout(logout, 2000);
    }
}

// ============================================
// REGISTRO
// ============================================

async function manejarRegistro(e) {
    e.preventDefault();
    limpiarErrores();

    if (!verificarRateLimit('registro')) return;

    const inputs = {
        nombreUsuario: sanitizarInput(document.getElementById('username').value),
        email: sanitizarInput(document.getElementById('registerEmail').value),
        password: document.getElementById('registerPassword').value,
        confirmPassword: document.getElementById('confirmPassword').value,
        dia: parseInt(document.getElementById('birthDay').value),
        mes: parseInt(document.getElementById('birthMonth').value),
        año: parseInt(document.getElementById('birthYear').value)
    };

    if (detectarAtaque(inputs.nombreUsuario) || detectarAtaque(inputs.email)) {
        return;
    }

    if (!validarRegistroCompleto(inputs.nombreUsuario, inputs.email, inputs.password, inputs.confirmPassword, inputs.dia, inputs.mes, inputs.año)) {
        registrarIntentoFallido();
        return;
    }

    try {
        const userCredential = await createUserWithEmailAndPassword(auth, inputs.email, inputs.password);
        const user = userCredential.user;
        
        await updateProfile(user, {
            displayName: inputs.nombreUsuario
        });
        
        await sendEmailVerification(user);
        
        const datosUsuario = {
            username: inputs.nombreUsuario,
            birthDate: `${inputs.dia}/${inputs.mes}/${inputs.año}`,
            registrationDate: serverTimestamp(),
            profilePhoto: null,
            accountStatus: 'active',
            securityLevel: 'standard'
        };
        
        await setDoc(doc(db, 'users', user.uid), datosUsuario);
        
        limpiarIntentosFallidos();
        mostrarExito('registerSuccess', '✅ Cuenta creada. Verifica tu email para continuar.');
        
        setTimeout(() => {
            cerrarModal('registerModal');
            mostrarNotificacion('Registro Exitoso', `¡Bienvenido ${inputs.nombreUsuario}! Revisa tu email.`, 'success');
        }, 2000);
        
    } catch (error) {
        registrarIntentoFallido();
        manejarErrorFirebase(error, 'Error en el registro');
        const mensajeError = error.code === 'auth/email-already-in-use' ? 
            'Este email ya está registrado' : 'Error al crear la cuenta';
        mostrarError('registerError', mensajeError);
    }
}

// ============================================
// LOGIN
// ============================================

async function manejarLogin(e) {
    e.preventDefault();
    limpiarErrores();

    if (!verificarRateLimit('login')) return;

    const email = sanitizarInput(document.getElementById('loginUsername').value);
    const password = document.getElementById('loginPassword').value;

    if (!email || !password) {
        mostrarError('loginError', 'Completa todos los campos');
        registrarIntentoFallido();
        return;
    }

    if (detectarAtaque(email)) return;

    try {
        await signInWithEmailAndPassword(auth, email, password);
        
        limpiarIntentosFallidos();
        mostrarExito('loginSuccess', '✅ Ingresando de forma segura...');
        
        setTimeout(() => {
            cerrarModal('loginModal');
        }, 800);
        
    } catch (error) {
        registrarIntentoFallido();
        manejarErrorFirebase(error, 'Error en el login');
        
        const mensajeError = ['auth/user-not-found', 'auth/wrong-password'].includes(error.code) ?
            'Email o contraseña incorrectos' : 'Error al iniciar sesión';
        mostrarError('loginError', mensajeError);
    }
}

// ============================================
// ELIMINAR CUENTA
// ============================================

async function eliminarCuenta() {
    if (!usuario || !usuario.emailVerified) {
        mostrarNotificacion('Error', 'Debes estar autenticado y verificado', 'error');
        return;
    }

    if (!verificarRateLimit('eliminar-cuenta')) return;

    mostrarConfirmacionEliminarCuenta();
}

function mostrarConfirmacionEliminarCuenta() {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.style.display = 'block';
    modal.innerHTML = `
        <div class="modal-content" style="max-width: 500px;">
            <h2 style="color: #ff4444; text-align: center;">⚠️ Eliminar Cuenta</h2>
            <div style="margin: 2rem 0; text-align: center;">
                <p style="color: #ff4444; font-weight: bold;">Esta acción NO se puede deshacer</p>
                <p style="margin: 1rem 0;">Se eliminarán permanentemente:</p>
                <ul style="text-align: left; margin: 1rem 0;">
                    <li>❌ Todos tus datos personales</li>
                    <li>❌ Tu perfil y configuraciones</li>
                    <li>❌ Historial de servicios</li>
                    <li>❌ Acceso a la plataforma</li>
                </ul>
                <p style="margin: 1.5rem 0;"><strong>Para confirmar, ingresa tu contraseña:</strong></p>
                <input type="password" id="deletePassword" placeholder="Tu contraseña actual" 
                       style="width: 100%; padding: 0.8rem; margin: 0.5rem 0; 
                              background: rgba(255,255,255,0.1); border: 2px solid #ff4444; 
                              border-radius: 10px; color: white;">
                <div id="deleteError" class="error-message" style="margin: 0.5rem 0;"></div>
            </div>
            <div style="display: flex; gap: 1rem; justify-content: center;">
                <button onclick="this.closest('.modal').remove()" 
                        style="padding: 0.8rem 1.5rem; background: #666; color: white; 
                               border: none; border-radius: 25px; cursor: pointer;">
                    Cancelar
                </button>
                <button onclick="confirmarEliminarCuenta()" 
                        style="padding: 0.8rem 1.5rem; background: #ff4444; color: white; 
                               border: none; border-radius: 25px; cursor: pointer; font-weight: bold;">
                    SÍ, ELIMINAR MI CUENTA
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    document.getElementById('deletePassword').focus();
    
    window.confirmarEliminarCuenta = async function() {
        const password = document.getElementById('deletePassword').value;
        
        if (!password) {
            mostrarError('deleteError', 'Ingresa tu contraseña para confirmar');
            return;
        }

        try {
            const credential = EmailAuthProvider.credential(usuario.email, password);
            await reauthenticateWithCredential(auth.currentUser, credential);
            
            await deleteDoc(doc(db, 'users', usuario.uid));
            await deleteUser(auth.currentUser);
            
            modal.remove();
            delete window.confirmarEliminarCuenta;
            
            mostrarNotificacion('Cuenta Eliminada', 'Tu cuenta ha sido eliminada permanentemente.', 'success');
            
            usuario = null;
            actualizarInterfaz();
            mostrarSeccion('main');
            
        } catch (error) {
            console.error('Error eliminando cuenta:', error);
            
            if (error.code === 'auth/wrong-password') {
                mostrarError('deleteError', 'Contraseña incorrecta');
            } else if (error.code === 'auth/requires-recent-login') {
                mostrarError('deleteError', 'Inicia sesión nuevamente y vuelve a intentar');
                setTimeout(() => {
                    modal.remove();
                    logout();
                }, 2000);
            } else {
                mostrarError('deleteError', 'Error al eliminar cuenta. Contacta soporte.');
            }
        }
    };
}

// ============================================
// FUNCIONES DE LA INTERFAZ
// ============================================

function toggleMenu() {
    const menu = document.getElementById('sideMenu');
    const overlay = document.getElementById('menuOverlay');
    const boton = document.getElementById('menuToggle');
    
    if (!menu || !overlay || !boton) return;
    
    const isActive = menu.classList.contains('active');
    
    if (isActive) {
        cerrarMenu();
    } else {
        menu.classList.add('active');
        overlay.classList.add('active');
        boton.classList.add('active');
        document.body.style.overflow = 'hidden';
        
        setTimeout(() => {
            document.addEventListener('click', cerrarMenuClick, { once: true });
        }, 100);
    }
}

function cerrarMenu() {
    const menu = document.getElementById('sideMenu');
    const overlay = document.getElementById('menuOverlay');
    const boton = document.getElementById('menuToggle');
    
    if (menu && overlay && boton) {
        menu.classList.remove('active');
        overlay.classList.remove('active');
        boton.classList.remove('active');
        document.body.style.overflow = 'auto';
        document.removeEventListener('click', cerrarMenuClick);
    }
}

function cerrarMenuClick(event) {
    const menu = document.getElementById('sideMenu');
    const menuToggle = document.getElementById('menuToggle');
    
    if (!menu.contains(event.target) && !menuToggle.contains(event.target)) {
        cerrarMenu();
    }
}

function irInicio() {
    mostrarSeccion('main');
    actualizarNavegacion('inicio');
    setTimeout(() => {
        document.getElementById('inicio')?.scrollIntoView({ behavior: 'smooth' });
    }, 100);
    cerrarMenu();
}

function irASeccion(seccionId) {
    mostrarSeccion('main');
    actualizarNavegacion(seccionId);
    setTimeout(() => {
        const seccion = document.getElementById(seccionId);
        if (seccion) {
            seccion.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }, 100);
    cerrarMenu();
}

function actualizarNavegacion(seccionActiva) {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        const texto = link.textContent.toLowerCase();
        if (texto.includes(seccionActiva) || 
            (seccionActiva === 'inicio' && texto.includes('inicio')) ||
            (seccionActiva === 'servicios' && texto.includes('servicios')) ||
            (seccionActiva === 'productos' && texto.includes('productos')) ||
            (seccionActiva === 'contacto' && texto.includes('contacto'))) {
            link.classList.add('active');
        }
    });
}

function mostrarNotificacion(titulo, mensaje, tipo = 'info') {
    titulo = sanitizarInput(titulo);
    mensaje = sanitizarInput(mensaje);
    
    document.querySelectorAll('.notificacion-custom').forEach(n => n.remove());

    const notificacion = document.createElement('div');
    notificacion.className = 'notificacion-custom';
    
    const iconos = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    const icono = iconos[tipo] || iconos.info;
    
    notificacion.innerHTML = `
        <div class="icono-notificacion">${icono}</div>
        <div class="titulo-notificacion">${titulo}</div>
        <div class="mensaje-notificacion">${mensaje}</div>
        <button class="btn-notificacion" onclick="this.parentElement.remove()">OK</button>
    `;
    
    document.body.appendChild(notificacion);
    
    setTimeout(() => {
        if (notificacion.parentElement) {
            notificacion.remove();
        }
    }, 5000);
}

function abrirModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'block';
        modal.setAttribute('aria-hidden', 'false');
        limpiarErrores();
        cerrarMenu();
    }
}

function cerrarModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
        modal.setAttribute('aria-hidden', 'true');
        limpiarErrores();
        
        const forms = {
            'registerModal': 'registerForm',
            'loginModal': 'loginForm'
        };
        
        const formId = forms[modalId];
        if (formId) {
            const form = document.getElementById(formId);
            if (form) form.reset();
        }
    }
}

function mostrarSeccion(seccion) {
    const dashboard = document.getElementById('dashboard');
    const contenidoPrincipal = document.getElementById('mainContent');
    
    if (seccion === 'dashboard' && usuario) {
        dashboard.classList.add('active');
        dashboard.setAttribute('aria-hidden', 'false');
        contenidoPrincipal.classList.add('hidden');
        actualizarDashboard();
        cerrarMenu();
    } else {
        dashboard.classList.remove('active');
        dashboard.setAttribute('aria-hidden', 'true');
        contenidoPrincipal.classList.remove('hidden');
    }
}

function mostrarDashboard() {
    if (!usuario) {
        mostrarNotificacion('Acceso Denegado', 'Debes iniciar sesión primero', 'warning');
        abrirModal('loginModal');
        return;
    }
    
    if (!usuario.emailVerified) {
        mostrarNotificacion('Verificación Requerida', 'Verifica tu email para acceder al dashboard', 'warning');
        return;
    }
    
    mostrarSeccion('dashboard');
    mostrarSeccionDashboard(seccionActual);
}

function mostrarSeccionDashboard(seccion) {
    document.querySelectorAll('.dashboard-section').forEach(sec => {
        sec.classList.remove('active');
    });
    
    const seccionTarget = document.getElementById(`dashboard${seccion.charAt(0).toUpperCase() + seccion.slice(1)}`);
    if (seccionTarget) {
        seccionTarget.classList.add('active');
    }
    
    document.querySelectorAll('.dashboard-nav-link').forEach(link => {
        link.classList.remove('active');
        link.setAttribute('aria-selected', 'false');
    });
    
    const linkActivo = document.querySelector(`[data-section="${seccion}"]`);
    if (linkActivo) {
        linkActivo.classList.add('active');
        linkActivo.setAttribute('aria-selected', 'true');
    }
    
    seccionActual = seccion;
    cerrarMenu();
}

function editarPerfil() {
    mostrarDashboard();
    mostrarSeccionDashboard('profile');
}

function configuracion() {
    mostrarNotificacion('Configuración', 'Esta función estará disponible pronto.', 'info');
    cerrarMenu();
}

function toggleUserDropdown() {
    const dropdown = document.getElementById('userDropdown');
    if (dropdown) {
        dropdown.classList.toggle('active');
    }
}

function actualizarInterfaz() {
    const elementos = {
        authButtons: document.getElementById('authButtons'),
        userMenu: document.getElementById('userMenu'),
        authButtonsMenu: document.getElementById('authButtonsMenu'),
        userMenuLateral: document.getElementById('userMenuLateral'),
        usernameMenu: document.getElementById('usernameMenu')
    };

    if (usuario && usuario.emailVerified) {
        if (elementos.authButtons) elementos.authButtons.style.display = 'none';
        if (elementos.userMenu) elementos.userMenu.classList.add('active');
        if (elementos.authButtonsMenu) elementos.authButtonsMenu.style.display = 'none';
        if (elementos.userMenuLateral) elementos.userMenuLateral.classList.add('active');
        if (elementos.usernameMenu) elementos.usernameMenu.textContent = usuario.username;
        
        actualizarAvatares();
    } else {
        if (elementos.authButtons) elementos.authButtons.style.display = 'flex';
        if (elementos.userMenu) elementos.userMenu.classList.remove('active');
        if (elementos.authButtonsMenu) elementos.authButtonsMenu.style.display = 'flex';
        if (elementos.userMenuLateral) elementos.userMenuLateral.classList.remove('active');
    }
}

function actualizarAvatares() {
    const avatares = ['userAvatar', 'userAvatarMenu', 'profileAvatar'];
    const iniciales = ['userInitials', 'userInitialsMenu', 'profileInitials'];
    
    if (usuario.profilePhoto) {
        avatares.forEach(id => {
            const avatar = document.getElementById(id);
            if (avatar) {
                avatar.innerHTML = `<img src="${usuario.profilePhoto}" alt="Foto de perfil">`;
            }
        });
    } else {
        const inicial = usuario.username.charAt(0).toUpperCase();
        iniciales.forEach(id => {
            const element = document.getElementById(id);
            if (element) element.textContent = inicial;
        });
    }
}

function actualizarDashboard() {
    if (!usuario) return;
    
    const elementos = {
        dashboardUsername: document.getElementById('dashboardUsername'),
        editUsername: document.getElementById('editUsername'),
        editEmail: document.getElementById('editEmail'),
        editBirthDate: document.getElementById('editBirthDate'),
        editRegDate: document.getElementById('editRegDate')
    };
    
    if (elementos.dashboardUsername) elementos.dashboardUsername.textContent = usuario.username;
    if (elementos.editUsername) elementos.editUsername.value = usuario.username;
    if (elementos.editEmail) elementos.editEmail.value = usuario.email;
    if (elementos.editBirthDate) elementos.editBirthDate.value = usuario.birthDate;
    if (elementos.editRegDate) elementos.editRegDate.value = usuario.registrationDate ? 
        new Date(usuario.registrationDate.toDate()).toLocaleDateString('es-ES') : 'No disponible';
    
    actualizarAvatares();
}

// ============================================
// GESTIÓN DE LA FOTO DE PERFIL
// ============================================

function subirFoto() {
    if (!usuario || !usuario.emailVerified) {
        mostrarNotificacion('Acceso Denegado', 'Verifica tu cuenta primero', 'warning');
        return;
    }
    
    if (!verificarRateLimit('subir-foto')) return;
    
    document.getElementById('photoInput').click();
}

async function manejarFoto(event) {
    const archivo = event.target.files[0];
    if (!archivo) return;

    const tiposPermitidos = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    
    if (!tiposPermitidos.includes(archivo.type)) {
        mostrarNotificacion('Error', 'Solo se permiten imágenes JPG, PNG, GIF o WebP', 'error');
        event.target.value = '';
        return;
    }
    
    if (archivo.size > 1.5 * 1024 * 1024) {
        mostrarNotificacion('Error', 'La imagen es muy grande (máximo 1.5MB)', 'error');
        event.target.value = '';
        return;
    }
    
    if (!usuario || !usuario.emailVerified) {
        mostrarNotificacion('Error', 'Debes estar autenticado y verificado', 'error');
        event.target.value = '';
        return;
    }
    
    try {
        const reader = new FileReader();
        reader.onload = async function(e) {
            const imagenData = e.target.result;
            
            if (imagenData.length > 2 * 1024 * 1024) {
                mostrarNotificacion('Error', 'Imagen muy compleja, usa una más simple', 'error');
                return;
            }
            
            if (!imagenData.startsWith('data:image/')) {
                mostrarNotificacion('Error', 'Formato de imagen no válido', 'error');
                return;
            }
            
            actualizarAvatares();
            
            try {
                const docRef = doc(db, 'users', usuario.uid);
                await updateDoc(docRef, {
                    profilePhoto: imagenData,
                    photoUpdated: serverTimestamp()
                });
                
                usuario.profilePhoto = imagenData;
                mostrarNotificacion('Éxito', 'Foto actualizada correctamente', 'success');
                event.target.value = '';
                
            } catch (error) {
                console.error('Error actualizando foto:', error);
                manejarErrorFirebase(error, 'Error al actualizar foto');
                event.target.value = '';
            }
        };
        
        reader.onerror = function() {
            mostrarNotificacion('Error', 'Error al leer el archivo', 'error');
            event.target.value = '';
        };
        
        reader.readAsDataURL(archivo);
    } catch (error) {
        console.error('Error procesando foto:', error);
        mostrarNotificacion('Error', 'Error al procesar la imagen', 'error');
        event.target.value = '';
    }
}

// ============================================
// MODO EDICIÓN
// ============================================

async function toggleEditMode() {
    if (!usuario || !usuario.emailVerified) {
        mostrarNotificacion('Acceso Denegado', 'Verifica tu cuenta primero', 'warning');
        return;
    }

    if (!verificarRateLimit('editar-perfil')) return;

    const emailInput = document.getElementById('editEmail');
    const btn = document.getElementById('editProfileBtn');
    
    if (!editando) {
        emailInput.disabled = false;
        emailInput.style.background = 'rgba(0, 212, 255, 0.1)';
        btn.textContent = 'Guardar';
        btn.style.background = 'linear-gradient(45deg, #44ff44, #00cc44)';
        editando = true;
    } else {
        const nuevoEmail = sanitizarInput(emailInput.value);
        
        if (detectarAtaque(nuevoEmail)) {
            editando = false;
            toggleModoEdicionOff();
            return;
        }
        
        const errorEmail = validarEmail(nuevoEmail);
        if (errorEmail) {
            mostrarNotificacion('Error', errorEmail, 'error');
            registrarIntentoFallido();
            return;
        }

        if (nuevoEmail === usuario.email) {
            mostrarNotificacion('Info', 'No hay cambios que guardar', 'info');
            toggleModoEdicionOff();
            return;
        }

        try {
            const docRef = doc(db, 'users', usuario.uid);
            await updateDoc(docRef, {
                email: nuevoEmail,
                emailUpdated: serverTimestamp()
            });
            
            usuario.email = nuevoEmail;
            limpiarIntentosFallidos();
            toggleModoEdicionOff();
            
            mostrarNotificacion('Éxito', 'Perfil actualizado. Verifica tu nuevo email.', 'success');
        } catch (error) {
            console.error('Error actualizando perfil:', error);
            manejarErrorFirebase(error, 'Error al actualizar perfil');
            registrarIntentoFallido();
        }
    }
}

function toggleModoEdicionOff() {
    const emailInput = document.getElementById('editEmail');
    const btn = document.getElementById('editProfileBtn');
    
    emailInput.disabled = true;
    emailInput.style.background = 'transparent';
    btn.textContent = 'Editar Perfil';
    btn.style.background = 'linear-gradient(45deg, #00d4ff, #7c3aed)';
    editando = false;
}

// ============================================
// CERRAR SESIÓN
// ============================================

function logout() {
    mostrarNotificacion('Cerrar Sesión', '¿Estás seguro?', 'warning');
    
    setTimeout(() => {
        const notificacion = document.querySelector('.notificacion-custom');
        if (notificacion) {
            const btn = notificacion.querySelector('.btn-notificacion');
            btn.textContent = 'Sí, salir';
            btn.onclick = async function() {
                try {
                    await signOut(auth);
                    
                    usuario = null;
                    editando = false;
                    seccionActual = 'overview';
                    sesionExpirada = false;
                    if (timerSesion) clearTimeout(timerSesion);
                    if (timerInactividad) clearTimeout(timerInactividad);
                    
                    intentosFallidos = 0;
                    intentosLogin.clear();
                    
                    mostrarSeccion('main');
                    
                    const userDropdown = document.getElementById('userDropdown');
                    if (userDropdown) userDropdown.classList.remove('active');
                    cerrarMenu();
                    
                    notificacion.remove();
                    mostrarNotificacion('¡Hasta luego!', 'Sesión cerrada de forma segura', 'success');
                } catch (error) {
                    console.error('Error cerrando sesión:', error);
                    mostrarNotificacion('Error', 'Error al cerrar sesión', 'error');
                }
            };
            
            const cancelBtn = document.createElement('button');
            cancelBtn.className = 'btn-notificacion';
            cancelBtn.textContent = 'Cancelar';
            cancelBtn.style.background = 'linear-gradient(45deg, #666, #999)';
            cancelBtn.style.marginLeft = '10px';
            cancelBtn.onclick = function() {
                notificacion.remove();
            };
            btn.parentElement.appendChild(cancelBtn);
        }
    }, 100);
}

// ============================================
// VALIDACIONES
// ============================================

function validarRegistroCompleto(nombreUsuario, email, password, confirmPassword, dia, mes, año) {
    let hayErrores = false;

    const validaciones = [
        { campo: 'usernameError', valor: nombreUsuario, validador: validarUsuario },
        { campo: 'emailError', valor: email, validador: validarEmail },
        { campo: 'passwordError', valor: password, validador: validarPassword },
        { campo: 'confirmPasswordError', valor: [password, confirmPassword], validador: ([p1, p2]) => validarPasswordConfirm(p1, p2) }
    ];

    validaciones.forEach(({ campo, valor, validador }) => {
        const error = validador(valor);
        if (error) {
            mostrarError(campo, error);
            hayErrores = true;
        }
    });

    if (!dia || !mes || !año) {
        mostrarError('birthDateError', 'Completa tu fecha de nacimiento');
        hayErrores = true;
    } else {
        const errorEdad = validarEdad(dia, mes, año);
        if (errorEdad) {
            mostrarError('birthDateError', errorEdad);
            hayErrores = true;
        }
    }

    return !hayErrores;
}

function validarUsuario(nombreUsuario) {
    if (!nombreUsuario) return 'Nombre de usuario requerido';
    if (nombreUsuario.length < 3) return 'Mínimo 3 caracteres';
    if (nombreUsuario.length > 15) return 'Máximo 15 caracteres';
    if (!/^[a-zA-Z0-9_]+$/.test(nombreUsuario)) return 'Solo letras, números y guión bajo';
    
    const prohibidos = ['admin', 'root', 'user', 'test', 'null', 'undefined', 'system', 'lisium', 'support', 'help'];
    if (prohibidos.includes(nombreUsuario.toLowerCase())) {
        return 'Nombre de usuario no disponible';
    }
    
    return null;
}

function validarEmail(email) {
    if (!email) return 'Email requerido';
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!regex.test(email)) return 'Email no válido';
    if (email.length > 80) return 'Email muy largo';
    
    const dominiosProhibidos = ['temp-mail.org', '10minutemail.com', 'guerrillamail.com', 'mailinator.com'];
    const dominio = email.split('@')[1]?.toLowerCase();
    if (dominiosProhibidos.includes(dominio)) {
        return 'No se permiten emails temporales';
    }
    
    return null;
}

function validarPassword(password) {
    if (!password) return 'Contraseña requerida';
    if (password.length < 10) return 'Mínimo 10 caracteres';
    if (password.length > 100) return 'Máximo 100 caracteres';
    if (!/(?=.*[a-z])/.test(password)) return 'Necesita al menos una minúscula';
    if (!/(?=.*[A-Z])/.test(password)) return 'Necesita al menos una mayúscula';
    if (!/(?=.*\d)/.test(password)) return 'Necesita al menos un número';
    if (!/(?=.*[!@#$%^&*(),.?":{}|<>])/.test(password)) return 'Necesita un carácter especial';
    
    const patronesComunes = [
        /(.)\1{2,}/g,
        /123456|abcdef|qwerty|password|admin|lisium/gi,
    ];
    
    for (let patron of patronesComunes) {
        if (patron.test(password)) {
            return 'Contraseña muy predecible, usa una más compleja';
        }
    }
    
    return null;
}

function validarPasswordConfirm(password, confirm) {
    if (password !== confirm) return 'Las contraseñas no coinciden';
    return null;
}

function validarEdad(dia, mes, año) {
    const fechaNac = new Date(año, mes - 1, dia);
    const hoy = new Date();
    
    if (fechaNac > hoy) return 'Fecha de nacimiento inválida';
    
    let edad = hoy.getFullYear() - fechaNac.getFullYear();
    const diferenciaMes = hoy.getMonth() - fechaNac.getMonth();
    
    if (diferenciaMes < 0 || (diferenciaMes === 0 && hoy.getDate() < fechaNac.getDate())) {
        edad--;
    }
    
    if (edad < 16) return 'Debes ser mayor de 16 años';
    if (edad > 120 || año < 1900) return 'Fecha no válida';
    return null;
}

// ============================================
// UTILIDADES
// ============================================

function limpiarErrores() {
    document.querySelectorAll('.error-message, .success-message').forEach(el => {
        el.style.display = 'none';
        el.textContent = '';
    });
}

function mostrarError(elementId, mensaje) {
    const elemento = document.getElementById(elementId);
    if (elemento) {
        elemento.textContent = sanitizarInput(mensaje);
        elemento.style.display = 'block';
    }
}

function mostrarExito(elementId, mensaje) {
    const elemento = document.getElementById(elementId);
    if (elemento) {
        elemento.textContent = sanitizarInput(mensaje);
        elemento.style.display = 'block';
    }
}

function registrarIntentoFallido() {
    intentosFallidos++;
    ultimoIntento = Date.now();
}

function limpiarIntentosFallidos() {
    intentosFallidos = 0;
}

// ============================================
// CONFIGURACIÓN DE FECHAS
// ============================================

function llenarFechas() {
    const daySelect = document.getElementById('birthDay');
    const yearSelect = document.getElementById('birthYear');
    
    if (daySelect && yearSelect) {
        daySelect.innerHTML = '<option value="">Día</option>';
        yearSelect.innerHTML = '<option value="">Año</option>';
        
        for (let i = 1; i <= 31; i++) {
            const option = document.createElement('option');
            option.value = i;
            option.textContent = i;
            daySelect.appendChild(option);
        }
        
        const añoActual = new Date().getFullYear();
        for (let i = añoActual - 16; i >= 1900; i--) {
            const option = document.createElement('option');
            option.value = i;
            option.textContent = i;
            yearSelect.appendChild(option);
        }
    }
}

// ============================================
// CONFIGURACIÓN DE EVENTOS
// ============================================

function configurarEventos() {
    console.log('🔧 Configurando eventos de seguridad...');
    
    const forms = [
        { id: 'registerForm', handler: manejarRegistro },
        { id: 'loginForm', handler: manejarLogin }
    ];
    
    forms.forEach(({ id, handler }) => {
        const form = document.getElementById(id);
        if (form) {
            form.addEventListener('submit', handler);
            console.log(`✅ Formulario ${id} configurado`);
        }
    });

    const menuToggle = document.getElementById('menuToggle');
    if (menuToggle) {
        menuToggle.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            toggleMenu();
        });
    }

    const menuOverlay = document.getElementById('menuOverlay');
    if (menuOverlay) {
        menuOverlay.addEventListener('click', cerrarMenu);
    }

    // Validaciones en tiempo real
    configurarValidacionesTiempoReal();
}

function configurarValidacionesTiempoReal() {
    let ultimaValidacion = 0;
    const VALIDACION_DELAY = 800;

    function validacionConDelay(inputId, validadorFn) {
        const input = document.getElementById(inputId);
        if (input) {
            input.addEventListener('input', function() {
                const ahora = Date.now();
                if (ahora - ultimaValidacion < VALIDACION_DELAY) return;
                ultimaValidacion = ahora;

                const valor = sanitizarInput(this.value);
                if (detectarAtaque(valor)) {
                    this.value = '';
                    return;
                }

                const error = validadorFn(valor);
                const errorElement = document.getElementById(inputId + 'Error');
                if (error) {
                    mostrarError(inputId + 'Error', error);
                } else {
                    if (errorElement) errorElement.style.display = 'none';
                }
            });
            
            input.addEventListener('paste', function(e) {
                setTimeout(() => {
                    const valor = sanitizarInput(this.value);
                    if (detectarAtaque(valor)) {
                        this.value = '';
                        mostrarNotificacion('Contenido Bloqueado', 'Se detectó contenido no válido', 'warning');
                    }
                }, 10);
            });
        }
    }

    validacionConDelay('username', validarUsuario);
    validacionConDelay('registerEmail', validarEmail);
    
    const registerPasswordInput = document.getElementById('registerPassword');
    if (registerPasswordInput) {
        registerPasswordInput.addEventListener('input', function() {
            const ahora = Date.now();
            if (ahora - ultimaValidacion < VALIDACION_DELAY) return;
            ultimaValidacion = ahora;

            const error = validarPassword(this.value);
            if (error) {
                mostrarError('passwordError', error);
            } else {
                const errorElement = document.getElementById('passwordError');
                if (errorElement) errorElement.style.display = 'none';
            }
            
            const confirmPassword = document.getElementById('confirmPassword').value;
            if (confirmPassword) {
                const confirmError = validarPasswordConfirm(this.value, confirmPassword);
                if (confirmError) {
                    mostrarError('confirmPasswordError', confirmError);
                } else {
                    const confirmErrorElement = document.getElementById('confirmPasswordError');
                    if (confirmErrorElement) confirmErrorElement.style.display = 'none';
                }
            }
        });
    }

    const confirmPasswordInput = document.getElementById('confirmPassword');
    if (confirmPasswordInput) {
        confirmPasswordInput.addEventListener('input', function() {
            const ahora = Date.now();
            if (ahora - ultimaValidacion < VALIDACION_DELAY) return;
            ultimaValidacion = ahora;

            const password = document.getElementById('registerPassword').value;
            const error = validarPasswordConfirm(password, this.value);
            if (error) {
                mostrarError('confirmPasswordError', error);
            } else {
                const errorElement = document.getElementById('confirmPasswordError');
                if (errorElement) errorElement.style.display = 'none';
            }
        });
    }
}

// ============================================
// EVENTOS GLOBALES
// ============================================

function configurarEventosGlobales() {
    // Cerrar modales y dropdowns
    window.onclick = function(event) {
        if (event.target.classList.contains('modal')) {
            const modalId = event.target.id;
            if (modalId) cerrarModal(modalId);
        }
        
        if (!event.target.closest('.user-menu')) {
            const userDropdown = document.getElementById('userDropdown');
            if (userDropdown) userDropdown.classList.remove('active');
        }
        
        if (!event.target.closest('.side-menu') && !event.target.closest('.menu-toggle')) {
            const menu = document.getElementById('sideMenu');
            if (menu && menu.classList.contains('active')) {
                cerrarMenu();
            }
        }
    };

    // Eventos de teclado
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            const userDropdown = document.getElementById('userDropdown');
            if (userDropdown) userDropdown.classList.remove('active');
            
            document.querySelectorAll('.modal').forEach(modal => {
                if (modal.style.display === 'block') {
                    cerrarModal(modal.id);
                }
            });
            
            cerrarMenu();
            document.querySelectorAll('.notificacion-custom').forEach(notificacion => {
                notificacion.remove();
            });
        }
        
        // Prevenir herramientas de desarrollo en producción
        if (!isDevelopment()) {
            if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I') || 
                (e.ctrlKey && e.shiftKey && e.key === 'C') || (e.ctrlKey && e.key === 'u')) {
                e.preventDefault();
                mostrarNotificacion('Acceso Restringido', 'Herramientas de desarrollo bloqueadas por seguridad', 'warning');
            }
        }
    });

    // Header scroll effect
    let scrollTimeout;
    window.addEventListener('scroll', () => {
        const header = document.getElementById('header');
        if (!header) return;
        
        clearTimeout(scrollTimeout);
        
        const scrollPos = window.scrollY;
        
        if (scrollPos > 80) {
            header.classList.add('scrolled');
        } else {
            header.classList.remove('scrolled');
        }
        
        scrollTimeout = setTimeout(() => {
            const notificaciones = document.querySelectorAll('.notificacion-custom');
            if (notificaciones.length > 0 && scrollPos > 200) {
                notificaciones.forEach(n => n.remove());
            }
        }, 500);
    });

    // Detectar cambios de visibilidad
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            console.log('🔒 Pestaña oculta - modo seguro');
        } else {
            console.log('🔒 Pestaña visible - verificando sesión');
            if (usuario && auth.currentUser) {
                auth.currentUser.getIdToken(true).catch(() => {
                    mostrarNotificacion('Sesión Expirada', 'Inicia sesión nuevamente', 'warning');
                    logout();
                });
            }
        }
    });

    // Monitoreo de conexión
    window.addEventListener('online', () => {
        if (db) enableNetwork(db);
        mostrarNotificacion('Conexión', 'Conectado a internet', 'success');
    });

    window.addEventListener('offline', () => {
        if (db) disableNetwork(db);
        mostrarNotificacion('Sin Conexión', 'Modo offline activado', 'warning');
    });

    // Detección de bots y herramientas automatizadas
    if (navigator.webdriver || window.phantom || window._phantom || window.callPhantom) {
        console.warn('🤖 Bot detectado');
        if (!isDevelopment()) {
            mostrarNotificacion('Acceso Restringido', 'Acceso automatizado detectado', 'warning');
        }
    }
}

// ============================================
// FUNCIONES GLOBALES EXPORTADAS
// ============================================

const funcionesGlobales = {
    toggleMenu,
    cerrarMenu,
    irInicio,
    irASeccion,
    abrirModal,
    cerrarModal,
    mostrarDashboard,
    mostrarSeccionDashboard,
    editarPerfil,
    configuracion,
    toggleUserDropdown,
    logout,
    subirFoto,
    manejarFoto,
    toggleEditMode,
    eliminarCuenta
};

Object.keys(funcionesGlobales).forEach(func => {
    if (typeof funcionesGlobales[func] === 'function') {
        window[func] = funcionesGlobales[func];
    }
});

// ============================================
// INICIALIZACIÓN
// ============================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Iniciando Lisium Corp Ultra Secure v3.0...');
    
    const elementosCriticos = [
        'menuToggle', 'sideMenu', 'menuOverlay', 
        'registerForm', 'loginForm', 'header'
    ];
    
    const elementosFaltantes = elementosCriticos.filter(id => !document.getElementById(id));
    
    if (elementosFaltantes.length > 0) {
        console.error('❌ Elementos críticos faltantes:', elementosFaltantes);
        mostrarNotificacion(
            'Error Crítico',
            'La aplicación no se pudo inicializar correctamente. Recarga la página.',
            'error'
        );
        return;
    }
    
    try {
        llenarFechas();
        console.log('📅 Fechas configuradas');
        
        configurarEventos();
        console.log('🎯 Eventos principales configurados');
        
        configurarEventosGlobales();
        console.log('🌐 Eventos globales configurados');
        
        if (!appCheckInitialized && !isDevelopment()) {
            console.warn('⚠️ App Check no inicializado en producción');
            mostrarNotificacion(
                'Verificación de Seguridad',
                'Algunos sistemas de seguridad no están disponibles.',
                'warning'
            );
        }
        
        try {
            localStorage.setItem('lisium-test', 'test');
            localStorage.removeItem('lisium-test');
        } catch (e) {
            console.warn('⚠️ localStorage no disponible');
        }
        
        console.log('🔒 Firebase con App Check iniciado');
        console.log('✨ Lisium Corp Ultra Secure lista!');
        console.log('🛡️ Protecciones activas: Rate limiting, detección de ataques, validación estricta, gestión de sesión');
        
        if (isDevelopment()) {
            console.log('🚧 MODO DESARROLLO - Algunas protecciones están relajadas');
            console.log('📝 Para producción, configura variables de entorno y dominio seguro');
        }
        
    } catch (error) {
        console.error('❌ Error durante la inicialización:', error);
        mostrarNotificacion(
            'Error de Inicialización',
            'Ocurrió un error al inicializar la aplicación. Recarga la página.',
            'error'
        );
    }
});

// Mensaje de seguridad en consola
setTimeout(() => {
    if (!isDevelopment()) {
        console.clear();
        console.log('%c🔒 LISIUM CORP - SISTEMA SEGURO', 'color: #00d4ff; font-size: 24px; font-weight: bold;');
        console.log('%c⚠️ ADVERTENCIA DE SEGURIDAD', 'color: #ff4444; font-size: 18px; font-weight: bold;');
        console.log('%cEste sitio web está protegido por sistemas de seguridad avanzados.', 'color: orange; font-size: 14px;');
        console.log('%cCualquier intento de manipulación será registrado y puede resultar en el bloqueo del acceso.', 'color: orange; font-size: 12px;');
        console.log('%cSi eres un desarrollador legítimo, contacta con nosotros en: lisium.corp.uy@gmail.com', 'color: white; font-size: 12px;');
    }
}, 2000);
            