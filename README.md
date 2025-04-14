![Ejemplo de imagen](assets/firebase_f.png)

# 🕵️ PRS222_Standards

## 🔐 **Estándar de Seguridad** 🛡️🔒



## 📂 **Estructura de Carpetas del Proyecto**

### 🎨 **FrontEnd** 🧩

El **`AuthService`** se encarga de gestionar toda la autenticación y autorización de usuarios en la aplicación. Utiliza Firebase para el inicio de sesión, almacenamiento de tokens en el `localStorage` y la obtención de información del usuario desde la API. Además, verifica el estado de autenticación, maneja la asignación de roles (como `ADMIN`), permite la reautenticación para cambios sensibles y gestiona la actualización de datos como la contraseña y el correo electrónico del usuario. También incluye funcionalidades para enviar solicitudes de restablecimiento de contraseña y cerrar sesión, limpiando los datos de autenticación almacenados.

---
## 🔧 Funcionalidades Principales

- 🟢 🔐 **Autenticación con Firebase:** Permite el inicio de sesión y mantiene la sesión activa usando tokens.

- 🟢 🛡️ **Autorización basada en roles:** Controla el acceso a ciertas funcionalidades según el rol del usuario (ej. ADMIN).

- 🟢 🚧 **Protección de rutas:** Implementa guardias para impedir el acceso no autorizado a rutas privadas.

- 🟢 👤 **Gestión del perfil:** Permite visualizar y actualizar datos personales del usuario.

- 🟢 ✉️ **Recuperación y cambio de contraseña:** Envía correos de restablecimiento y permite actualizar la contraseña.

- 🟢 🔁 **Actualización de correo electrónico:** Solicita reautenticación previa para garantizar la seguridad en cambios sensibles.

- 🟢 🔓 **Cierre de sesión:** Limpia completamente el token y los datos del usuario del `localStorage`.

---
###  Inicio de Sesion  - Usuario o Admin 💁‍♂️

Esta función permite a los usuarios iniciar sesión utilizando su correo electrónico y contraseña. Requiere dos parámetros: el email y el password. Utiliza Firebase Authentication para autenticar al usuario y obtiene un token de autenticación, el cual se guarda en localStorage. Además, realiza una solicitud a una API para obtener la información del usuario, como su rol, y almacena esos datos en localStorage.
``` ts
// 🔐 LOGIN PRINCIPAL
login(email: string, password: string): Observable<any> {
    return from(
      this.afAuth.signInWithEmailAndPassword(email, password).then(async (userCredential) => {
        const user = userCredential.user;
        if (!user) throw new Error("No se pudo iniciar sesión");
        const idTokenResult = await user.getIdTokenResult(true);
        const token = idTokenResult.token;
        if (isPlatformBrowser(this.platformId)) {
          localStorage.setItem("authToken", token);
        }
        try {
          const res = await fetch(`${this.userMe}/me`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (!res.ok) throw new Error("No se pudo obtener la información del usuario");
          const userInfo = await res.json();
          if (isPlatformBrowser(this.platformId)) {
            localStorage.setItem("userRole", userInfo.role);
            localStorage.setItem("userInfo", JSON.stringify(userInfo));
          }
          return userInfo;
        } catch (error) {
          console.warn("Login exitoso, pero falló la API:", error);
          return null; // Permitimos continuar aunque falle la API
        }
      })
    );
  }

```

#### Estructura de Archivos:

```bash
📁 app
└── 📁 auths
    ├── 📁 configuration             # ⚙️ Configuración del sistema
    │   ├── 📄 configuration.component.ts     # 🎯 Lógica del componente
    │   ├── 📄 configuration.component.html   # 🖼️ Vista HTML
    │   └── 📄 configuration.component.css    # 🎨 Estilos CSS
    ├── 📁 guards                     # 🛡️ Protecciones de rutas
    │   └── 📄 auth.guard.ts           # 🚧 Guardia de autenticación
    ├── 📁 login                      # 🔐 Pantalla de inicio de sesión
    ├── 📁 profile                    # 👤 Perfil del usuario
    └── 📁 services                   # 🛠️ Servicios generales
        └── 📄 auth.service.ts        # 🔐 Lógica de autenticación
```
