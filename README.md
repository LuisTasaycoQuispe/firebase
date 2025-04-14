![Ejemplo de imagen](assets/firebase_f.png)

# 🕵️ PRS222_Standards

## 🔐 **Estándar de Seguridad** 🛡️🔒



## 📂 **Estructura de Carpetas del Proyecto**


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


### Inicio de Sesion - Usuario o Admin 💁‍♂️

<img src="https://static.vecteezy.com/system/resources/thumbnails/027/205/841/small_2x/login-and-password-concept-3d-illustration-computer-and-account-login-and-password-form-page-on-screen-3d-illustration-png.png" alt="Imagen de api" width="150" align="left" style="margin-right: 20px; margin-bottom: 20px;">

Esta función permite a los usuarios iniciar sesión utilizando su correo electrónico y contraseña. Requiere dos parámetros: el email y el password. Utiliza Firebase Authentication para autenticar al usuario y obtiene un token de autenticación, el cual se guarda en localStorage. Además, realiza una solicitud a una API para obtener la información del usuario, como su rol, y almacena esos datos en localStorage.

</br>

- 🟢 🔐 LOGIN PRINCIPAL
``` ts

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
### Manejo de Roles 👑 

<img src="https://scientiait.blob.core.windows.net/programandoamedianoche/wp-content/uploads/2009/10/authentication.png" alt="Imagen de api" width="180" align="left" style="margin-right: 20px; margin-bottom: 20px;">

Después de un inicio de sesión exitoso, el rol del usuario se guarda en el localStorage. Puedes verificar el tipo de usuario con las funciones isAdmin() y getRole().

- 🟢 isAdmin(): Consulta el token de Firebase y verifica si el rol del usuario es "ADMIN".

- 🟢 getRole(): Obtiene el rol almacenado en el localStorage, que puede ser "ADMIN" o "USUARIO".

Estas funciones te permiten controlar los permisos de acceso según el rol del usuario. Si necesitas saber si un usuario tiene permisos de administrador, simplemente utiliza isAdmin() para hacer esa comprobación.


---
</br>

``` ts

// 🛡️ Verificar si el usuario tiene rol ADMIN (por claims de Firebase)
isAdmin(): Observable<boolean> {
  return this.afAuth.idTokenResult.pipe(
    map((token) => token?.claims?.["role"] === "ADMIN")
  );
}

// 🏷️ Obtener rol del usuario desde localStorage
getRole(): string | null {
  return isPlatformBrowser(this.platformId)
    ? localStorage.getItem("userRole")
    : null;
}

// Función para verificar si el usuario es ADMIN (se puede llamar en tu aplicación)
checkIfAdmin(): Observable<boolean> {
  const role = this.getRole();
  if (role === "ADMIN") {
    return of(true);  // Si el rol es ADMIN, el usuario es administrador
  }
  return of(false);  // Si el rol no es ADMIN, el usuario no es administrador
}
```

---

</br>

### Proteccion de Rutas Mediante **AuthGuard**  🔒🚪

Este archivo define un guardia de autenticación (`AuthGuard`) en Angular, que protege las rutas de la aplicación asegurándose de que solo los usuarios autenticados y con los roles adecuados puedan acceder a ciertas páginas. Si el usuario no está autenticado o no tiene el rol requerido, se redirige automáticamente al login o a la página de inicio. Además, evita que los usuarios autenticados accedan nuevamente a la página de login.

``` ts
// El guard que protege las rutas según la autenticación y el rol
canActivate(route: ActivatedRouteSnapshot): Observable<boolean | UrlTree> | boolean | UrlTree {
  const isLoginRoute = route.routeConfig?.path === 'login';

  if (isLoginRoute) {
    return this.canActivateIfNotAuthenticated();
  }

  const expectedRole = route.data?.["role"];
  return this.checkAccess(expectedRole);
}

// Verifica si el usuario está autenticado y tiene el rol adecuado
private checkAccess(expectedRole?: string): Observable<boolean | UrlTree> {
  return this.authService.isAuthenticated().pipe(
    take(1),
    switchMap((isAuthenticated) => {
      if (!isAuthenticated) {
        return of(this.router.createUrlTree(["/login"])); // Redirige al login si no está autenticado
      }

      if (!expectedRole) {
        return of(true); // Permite el acceso si no se espera un rol específico
      }

      const userRole = this.authService.getRole(); // Obtiene el rol del usuario
      if (userRole === expectedRole) {
        return of(true); // Permite el acceso si el rol coincide
      } else {
        return of(this.router.createUrlTree(["/dashboard"])); // Redirige si el rol no coincide
      }
    })
  );
}

```
</br>

🟢 ***Este codigo es la clave 🔑 para proteger la ruta en Angular, usando un guard que verifica si el usuario está autenticado y tiene el rol esperado***


---
