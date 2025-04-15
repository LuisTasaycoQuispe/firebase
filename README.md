![Ejemplo de imagen](firebase_f.png)

# 🕵️ PRS222_Standards

## 🔐 **Estándar de Seguridad** 🛡️🔒



## [![Typing SVG](https://readme-typing-svg.herokuapp.com?font=Bungee+Spice&size=22&pause=1000&width=803&lines=%F0%9F%93%82+Estructura+de+Carpetas+del+Proyecto+Frontend+(Security))](https://git.io/typing-svg)

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

###   🛡️🔐 Proteccion de Rutas Mediante **AuthGuard**  

</br>
Este archivo define un guardia de autenticación (`AuthGuard`) en Angular, que protege las rutas de la aplicación asegurándose de que solo los usuarios autenticados y con los roles adecuados puedan acceder a ciertas páginas. Si el usuario no está autenticado o no tiene el rol requerido, se redirige automáticamente al login o a la página de inicio. Además, evita que los usuarios autenticados accedan nuevamente a la página de login.


</br>
</br>


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

## [![Typing SVG](https://readme-typing-svg.herokuapp.com?font=Bungee+Spice&size=22&pause=1000&width=803&lines=%F0%9F%93%82+Estructura+de+Carpetas+del+Proyecto+Backend(Security))](https://git.io/typing-svg)

## 🌐 API Gateway


<img src="https://cdn-icons-png.flaticon.com/512/10169/10169724.png" alt="Imagen de api" width="130" align="left" style="margin-right: 20px; margin-bottom: 20px;">

El **API Gateway** es el punto de entrada único para todas las solicitudes que llegan a una aplicación con microservicios. Se encarga de redirigir las peticiones a los microservicios correctos y puede manejar tareas como autenticación, seguridad, control de acceso y manejo de errores. Al usar un API Gateway, el cliente solo necesita conocer una URL, lo que simplifica la comunicación y mejora el control sobre el tráfico y las peticiones.

</br>


### ⚙️ Funciones principales del API Gateway:


| **Función**                     | **Descripción**                                                                 |
|----------------------------------|---------------------------------------------------------------------------------|
| 🔁 **Enrutamiento de peticiones**   | Redirige las solicitudes entrantes al microservicio correspondiente según la URL. |
| 🔐 **Seguridad y autenticación**    | Verifica tokens JWT u otros mecanismos antes de permitir el acceso.             |
| 🧰 **Filtros personalizados**       | Como validar cabeceras, modificar peticiones/respuestas, agregar logs, etc.     |
| 🌐 **CORS y configuración de acceso** | Permite definir desde qué dominios se aceptan peticiones.                      |
| 📉 **Manejo de errores centralizado** | Permite manejar y devolver errores de forma consistente.                       |



``` bash

api-gateway/
├── 📁 src/
│   └── 📁 main/
│       ├── 📁 java/pe/edu/vallegrande/apigateway/
│       │   ├── 📁 config/
│       │   │   ├── 📄 SecurityConfig.java        # Configuración de seguridad (CORS, CSRF, etc.)
│       │   │   └── 📄 WebConfig.java             # Configuración web general
│       │   ├── 📁 filter/
│       │   │   ├── 📄 AuthHeaderFilter.java      # Filtro personalizado para autenticación con headers
│       │   └── 📄 ApiGatewayApplication.java     # Clase principal Spring Boot
│       └── 📁 resources/
│           └── 📄 application.yml                # Configuración de rutas, puertos, CORS, etc.


```


###  🔐 Configuración de Seguridad y CORS en el API Gateway

En este proyecto, se ha configurado el **API Gateway** para manejar la seguridad, autenticación y control de acceso a los microservicios, además de gestionar las solicitudes CORS entre el frontend y el backend.

#### 1. 🛡️ **Configuración de Seguridad (SecurityConfig)**
Esta clase configura la seguridad para las solicitudes que llegan al API Gateway. Las principales funciones son:

- **Deshabilitar CSRF**: Ya que no es necesario en un entorno de microservicios.
- **Autenticación de Usuarios**: Se utiliza JWT para la autenticación de usuarios. La ruta de **olvidé la contraseña** (`/api/auth/forgot-password`) está exenta de autenticación.
  
``` java
  @Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
      return http
              .csrf(ServerHttpSecurity.CsrfSpec::disable)
              .authorizeExchange(exchanges -> exchanges
                      .pathMatchers("/api/auth/forgot-password").permitAll()  // Sin autenticación
                      .anyExchange().authenticated()  // Requiere autenticación para el resto
              )
              .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())) // JWT para autenticación
              .build();
  }
```


#### 2. 🌐 **Configuración de CORS (WebConfig)**

Se configura **CORS** para permitir que las peticiones del frontend (en este caso, ejecutado en `localhost:4200`) puedan interactuar con el **API Gateway** sin problemas de seguridad:

- Permite métodos como `GET`, `POST`, `PUT`, `DELETE`.
- Acepta todas las cabeceras y permite credenciales.

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOriginPatterns(List.of("http://localhost:4200"));
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    config.setAllowedHeaders(List.of("*"));
    config.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;


###  🔑 Filtro de Autorización (AuthHeaderFilter)

Este filtro intercepta las solicitudes entrantes y, si contiene un header Authorization con un token Bearer, lo agrega a la solicitud. De esta forma, el token es enviado correctamente a los microservicios para su validación.


``` java

@Override
public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    if (authHeader != null && authHeader.startsWith("Bearer ")) {
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header(HttpHeaders.AUTHORIZATION, authHeader)
                .build();
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }
    return chain.filter(exchange);
}

```


## Integración de Firebase en Spring Boot 🔐
En este proyecto, el archivo security-prs1-firebase-adminsdk-fbsvc-b47fdda0f7.json contiene las credenciales de la cuenta de servicio proporcionada por Firebase, lo que permite que tu aplicación Spring Boot se autentique como administrador. Este archivo es esencial para interactuar con servicios como Firebase Authentication y Firebase Realtime Database. A través de esta integración, puedes realizar tareas administrativas como la creación, actualización y eliminación de usuarios, la verificación de tokens JWT, y el envío de notificaciones push. Además, en el archivo application.yml, se configura la seguridad con JWT de Firebase usando Spring Security, lo que permite autenticar las solicitudes y acceder a datos protegidos de forma segura.



``` bash

📁 src/
└── 📁 main/
    └── 📁 java/pe/edu/vallegrande/user/
    │   ├── 📁 config/         
    │   │   ├── 📄 CustomAuthenticationToken.java
    │   │   ├── 📄 FirebaseConfig.java
    │   │   └── 📄 SecurityConfig.java
    │   ├── 📁 controller/      
    │   ├── 📁 dto/             
    │   ├── 📁 model/           
    │   │   └── 📄 User.java
    │   └── 📁 repository/      
    │   │   └── 📄 UsersRepository.java
    │   └── 📁 service/         
    │       ├── 📄 EmailService.java
    │       └── 📄 UserService.java
    │  
    └── 📁 resources
            ├── 📁 config/
            │   └── 📄 security-prs1-firebase-adminsdk-fbsvc-b47fdda0f7.json
            └── 📄 application.yml
```

### Archivo security-prs1-firebase  🗝️ 


<img src="https://damphat.gallerycdn.vsassets.io/extensions/damphat/firebase-json/1.3.0/1685010293285/Microsoft.VisualStudio.Services.Icons.Default" alt="Imagen de api" width="150" align="left" style="margin-right: 20px; margin-bottom: 20px;">



El archivo ***security-prs1-firebase-adminsdk-fbsvc-b47fdda0f7.json*** es una credencial de tipo cuenta de servicio proporcionada por Firebase. Este archivo permite que tu aplicación Spring Boot se conecte de forma segura a los servicios de Firebase como administrador, autenticándose con privilegios elevados. Es fundamental cuando necesitas realizar operaciones internas en Firebase sin intervención del usuario, como acceder a la base de datos, validar tokens, o enviar notificaciones.

</br>

``` json

{
  "type": "service_account",
  "project_id": "security-prs1",
  "private_key_id": "REDACTED",
  "private_key": "REDACTED",
  "client_email": "firebase-adminsdk-fbsvc@security-prs1.iam.gserviceaccount.com",
  "client_id": "100590623008739978220",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40security-prs1.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}


```

### 📌 ¿Para qué sirve?
- 🟢 Autenticar tu backend con Firebase como administrador.

- 🟢 Verificar manualmente los tokens JWT generados por Firebase Authentication.

- 🟢 Enviar notificaciones push a través de Firebase Cloud Messaging (FCM).

- 🟢 Crear, actualizar o eliminar usuarios directamente desde el backend.

- 🟢 Leer y escribir datos en Firestore o Realtime Database con permisos elevados.

- 🟢 Realizar pruebas y configuraciones administrativas sin usar la consola web de Firebase.


### El aplication.yml ⚙️

En este archivo application.yml estás manejando configuración de seguridad con JWT de Firebase usando Spring Security. Ademas de la conexion con la base de datos

``` yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://securetoken.google.com/security-prs1
          jwk-set-uri: https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com

```

### 📦 Módulo: UserService

Este servicio maneja la lógica principal relacionada con la gestión de usuarios. Incluye:Creación de usuario: Guarda al usuario tanto en Firebase Authentication como en la base de datos.Actualización de usuario: Permite modificar información del usuario y actualizar roles en Firebase.Autenticación y seguridad: Cambia email o contraseña del usuario sincronizándolo con Firebase.Gestión de perfil: Permite al usuario editar sus propios datos (excepto email, contraseña y rol).Recuperación de contraseña: Envía enlace de reseteo mediante correo electrónico.Eliminación de usuario: Elimina al usuario de Firebase y de la base de datos.

### Funcion Principal:  Crear un nuevo usuario 🧑

Este método crea un usuario tanto en Firebase como en la base de datos:

``` java
public Mono<UserDto> createUser(UserCreateDto dto) {
        return usersRepository.findByEmail(dto.getEmail())
                .flatMap(existing -> Mono.error(new IllegalArgumentException("El correo ya está en uso.")))
                .switchIfEmpty(Mono.defer(() -> {
                    // 🔐 Crear usuario en Firebase
                    CreateRequest request = new CreateRequest()
                            .setEmail(dto.getEmail())
                            .setPassword(dto.getPassword())
                            .setEmailVerified(false)
                            .setDisabled(false);
                    return Mono.fromCallable(() -> FirebaseAuth.getInstance().createUser(request))
                            .flatMap(firebaseUser -> {
                                String uid = firebaseUser.getUid();
                                // 🔐 Asignar claim
                                String primaryRole = dto.getRole().isEmpty() ? "USER" : dto.getRole().get(0);
                                return Mono.fromCallable(() -> {
                                    FirebaseAuth.getInstance().setCustomUserClaims(uid, Map.of("role", primaryRole.toUpperCase()));
                                    System.out.println("✅ Claim de rol asignado: " + primaryRole);
                                    return uid;
                                }).cast(String.class);
                            })
                            .flatMap(uid -> {
                                // 🔄 Guardar en BD
                                User user = new User();
                                user.setFirebaseUid(uid);
                                user.setName(dto.getName());
                                user.setLastName(dto.getLastName());
                                user.setDocumentType(dto.getDocumentType());
                                user.setDocumentNumber(dto.getDocumentNumber());
                                user.setCellPhone(dto.getCellPhone());
                                user.setEmail(dto.getEmail());
                                user.setPassword(passwordEncoder.encode(dto.getPassword()));
                                user.setRole(dto.getRole());
                                user.setProfileImage(dto.getProfileImage());
                                return usersRepository.save(user)
                                        .map(this::toDto)
                                        .cast(UserDto.class);
                            });
                })).cast(UserDto.class);
    }
```
