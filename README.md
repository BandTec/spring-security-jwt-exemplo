# Autenticação JWT com Spring Boot 3 + Spring Security 6

Projeto de referência para implementação de autenticação stateless com **JWT (JSON Web Token)**
usando Spring Boot 3.x, Spring Security 6 e JJWT 0.12.x.

> **Branch:** `spring-3.x.x` — Spring Boot 3.4.x | Java 21 | JJWT 0.12.x

---

## O que é JWT?

JWT (JSON Web Token) é um padrão aberto ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519))
para transmitir informações de forma compacta e segura entre partes. Um token JWT é uma string
com três segmentos codificados em Base64, separados por ponto:

```
HEADER.PAYLOAD.SIGNATURE

eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huQGRvZS5jb20iLCJhdXRob3JpdGllcyI6IiIsImlhdCI6MTc0MzM1MDQwMCwiZXhwIjoxNzQzMzU0MDAwfQ.AbC123...
```

| Segmento      | Conteúdo                                                        | Criptografado? |
|---------------|-----------------------------------------------------------------|---------------|
| **Header**    | Tipo do token (`JWT`) e algoritmo de assinatura (`HS256`)       | Nao (Base64)  |
| **Payload**   | Claims: `sub`, `exp`, `iat`, `authorities` e outros dados       | Nao (Base64)  |
| **Signature** | Hash do header + payload com a chave secreta                    | Sim (HMAC)    |

> **Importante:** o payload e apenas codificado em Base64, **nao criptografado**.
> Qualquer pessoa pode decodifica-lo em [jwt.io](https://jwt.io).
> **Nunca coloque senhas ou dados sensiveis no payload.**

### Por que JWT ao inves de sessao?

| Sessao (stateful)                                      | JWT (stateless)                                         |
|--------------------------------------------------------|---------------------------------------------------------|
| Servidor armazena o estado da sessao na memoria/banco  | Servidor nao armazena nada — o token e autocontido      |
| Dificil de escalar horizontalmente                     | Escala facilmente — qualquer servidor valida o token    |
| Cookie de sessao enviado automaticamente pelo browser  | Token enviado explicitamente no header `Authorization`  |
| Logout invalida a sessao no servidor                   | Logout no cliente (remover o token); servidor nao sabe  |

---

## Arquitetura e Fluxo

### 1. Login (obter o token)

```
Cliente                          API (Spring Boot)
  |                                      |
  |  POST /usuarios/login                |
  |  { "email": "...", "senha": "..." }  |
  |------------------------------------->|
  |                                      |  UsuarioController.login()
  |                                      |    -> UsuarioService.autenticar()
  |                                      |      -> AuthenticationManager.authenticate()
  |                                      |        -> AutenticacaoProvider.authenticate()
  |                                      |          -> AutenticacaoService.loadUserByUsername()
  |                                      |            (busca usuario no banco pelo e-mail)
  |                                      |          -> BCrypt.matches(senha, hashNoBanco)
  |                                      |      -> GerenciadorTokenJwt.generateToken()
  |                                      |        (gera token assinado com HS256)
  |                                      |
  |  200 OK                              |
  |  { "token": "eyJ...", "nome": "..." }|
  |<-------------------------------------|
```

### 2. Acessar endpoint protegido (usar o token)

```
Cliente                          API (Spring Boot)
  |                                      |
  |  GET /usuarios                       |
  |  Authorization: Bearer eyJ...        |
  |------------------------------------->|
  |                                      |  AutenticacaoFilter.doFilterInternal()
  |                                      |    1. Extrai "Bearer eyJ..." do header
  |                                      |    2. GerenciadorTokenJwt.getUsernameFromToken()
  |                                      |       -> JJWT verifica assinatura + expiracao
  |                                      |       -> extrai "sub" (e-mail) do payload
  |                                      |    3. AutenticacaoService.loadUserByUsername()
  |                                      |       -> carrega UserDetails do banco
  |                                      |    4. GerenciadorTokenJwt.validateToken()
  |                                      |       -> username bate? token nao expirou?
  |                                      |    5. SecurityContextHolder.setAuthentication()
  |                                      |       -> registra usuario como autenticado
  |                                      |
  |                                      |  Spring Security verifica autorizacao
  |                                      |  -> usuario autenticado? endpoint permitido?
  |                                      |
  |                                      |  UsuarioController.listarTodos()
  |  200 OK [ lista de usuarios ]        |
  |<-------------------------------------|
```

### 3. Token invalido ou expirado

```
Cliente                          API (Spring Boot)
  |                                      |
  |  GET /usuarios                       |
  |  Authorization: Bearer eyJ...EXPIRADO|
  |------------------------------------->|
  |                                      |  AutenticacaoFilter
  |                                      |    -> JJWT lanca ExpiredJwtException
  |                                      |    -> username permanece null
  |                                      |    -> SecurityContext nao e populado
  |                                      |
  |                                      |  AutenticacaoEntryPoint.commence()
  |  401 Unauthorized                    |
  |<-------------------------------------|
```

---

## Classes de Seguranca

### `GerenciadorTokenJwt`
Responsavel por **gerar**, **validar** e **extrair claims** de tokens JWT.

| Metodo                    | Responsabilidade                                          |
|---------------------------|-----------------------------------------------------------|
| `generateToken(auth)`     | Cria token com subject, authorities, iat e exp            |
| `validateToken(token, ud)`| Verifica se username bate e se token nao expirou          |
| `getUsernameFromToken(t)` | Extrai o e-mail (claim `sub`) do payload                  |
| `getAllClaimsFromToken(t)` | Parseia o token — JJWT verifica assinatura aqui           |
| `parseSecret()`           | Decodifica o secret Base64 em `SecretKey` HMAC-SHA256     |

### `AutenticacaoFilter`
**Filtro HTTP** que intercepta todas as requisicoes e autentica o usuario pelo token JWT.
Executado antes de `UsernamePasswordAuthenticationFilter`.

### `AutenticacaoProvider`
Valida credenciais de **login** (e-mail + senha) comparando a senha digitada com o hash BCrypt no banco.

### `AutenticacaoService`
Implementa `UserDetailsService` — carrega o usuario do banco de dados pelo e-mail para o Spring Security.

### `SecurityConfiguracao`
Configuracao central do Spring Security: define quais URLs sao publicas, politica de sessao (STATELESS),
CORS, CSRF e registra o filtro JWT.

### `AutenticacaoEntryPoint`
Trata erros de autenticacao: retorna `401 Unauthorized` ou `403 Forbidden` conforme o tipo de falha.

---

## Requisitos

- Java 21+
- Maven 3.8+ (ou usar o wrapper `./mvnw`)
- Nenhuma instalacao de banco de dados necessaria (H2 in-memory)

---

## Como rodar

```bash
# Clonar o repositorio
git clone <url-do-repo>
cd spring-security-jwt-exemplo

# Rodar com Maven Wrapper (recomendado)
./mvnw spring-boot:run

# Ou com Maven instalado
mvn spring-boot:run
```

A API ficara disponivel em `http://localhost:8080`.

### Usuario de teste pre-cadastrado

| Campo | Valor         |
|-------|---------------|
| Email | john@doe.com  |
| Senha | 123456        |

---

## Endpoints

### POST `/usuarios/login` — Autenticar e obter token

```bash
curl -X POST http://localhost:8080/usuarios/login \
  -H "Content-Type: application/json" \
  -d '{"email": "john@doe.com", "senha": "123456"}'
```

**Resposta 200 OK:**
```json
{
  "userId": 1,
  "nome": "John Doe",
  "email": "john@doe.com",
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huQGRvZS5jb20i..."
}
```

---

### GET `/usuarios` — Listar usuarios (requer token)

```bash
# Substituir <TOKEN> pelo valor retornado no login
curl -X GET http://localhost:8080/usuarios \
  -H "Authorization: Bearer <TOKEN>"
```

**Resposta 200 OK:**
```json
[
  { "id": 1, "nome": "John Doe", "email": "john@doe.com" }
]
```

**Sem token -> 401 Unauthorized:**
```bash
curl -X GET http://localhost:8080/usuarios
# -> HTTP 401
```

---

### POST `/usuarios` — Criar novo usuario (requer token)

```bash
curl -X POST http://localhost:8080/usuarios \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"nome": "Maria Silva", "email": "maria@email.com", "senha": "minhasenha"}'
```

**Resposta 201 Created** (sem body)

---

### Documentacao interativa (Swagger UI)

Acesse `http://localhost:8080/swagger-ui.html` para testar os endpoints pelo browser.

Para autenticar no Swagger:
1. Faca login via `/usuarios/login` e copie o token
2. Clique em **Authorize** (cadeado) e cole: `Bearer eyJ...`

---

### Console H2 (banco in-memory)

Acesse `http://localhost:8080/h2-console`

| Campo    | Valor                        |
|----------|------------------------------|
| JDBC URL | `jdbc:h2:mem:teste-security` |
| User     | `admin`                      |
| Password | `admin`                      |

---

## Boas Praticas de Seguranca

### O que este projeto demonstra corretamente

- **BCrypt** para hash de senhas (com salt automatico)
- **STATELESS session** — servidor nao armazena estado de autenticacao
- **CSRF desabilitado** — correto para APIs REST com JWT (sem cookies de sessao)
- **Token no header Authorization** — padrao RFC 6750 (Bearer Token)
- **Chave secreta em Base64** com tamanho adequado para HS256 (>=256 bits)
- **Tratamento de excecoes JWT** — expirado, malformado, assinatura invalida

### O que NAO fazer em producao

| Pratica ruim                              | Alternativa segura                                      |
|-------------------------------------------|---------------------------------------------------------|
| Secret hardcoded em `application.properties` | Variavel de ambiente: `jwt.secret=${JWT_SECRET}`   |
| Token com validade muito longa            | 15 min a 1 hora + Refresh Token para renovacao          |
| Armazenar token no `localStorage`         | `sessionStorage` ou cookie HttpOnly                     |
| Colocar dados sensiveis no payload JWT    | Payload nao e criptografado — use apenas dados publicos |
| `*` no CORS em producao                  | `setAllowedOrigins(List.of("https://meuapp.com"))`      |
| H2 console habilitado em producao         | `spring.h2.console.enabled=false`                       |

### Gerar uma chave secreta segura para producao

```bash
# Linux/Mac — gera 64 bytes aleatorios em Base64 (512 bits)
openssl rand -base64 64

# Cole o resultado como valor de jwt.secret (ou variavel de ambiente JWT_SECRET)
```

---

## Dependencias principais

```xml
<!-- Spring Security -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<!-- JJWT 0.12.x (nova API) -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.6</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.12.6</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.12.6</version>
    <scope>runtime</scope>
</dependency>
```

---

## Estrutura do Projeto

```
src/main/java/school/sptech/exemplojwt/
├── config/
│   ├── GerenciadorTokenJwt.java      # Geracao e validacao de tokens JWT
│   ├── AutenticacaoFilter.java       # Filtro HTTP: extrai e valida o token
│   ├── AutenticacaoProvider.java     # Valida credenciais no login
│   ├── AutenticacaoEntryPoint.java   # Trata erros 401/403
│   └── SecurityConfiguracao.java     # Configuracao central do Spring Security
├── controller/
│   └── UsuarioController.java        # Endpoints REST
├── service/
│   ├── UsuarioService.java           # Logica de negocio + orquestra o login
│   └── AutenticacaoService.java      # UserDetailsService (carrega usuario do banco)
├── entity/
│   └── Usuario.java                  # Entidade JPA
├── dto/
│   ├── UsuarioLoginDto.java          # Request do login
│   ├── UsuarioTokenDto.java          # Response do login (com token)
│   ├── UsuarioCriacaoDto.java        # Request de criacao
│   ├── UsuarioListarDto.java         # Response de listagem
│   ├── UsuarioDetalhesDto.java       # Implementa UserDetails
│   └── UsuarioMapper.java            # Conversao entre entity e DTOs
└── repository/
    └── UsuarioRepository.java        # Acesso ao banco de dados
```

---

*Projeto educacional — SPTech | Branch: `spring-3.x.x` (Spring Boot 3.4.x + JJWT 0.12.x)*
