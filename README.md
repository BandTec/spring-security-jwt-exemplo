# Da Senha ao Token — Autenticação JWT com Spring Boot 4

> **Branch:** `main` — Spring Boot 4.0.5 | Java 21 LTS | JJWT 0.12.6
>
> Para a versao Spring Boot 3.x, veja a branch [`spring-3.x.x`](../../tree/spring-3.x.x)

---

## A Historia das Senhas

Para entender por que usamos BCrypt, Salt, Pepper e JWT, precisamos comecar do inicio.

### Anos 90: Texto Puro (Plaintext)

Os primeiros sistemas simplesmente gravavam a senha diretamente no banco de dados:

```sql
-- Anos 90 — Nao faca isso. Nunca. Em hipotese alguma.
INSERT INTO usuario (email, senha) VALUES ('john@doe.com', '123456');
```

O problema era obvio: qualquer pessoa com acesso ao banco — um DBA malicioso, um backup vazado, um SQL Injection — via todas as senhas de todos os usuarios, em texto claro.

Quando o Yahoo teve [3 bilhoes de contas vazadas em 2013](https://en.wikipedia.org/wiki/Yahoo!_data_breaches), grande parte das senhas estava em plaintext ou em formatos equivalentemente frageis.

---

### MD5 e SHA-1: A Ilusao de Seguranca

A solucao natural foi usar funcoes de hash. Em vez de gravar `123456`, gravava-se o hash:

```
MD5("123456")   = "e10adc3949ba59abbe56e057f20f883e"
SHA1("123456")  = "7c4a8d09ca3762af61e59520943dc26494f8941b"
```

Parecia seguro. Afinal, hash nao tem inversa, certo?

O problema: hash e **deterministico**. A mesma entrada sempre produz a mesma saida. Isso abriu caminho para as **Rainbow Tables**.

---

### Rainbow Tables: Atacando o Hash

Rainbow Table e uma tabela precomputada com milhoes (ou bilhoes) de pares `hash → senha`:

```
e10adc3949ba59abbe56e057f20f883e  →  123456
5f4dcc3b5aa765d61d8327deb882cf99  →  password
827ccb0eea8a706c4c34a16891f84e7b  →  12345678
...
```

Com essa tabela em maos, o atacante nao precisa "quebrar" o hash — so precisa fazer uma consulta. Sites como [CrackStation](https://crackstation.net) e [WeakPass](https://weakpass.com) tem bilhoes de hashes precomputados disponiveis gratuitamente.

```bash
# Teste voce mesmo — cole esse hash no CrackStation:
e10adc3949ba59abbe56e057f20f883e
# Resultado imediato: "123456"
```

Resultado: MD5 e SHA-1 sao **inuteis** para armazenar senhas. O NIST [desaconselha seu uso](https://csrc.nist.gov/projects/hash-functions) para autenticacao desde 2005.

---

### Salt: Quebrando as Rainbow Tables

A resposta ao problema das Rainbow Tables e o **Salt**: um valor aleatorio e unico gerado para cada usuario, concatenado com a senha antes do hash.

```
salt_usuario_1 = "xK9p$2mR"
hash = MD5("xK9p$2mR" + "123456") = "3c59dc048e8850243be8079a5c74d079"

salt_usuario_2 = "7bQw#1nZ"
hash = MD5("7bQw#1nZ" + "123456") = "a2c28d7e6f1b3904d8f752c9e1470e2c"
```

Dois usuarios com a mesma senha `123456` tem hashes completamente diferentes. As Rainbow Tables preexistentes tornam-se **inuteis** — seria necessario gerar uma tabela nova para cada salt possivel, o que e computacionalmente inviavel.

O salt nao e secreto — fica armazenado junto com o hash no banco de dados. O que o torna efetivo e a unicidade: o atacante precisaria montar uma Rainbow Table especifica para cada usuario individualmente.

---

### O Problema dos Hashes Rapidos

Mesmo com salt, MD5 e SHA-256 tem um problema fundamental: sao **rapidos demais**.

Uma GPU moderna consegue calcular:

| Algoritmo  | Velocidade estimada (GPU)         |
|------------|-----------------------------------|
| MD5        | ~50 **bilhoes** de hashes/segundo |
| SHA-256    | ~10 **bilhoes** de hashes/segundo |
| BCrypt (cost 10) | ~20.000 hashes/segundo      |
| Argon2id   | Configuravel (proposital)         |

Com MD5, um atacante que obtem o banco de dados pode tentar 50 bilhoes de senhas por segundo. Uma senha de 8 caracteres alfanumericos tem ~218 trilhoes de combinacoes — quebravel em menos de 1 hora com hardware dedicado.

---

### BCrypt: Lento por Design

BCrypt foi criado em 1999 especificamente para armazenar senhas. Sua caracteristica central e o **fator de custo** (cost factor), que controla quantas rodadas de processamento sao executadas:

```
custo = 10  →  2^10  = 1.024 rodadas  →  ~100ms por hash
custo = 12  →  2^12  = 4.096 rodadas  →  ~400ms por hash
custo = 14  →  2^14  = 16.384 rodadas →  ~1,6s por hash
```

O fator de custo e **ajustavel conforme o hardware evolui**. Em 2010, cost=10 era seguro. Em 2025, cost=12 ou 13 e mais adequado. O BCrypt acompanha o crescimento computacional.

#### Anatomia de um hash BCrypt

O usuario de teste deste projeto tem sua senha armazenada como:

```
$2a$10$0/TKTGxdREbWaWjWYhwf6e9P1fPOAMMNqEnZgOG95jnSkHSfkkIrC
```

Cada parte tem um significado:

```
$2a$        → versao do BCrypt (2a = versao atual recomendada)
$10$        → fator de custo (cost=10, ou seja, 2^10 = 1024 iteracoes)
0/TKTGxdREbWaWjWYhwf6e  → salt (22 caracteres Base64 = 16 bytes aleatorios)
9P1fPOAMMNqEnZgOG95jnSkHSfkkIrC → hash da senha + salt (31 caracteres)
```

O salt esta embutido no proprio hash — nao e necessario armazena-lo separadamente.

Como o Spring Boot utiliza BCrypt neste projeto:

```java
// SecurityConfiguracao.java — define o encoder como bean
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(); // cost padrao = 10
}

// UsuarioService.java — ao criar usuario, a senha e hasheada antes de salvar
String senhaCriptografada = passwordEncoder.encode(novoUsuario.getSenha());
novoUsuario.setSenha(senhaCriptografada);

// AutenticacaoProvider.java — ao fazer login, compara senha digitada com hash no banco
if (this.passwordEncoder.matches(senhaDigitada, hashNoBanco)) {
    // autenticado!
}
```

O metodo `matches()` extrai o salt do proprio hash, recalcula e compara — voce nunca precisa gerenciar o salt manualmente.

---

### Argon2: Memory-Hard

BCrypt e **CPU-hard**: dificil de paralelizar porque exige muitas iteracoes de CPU. Mas GPUs modernas tem milhares de nucleos — mesmo lento, e possivel rodar muitas instancias de BCrypt em paralelo.

**Argon2** (vencedor da Password Hashing Competition em 2015) adiciona o conceito de **memory-hard**: alem de CPU, o algoritmo exige grande quantidade de RAM.

```
Argon2id (configuracao recomendada):
  - Memoria: 64 MB por hash
  - Iteracoes: 3
  - Paralelismo: 4 threads
```

Uma GPU com 8 GB de VRAM consegue rodar apenas ~125 instancias simultaneas de Argon2 com 64 MB cada. Isso torna ataques com GPU essencialmente inviavel.

O Spring Security suporta Argon2 nativamente:

```java
// Alternativa ao BCrypt para maior seguranca (requer spring-security-crypto)
@Bean
public PasswordEncoder passwordEncoder() {
    return new Argon2PasswordEncoder(
        16,   // tamanho do salt em bytes
        32,   // tamanho do hash em bytes
        1,    // paralelismo
        65536,// memoria em KB (64 MB)
        3     // iteracoes
    );
}
```

> Para este projeto educacional usamos BCrypt (mais simples de entender e configurar).
> Em producao, Argon2id e a escolha mais robusta segundo o [OWASP](https://chefsec.io/owasp-password-storage-cheat-sheet).

---

### Pepper: A Camada que o Banco Nao Conhece

Salt resolve as Rainbow Tables, e BCrypt/Argon2 torna o brute force lento. Mas existe ainda um cenario critico: **vazamento completo do banco de dados**.

Se o atacante tem o banco, ele tem os salts e os hashes. Com tempo suficiente, pode tentar senhas por brute force (devagar, mas possivel para senhas fracas).

O **Pepper** e uma chave secreta global da aplicacao que e concatenada com a senha antes do hash — mas que **nao fica no banco de dados**:

```
hash = BCrypt(senha + salt + pepper)

Onde:
  senha  = "123456"          (fornecida pelo usuario)
  salt   = "xK9p$2mR..."    (gerado automaticamente, salvo no banco)
  pepper = "chave-secreta"   (variavel de ambiente, NUNCA no banco)
```

Resultado: mesmo com o banco vazado, o atacante nao consegue calcular os hashes sem o pepper. Segundo estimativas da comunidade de seguranca, a combinacao Salt + Pepper + BCrypt/Argon2 reduz a efetividade de ataques de brute force em **mais de 99%** em cenarios de vazamento de banco.

```bash
# application.properties (pepper como variavel de ambiente)
security.pepper=${SENHA_PEPPER:valorPadraoDev}
```

> Este projeto nao implementa pepper para manter o codigo simples e focado no JWT.
> Em producao, considere adicionar pepper como camada extra.

---

### Resumo: A Evolucao da Seguranca de Senhas

```
Anos 90      Plaintext          Senha visivel diretamente no banco
             ↓
Anos 2000    MD5 / SHA-1        Hash deterministico, vulneravel a Rainbow Tables
             ↓
Mid-2000s    Salt + SHA-256     Derrota Rainbow Tables, mas ainda rapido demais
             ↓
1999-hoje    BCrypt             Lento por design (CPU-hard), salt embutido, cost ajustavel
             ↓
2015-hoje    Argon2             Memory-hard, resistente a GPU, recomendado pelo OWASP
             ↓
Combinado    Salt+Pepper+Argon2 Pratica mais robusta disponivel atualmente
```

---

## O que Esta Implementacao Resolve (e o que Deixa para Producao)

Esta tabela mostra explicitamente como cada problema discutido acima e endereçado — ou deixado como extensao consciente — neste projeto:

| Problema / Ameaca                    | Esta implementacao resolve?  | Como / Onde no codigo                                                                 |
|--------------------------------------|------------------------------|---------------------------------------------------------------------------------------|
| Senha em texto puro no banco         | **Sim**                      | `UsuarioService.criar()` chama `passwordEncoder.encode()` antes de salvar             |
| Rainbow Tables                       | **Sim**                      | BCrypt gera salt automaticamente — cada hash e unico mesmo para senhas iguais         |
| Hashes rapidos (MD5/SHA-1)           | **Sim**                      | `BCryptPasswordEncoder` (cost=10) leva ~100ms por hash                                |
| Brute force com GPU                  | **Parcialmente**             | BCrypt e CPU-hard; Argon2 (memory-hard) seria mais resistente a GPU                  |
| Vazamento total do banco             | **Parcialmente**             | BCrypt com salt dificulta; Pepper (nao implementado) completaria a protecao           |
| Sessao stateful / problemas de escala| **Sim**                      | JWT stateless — servidor nao guarda estado; qualquer instancia valida o token         |
| Token adulterado pelo cliente        | **Sim**                      | Assinatura HMAC-SHA256 em `GerenciadorTokenJwt` — alteracao invalida a signature     |
| Token expirado aceito                | **Sim**                      | JJWT valida claim `exp` automaticamente; `AutenticacaoFilter` trata `ExpiredJwtException` |
| Chave secreta exposta no repositorio | **Nao (intencional)**        | Em producao: `jwt.secret=${JWT_SECRET}` via variavel de ambiente                     |
| Pepper para protecao extra           | **Nao (intencional)**        | Extensao para o projeto de voces — adicionar pepper como variavel de ambiente        |
| Tokens de longa duracao sem saida    | **Nao (intencional)**        | Refresh Token e revogacao ficam fora do escopo didatico inicial                      |

---

## E Depois do Login? JWT

Agora que sabemos como armazenar senhas com seguranca, surge uma nova questao:

> **O usuario ja se autenticou. Como provamos isso nas proximas requisicoes sem pedir a senha de novo?**

A abordagem classica era a **sessao HTTP**: o servidor guarda na memoria que o usuario X esta autenticado e envia um cookie de sessao para o browser. Funciona — mas nao escala bem quando voce tem multiplos servidores (qual deles tem a sessao?).

A solucao moderna para APIs REST e o **JWT (JSON Web Token)**.

### O que e um JWT

JWT e um token autocontido e assinado digitalmente que o proprio cliente carrega. O servidor nao armazena nada — ele apenas verifica a assinatura.

```
HEADER.PAYLOAD.SIGNATURE
  ↑          ↑           ↑
algoritmo  dados do   prova de
           usuario    autenticidade
```

Cada parte e codificada em Base64 (nao criptografada — qualquer um pode ler o payload):

```json
// HEADER (decodificado)
{ "alg": "HS256", "typ": "JWT" }

// PAYLOAD (decodificado) — claims do token
{
  "sub": "john@doe.com",          // subject: quem e o usuario
  "authorities": "",              // roles/perfis do usuario
  "iat": 1743350400,              // issued at: quando foi emitido (Unix timestamp)
  "exp": 1743354000               // expiration: quando expira
}

// SIGNATURE
HMAC-SHA256(base64(header) + "." + base64(payload), chave-secreta)
```

> **Importante:** o payload e apenas Base64, nao e criptografado. Nao coloque senhas, numeros de cartao ou dados sensiveis no token. Use apenas o necessario para identificar o usuario.

A **assinatura** e o que garante a seguranca: so o servidor conhece a chave secreta. Se alguem modificar o payload (ex: mudar o email ou adicionar uma role), a assinatura nao vai bater e o token sera rejeitado.

### Fluxo Completo

```
1. LOGIN
   Cliente → POST /usuarios/login { email, senha }
   Servidor → valida credenciais (BCrypt.matches)
            → gera token JWT assinado com HS256
   Resposta → { "token": "eyJ...", "nome": "John Doe" }

2. REQUISICOES AUTENTICADAS
   Cliente → GET /usuarios
             Authorization: Bearer eyJ...
   Servidor → AutenticacaoFilter extrai o token
            → JJWT verifica assinatura e expiracao
            → extrai email do payload
            → autentica o usuario no SecurityContext
   Resposta → 200 OK [ lista de usuarios ]

3. TOKEN INVALIDO OU EXPIRADO
   Cliente → GET /usuarios
             Authorization: Bearer eyJ...EXPIRADO
   Servidor → JJWT lanca ExpiredJwtException
            → 401 Unauthorized
```

### Como o Codigo Implementa Isso

**Gerando o token no login** (`GerenciadorTokenJwt.java`):
```java
return Jwts.builder()
    .subject(authentication.getName())        // claim "sub": email do usuario
    .claim("authorities", authorities)        // claim customizado: roles
    .issuedAt(new Date())                     // claim "iat": agora
    .expiration(new Date(now + validity))     // claim "exp": daqui a N segundos
    .signWith(parseSecret())                  // assina com HMAC-SHA256
    .compact();                               // serializa para String
```

**Validando a cada requisicao** (`AutenticacaoFilter.java`):
```java
// Extrai "Bearer <token>" do header Authorization
jwtToken = requestTokenHeader.substring(7);

// JJWT valida assinatura e expiracao automaticamente ao parsear
username = jwtTokenManager.getUsernameFromToken(jwtToken);

// Registra o usuario como autenticado no contexto da thread
SecurityContextHolder.getContext().setAuthentication(autenticacao);
```

**A chave secreta** (`application.properties`):
```properties
# Minimo 256 bits (32 bytes) para HMAC-SHA256
# Em producao: jwt.secret=${JWT_SECRET}
jwt.secret=RXhpc3Rl...  (chave em Base64)

# Validade em SEGUNDOS — 3600 = 1 hora
jwt.validity=3600
```

---

## Como Rodar

**Requisitos:** Java 21+ e Maven 3.8+ (ou use o wrapper `./mvnw`)

```bash
./mvnw spring-boot:run
```

API disponivel em `http://localhost:8080`

**Usuario de teste pre-cadastrado:**

| Email         | Senha  | Hash BCrypt armazenado                                          |
|---------------|--------|-----------------------------------------------------------------|
| john@doe.com  | 123456 | `$2a$10$0/TKTGxdREbWaWjWYhwf6e9P1fPOAMMNqEnZgOG95jnSkHSfkkIrC` |

Decodificando o hash: `$2a$` (versao BCrypt) + `$10$` (cost=10) + salt (22 chars) + hash (31 chars).

---

## Endpoints

### POST `/usuarios/login` — Autenticar

```bash
curl -X POST http://localhost:8080/usuarios/login \
  -H "Content-Type: application/json" \
  -d '{"email": "john@doe.com", "senha": "123456"}'
```

Resposta `200 OK`:
```json
{
  "userId": 1,
  "nome": "John Doe",
  "email": "john@doe.com",
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huQGRvZS5jb20i..."
}
```

### GET `/usuarios` — Listar (requer token)

```bash
curl http://localhost:8080/usuarios \
  -H "Authorization: Bearer <TOKEN>"
```

Sem token → `401 Unauthorized`

### POST `/usuarios` — Criar usuario (requer token)

```bash
curl -X POST http://localhost:8080/usuarios \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"nome": "Maria Silva", "email": "maria@email.com", "senha": "minhasenha"}'
```

### Interfaces de desenvolvimento

| Interface        | URL                                    |
|------------------|----------------------------------------|
| Swagger UI       | http://localhost:8080/swagger-ui.html  |
| Console H2       | http://localhost:8080/h2-console       |
| H2 JDBC URL      | `jdbc:h2:mem:teste-security`           |
| H2 usuario/senha | `admin` / `admin`                      |

---

## O que NAO Fazer em Producao

| Pratica deste projeto (didatica) | Versao para producao                          |
|----------------------------------|-----------------------------------------------|
| `jwt.secret` no .properties      | Variavel de ambiente: `${JWT_SECRET}`         |
| H2 in-memory                     | PostgreSQL/MySQL com backup                   |
| `spring.h2.console.enabled=true` | `false` em producao                           |
| CORS com `*` (qualquer origem)   | `setAllowedOrigins(List.of("https://..."))`   |
| BCrypt cost=10                   | cost=12 ou 13 (ajuste conforme o hardware)    |
| Sem pepper                       | Adicionar pepper via variavel de ambiente     |
| Token de 1 hora sem refresh      | Token curto (15 min) + Refresh Token          |

---

## Dependencias

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<!-- JJWT 0.12.x -->
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

*Projeto educacional — SPTech | `main`: Spring Boot 4.0.5 + Spring Security 7 + JJWT 0.12.6*
