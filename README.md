# Da Senha ao Token: Autenticação JWT com Spring Boot 4

> **Branch:** `main` | Spring Boot 4.0.5 | Java 21 LTS | JJWT 0.12.6

---

## A História das Senhas

Para entender por que usamos BCrypt, Salt, Pepper e JWT, precisamos começar do início.

### Anos 90: Texto Puro

Os primeiros sistemas gravavam a senha diretamente no banco de dados:

```sql
-- Não faça isso. Nunca. Em hipótese alguma.
INSERT INTO usuario (email, senha) VALUES ('joao@email.com', 'senha123');
```

Qualquer pessoa com acesso ao banco, seja um DBA malicioso, um backup vazado ou um SQL Injection bem-sucedido, via todas as senhas de todos os usuários em texto claro.

### MD5 e SHA-1: A Ilusão de Segurança

A solução natural foi usar funções de hash. Em vez de gravar `senha123`, gravava-se o hash:

```
MD5("senha123") = "67abe4f56a5dd32d26a0c8c46b8e9a42"
```

Parecia seguro. Hash não tem inversa, certo?

O problema é que hash é **determinístico**: a mesma entrada sempre produz a mesma saída. Isso abriu espaço para as **Rainbow Tables**, tabelas precomputadas com bilhões de pares `hash → senha`. Sites como [CrackStation](https://crackstation.net) têm essas tabelas disponíveis gratuitamente. Você cola o hash e recebe a senha em segundos.

Resultado: MD5 e SHA-1 são inúteis para armazenar senhas. O NIST [desaconselha seu uso](https://csrc.nist.gov/projects/hash-functions) para autenticação desde 2005.

### Salt: Quebrando as Rainbow Tables

A resposta ao problema foi o **Salt**: um valor aleatório e único gerado para cada usuário, misturado com a senha antes do hash.

```
salt_joao  = "xK9p2mR8"
hash = MD5("xK9p2mR8" + "senha123") = "3c59dc048e8850243be8079a5c74d079"

salt_maria = "7bQw1nZ3"
hash = MD5("7bQw1nZ3" + "senha123") = "a2c28d7e6f1b3904d8f752c9e1470e2c"
```

Dois usuários com a mesma senha têm hashes completamente diferentes. As Rainbow Tables preexistentes tornam-se inúteis porque o atacante precisaria gerar uma tabela específica para cada salt possível, o que é computacionalmente inviável.

O salt não é secreto. Ele fica armazenado junto com o hash no banco. O que o torna efetivo é a unicidade.

### O Problema dos Hashes Rápidos

Mesmo com salt, MD5 e SHA-256 têm um problema fundamental: são rápidos demais.

| Algoritmo        | Velocidade estimada (GPU)          |
|------------------|------------------------------------|
| MD5              | ~50 bilhões de hashes por segundo  |
| SHA-256          | ~10 bilhões de hashes por segundo  |
| BCrypt (cost 10) | ~20.000 hashes por segundo         |
| Argon2id         | Configurável (intencional)         |

Com MD5, um atacante que obtém o banco pode tentar bilhões de senhas por segundo. Uma senha curta e comum é encontrada em minutos.

### BCrypt: Lento por Design

BCrypt foi criado em 1999 especificamente para armazenar senhas. Sua característica central é o **fator de custo**, que controla quantas rodadas de processamento são executadas:

```
custo = 10  →  2^10 = 1.024 rodadas  →  ~100ms por hash
custo = 12  →  2^12 = 4.096 rodadas  →  ~400ms por hash
```

O fator de custo é ajustável conforme o hardware evolui. O que era seguro em 2010 pode não ser suficiente em 2025. Essa adaptabilidade é o grande diferencial do BCrypt em relação a hashes comuns.

O hash BCrypt do usuário de teste deste projeto é:

```
$2a$10$0/TKTGxdREbWaWjWYhwf6e9P1fPOAMMNqEnZgOG95jnSkHSfkkIrC
```

Lendo o hash:

```
$2a$  = versão do BCrypt
$10$  = fator de custo (2^10 = 1024 iterações)
0/TKTGxdREbWaWjWYhwf6e  = salt (22 chars Base64, gerado automaticamente)
9P1fPOAMMNqEnZgOG95jnSkHSfkkIrC = hash da senha + salt
```

O salt fica embutido no próprio hash. Não é necessário armazená-lo separadamente.

### Argon2: Memory-Hard

BCrypt é CPU-hard: difícil de rodar em paralelo em CPU convencional. Mas GPUs têm milhares de núcleos e conseguem rodar muitas instâncias de BCrypt em paralelo mesmo com o custo elevado.

**Argon2** (vencedor da Password Hashing Competition em 2015) é **memory-hard**: além de CPU, cada operação de hash exige uma quantidade configurável de RAM. Uma GPU com 8 GB de VRAM, usando Argon2 com 64 MB por hash, consegue rodar apenas ~125 instâncias simultâneas. Isso torna ataques via GPU inviáveis na prática.

Este projeto usa BCrypt por ser mais simples de entender e configurar. A branch [`feature/argon2-pepper`](../../tree/feature/argon2-pepper) implementa Argon2id com pepper.

### Pepper: A Camada que o Banco Não Conhece

Salt protege contra Rainbow Tables. BCrypt torna o brute force lento. Mas existe ainda um cenário crítico: o atacante obtém o banco de dados completo.

Se o atacante tem o banco, tem os salts e os hashes. Com tempo suficiente, pode tentar senhas por brute force, lento mas possível para senhas fracas.

O **Pepper** é uma chave secreta da aplicação que é incorporada à senha antes do hash, mas que nunca fica no banco de dados:

```
hash = BCrypt(HMAC(senha, pepper))

senha  = entrada do usuário
pepper = variável de ambiente, nunca salvo no banco
```

Mesmo com o banco completamente vazado, o atacante não consegue calcular os hashes sem o pepper. A combinação Salt + Pepper + Argon2 é a prática mais robusta disponível atualmente.

Este projeto não implementa pepper para manter o foco no JWT. A branch [`feature/argon2-pepper`](../../tree/feature/argon2-pepper) adiciona essa camada.

### Resumo

```
Anos 90      Plaintext          Senha visível no banco
             ↓
Anos 2000    MD5 / SHA-1        Hash determinístico, vulnerável a Rainbow Tables
             ↓
Mid-2000s    Salt + SHA-256     Derrota Rainbow Tables, mas ainda muito rápido
             ↓
1999-hoje    BCrypt             Lento por design, salt embutido, custo ajustável
             ↓
2015-hoje    Argon2id           Memory-hard, resistente a GPU, recomendado pelo OWASP
             ↓
Combinado    Salt+Pepper+Argon2 Melhor prática disponível atualmente
```

---

## E Depois do Login? O Problema da Sessão

O usuário se autenticou. Como provamos isso nas próximas requisições sem pedir a senha de novo?

A abordagem tradicional era a **sessão HTTP**: o servidor guarda na memória que o usuário X está autenticado e envia um identificador (session ID) para o browser. Funciona, mas não escala quando há múltiplos servidores. Cada servidor teria uma memória diferente e o usuário autenticado em um não seria reconhecido por outro.

A solução moderna para APIs REST são os tokens. Mas não são todos iguais.

### Token Opaco vs. JWT

**Token Opaco** é uma string aleatória sem significado próprio:

```
a3f7b2c1-9e4d-4a8b-bc12-1f8e3d5a6c9f
```

Para validar, o servidor precisa consultar um banco ou cache:

```
Requisição → token → consulta BD → "esse token é do usuário 42, role ADMIN"
```

Vantagem: pode ser revogado instantaneamente, basta deletar do banco.
Desvantagem: toda requisição gera uma consulta ao banco de dados.

**JWT (JSON Web Token)** carrega as informações diretamente no payload, codificado em Base64:

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2FvQGVtYWlsLmNvbSIsImV4cCI6MTc0MzM1NDAwMH0.xyz
```

Decodificando o payload:
```json
{
  "sub": "joao@email.com",
  "iat": 1743350400,
  "exp": 1743354000
}
```

O servidor lê quem é o usuário diretamente do token, sem consultar banco.

Vantagem: stateless, qualquer servidor valida sem estado compartilhado.
Desvantagem: não pode ser revogado antes de expirar. Se o token foi emitido, ele é válido até o campo `exp`. Por isso tokens de curta duração são essenciais.

### O que é um JWT

JWT é um token com três partes separadas por ponto:

```
HEADER.PAYLOAD.SIGNATURE
```

Cada parte é codificada em Base64, mas não é criptografada. Qualquer um com o token pode ler o payload. Nunca coloque senhas, números de cartão ou dados pessoais sensíveis no token.

```json
// HEADER
{ "alg": "HS256", "typ": "JWT" }

// PAYLOAD
{
  "sub": "joao@email.com",    // quem é o usuário
  "iat": 1743350400,          // quando foi emitido
  "exp": 1743354000           // quando expira
}

// SIGNATURE
HMAC-SHA256(base64(header) + "." + base64(payload), chave-secreta)
```

A assinatura é o que garante a integridade: só o servidor conhece a chave secreta. Se alguém modificar o payload, a assinatura não bate e o token é rejeitado.

---

## Onde Guardar o Token no Frontend

Depois que o servidor emite o JWT, o frontend precisa guardá-lo em algum lugar para enviá-lo nas próximas requisições. Existem três abordagens comuns e a diferença entre elas é principalmente de segurança.

### sessionStorage

O token é guardado via JavaScript (`sessionStorage.setItem('token', valor)`) e recuperado na hora de fazer requisições (`sessionStorage.getItem('token')`).

Escopo: específico da aba. Quando a aba fecha, os dados somem.

Problema de segurança: qualquer script JavaScript rodando na página consegue ler o valor. Um ataque **XSS** que injeta um script malicioso na página pode roubar o token e usá-lo em outra máquina.

### localStorage

Igual ao sessionStorage, mas os dados persistem depois que o browser fecha. É compartilhado entre todas as abas do mesmo domínio.

O problema de segurança é o mesmo, agravado pelo fato de que o token fica armazenado permanentemente.

### Cookie com HttpOnly (o que este projeto usa)

O servidor envia o token via `Set-Cookie` com a flag `HttpOnly`. Essa flag instrui o browser a nunca expor o valor via JavaScript. `document.cookie` não mostra cookies HttpOnly.

O browser gerencia o cookie automaticamente: armazena na resposta do login e envia em todas as requisições subsequentes ao mesmo domínio, sem nenhum código JavaScript do lado do frontend.

```http
Set-Cookie: authToken=eyJ...; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600
```

Vantagem: XSS não consegue roubar o token porque JavaScript não tem acesso a ele.

Desvantagem: requer atenção ao CSRF (Cross-Site Request Forgery). Como o browser envia o cookie automaticamente, uma página maliciosa em outro domínio poderia disparar requisições autenticadas. A flag `SameSite=Strict` resolve isso: instrui o browser a não enviar o cookie em requisições originadas de outros domínios.

Segurança é sobre camadas. Cookie HttpOnly com `SameSite=Strict` é a abordagem mais robusta para a maioria dos casos, mas não é invulnerável. A configuração correta do CORS, a validação dos inputs, o tempo de expiração do token e a rotação das chaves formam juntos a postura de segurança da aplicação. Cada camada compensa as fraquezas das outras.

### Por que o JavaScript não pode limpar um cookie HttpOnly

No logout, o frontend não pode simplesmente fazer `document.cookie = 'authToken=; expires=0'` porque `document.cookie` ignora cookies HttpOnly. A única forma de remover o cookie é o servidor responder com `Set-Cookie: authToken=; Max-Age=0`, que instrui o browser a deletá-lo. Por isso o endpoint `/usuarios/logout` existe no backend.

---

## O Fluxo Completo

### 1. Login

```
Cliente  →  POST /usuarios/login  { email, senha }

Servidor →  valida credenciais com BCrypt.matches()
         →  gera JWT assinado com HMAC-SHA256
         →  Set-Cookie: authToken=eyJ...; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600

Browser  →  armazena o cookie automaticamente
Resposta →  { userId, nome, email }   (o token não vai no body)
```

### 2. Requisições Autenticadas

```
Browser  →  GET /usuarios
            Cookie: authToken=eyJ...   (enviado automaticamente, sem código JS)

Servidor →  AutenticacaoFilter extrai o token do cookie
         →  JJWT verifica assinatura e expiração
         →  extrai email do payload
         →  registra autenticação no SecurityContext

Resposta →  200 OK  [ lista de usuários ]
```

### 3. Logout

```
Browser  →  POST /usuarios/logout
            Cookie: authToken=eyJ...

Servidor →  Set-Cookie: authToken=; HttpOnly; Max-Age=0
Browser  →  deleta o cookie

Obs: o token JWT ainda é tecnicamente válido até o campo exp expirar.
     Por isso tokens de curta duração (15-60 min) são importantes.
```

### 4. Token Inválido ou Expirado

```
Browser  →  GET /usuarios
            Cookie: authToken=eyJ...EXPIRADO

Servidor →  JJWT lança ExpiredJwtException
         →  AutenticacaoEntryPoint responde com 401 Unauthorized
```

### Como o Código Implementa Isso

**Gerando o token** (`GerenciadorTokenJwt.java`):
```java
return Jwts.builder()
    .subject(authentication.getName())    // claim "sub": email do usuário
    .claim("authorities", authorities)    // roles do usuário
    .issuedAt(new Date())                 // claim "iat"
    .expiration(new Date(now + validity)) // claim "exp"
    .signWith(parseSecret())              // HMAC-SHA256
    .compact();
```

**Enviando o token via cookie** (`UsuarioController.java`):
```java
ResponseCookie cookie = ResponseCookie.from("authToken", token)
    .httpOnly(true)       // JavaScript não lê
    .secure(false)        // true em produção (exige HTTPS)
    .sameSite("Strict")   // bloqueia envio cross-site
    .path("/")
    .maxAge(Duration.ofSeconds(jwtValidity))
    .build();

response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
```

**Extraindo o token na requisição** (`AutenticacaoFilter.java`):
```java
// Tenta extrair do cookie primeiro, com fallback para Authorization: Bearer
String token = extrairDosCookies(request);
if (token == null) {
    token = extrairDoHeader(request);
}
```

---

## O que Esta Implementação Resolve

| Problema                              | Resolve?          | Como                                                                      |
|---------------------------------------|-------------------|---------------------------------------------------------------------------|
| Senha em texto puro no banco          | Sim               | `passwordEncoder.encode()` em `UsuarioService.criar()`                    |
| Rainbow Tables                        | Sim               | BCrypt gera salt único automaticamente                                    |
| Hashes rápidos (MD5/SHA-1)            | Sim               | BCrypt cost=10, ~100ms por hash                                           |
| Brute force com GPU                   | Parcialmente      | BCrypt é CPU-hard; Argon2 seria mais resistente (ver branch argon2)       |
| Vazamento total do banco              | Parcialmente      | BCrypt dificulta; Pepper completaria a proteção (ver branch argon2)       |
| Token adulterado pelo cliente         | Sim               | Assinatura HMAC-SHA256 em `GerenciadorTokenJwt`                           |
| Token expirado aceito                 | Sim               | JJWT valida claim `exp`                                                   |
| Token roubável via XSS                | Sim               | Cookie HttpOnly: JavaScript não acessa o token                            |
| CSRF via cookie                       | Sim               | `SameSite=Strict` bloqueia envio cross-site                               |
| Chave secreta exposta no repositório  | Não (intencional) | Em produção: `jwt.secret=${JWT_SECRET}` via variável de ambiente          |
| Tokens sem possibilidade de revogação | Não (intencional) | Refresh Token e blacklist ficam fora do escopo didático                   |

---

## Como Rodar

Requisitos: Java 21+ e Maven 3.8+

```bash
./mvnw spring-boot:run
```

API disponível em `http://localhost:8080`.

Usuário de teste pré-cadastrado:

| Email         | Senha  |
|---------------|--------|
| john@doe.com  | 123456 |

### Interfaces de desenvolvimento

| Interface   | URL                                   |
|-------------|---------------------------------------|
| Swagger UI  | http://localhost:8080/swagger-ui.html |
| Console H2  | http://localhost:8080/h2-console      |
| H2 JDBC URL | `jdbc:h2:mem:teste-security`          |

---

## Endpoints

### POST /usuarios/login

```bash
curl -c cookies.txt -X POST http://localhost:8080/usuarios/login \
  -H "Content-Type: application/json" \
  -d '{"email": "john@doe.com", "senha": "123456"}'
```

Resposta `200 OK`:
```json
{ "userId": 1, "nome": "John Doe", "email": "john@doe.com" }
```

O token JWT vai no `Set-Cookie` da resposta, não no body.

### GET /usuarios (requer autenticação)

```bash
curl -b cookies.txt http://localhost:8080/usuarios
```

O `-b cookies.txt` instrui o curl a enviar os cookies salvos, simulando o comportamento do browser.

### POST /usuarios (requer autenticação)

```bash
curl -b cookies.txt -X POST http://localhost:8080/usuarios \
  -H "Content-Type: application/json" \
  -d '{"nome": "Maria Silva", "email": "maria@email.com", "senha": "minhasenha"}'
```

### POST /usuarios/logout

```bash
curl -b cookies.txt -c cookies.txt -X POST http://localhost:8080/usuarios/logout
```

---

## O que Não Fazer em Produção

| Prática neste projeto (didática) | O que fazer em produção                         |
|----------------------------------|-------------------------------------------------|
| `jwt.secret` fixo no .properties | Variável de ambiente `${JWT_SECRET}`            |
| H2 in-memory                     | PostgreSQL ou MySQL com backup                  |
| `spring.h2.console.enabled=true` | Desativar em produção                           |
| `secure(false)` no cookie        | `secure(true)`, exige HTTPS                     |
| BCrypt cost=10                   | cost=12 ou 13 conforme o hardware               |
| Sem pepper                       | Pepper via variável de ambiente                 |
| Token de 1 hora sem refresh      | Token curto (15 min) + Refresh Token revogável  |
| CORS aberto                      | `setAllowedOrigins(List.of("https://..."))` explícito |

---

## Dicas e Cuidados

### Sobre Senhas

Nunca reinvente o algoritmo de hash. Usar `SHA-256(senha + salt)` manualmente parece razoável, mas você não consegue controlar a velocidade do cálculo. Use sempre uma biblioteca consolidada: BCrypt, Argon2 ou scrypt.

Ajuste o custo conforme o hardware evolui. O hash deve levar entre 100ms e 500ms no servidor. Se estiver muito rápido, aumente o cost.

Salt não é secreto, pepper é. Salt pode ficar no banco sem problema, sua função é apenas unicidade. Pepper deve ficar fora do banco em variável de ambiente, porque sem ele os hashes são inúteis mesmo com o banco exposto.

Nunca logue senhas. Nem em modo debug. Nem "só por enquanto". Logs ficam em arquivos, arquivos ficam em backups, backups ficam em storage externo.

Cuidado com comparação de timing. `senha.equals(outraSenha)` retorna `false` mais rápido quando as strings diferem nos primeiros caracteres, o que permite ataques de timing. `BCryptPasswordEncoder.matches()` já resolve isso internamente.

### Sobre JWT

Mantenha o tempo de expiração curto. Uma hora é o máximo razoável para um access token. Em produção, prefira 15 minutos com Refresh Token para renovação silenciosa.

Não coloque dados sensíveis no payload. O payload é Base64, não é criptografia. Email, userId e roles são adequados. Número de cartão, CPF e outros dados pessoais: nunca.

A chave secreta é o ponto mais crítico. Se `jwt.secret` vazar, qualquer um pode forjar tokens com qualquer identidade. Use no mínimo 256 bits (32 bytes) para HS256, mantenha em variável de ambiente e considere rotação periódica em sistemas críticos.

JWT não tem logout real. Ao deslogar, o browser descarta o cookie, mas o token continua tecnicamente válido até expirar. Estratégias: tokens curtos, blacklist de tokens revogados (perde o benefício stateless) ou Refresh Token revogável no servidor.

### Sobre Segurança em Geral

Segurança não é um recurso que você liga ou desliga. É uma soma de camadas onde cada uma compensa as fraquezas das outras. Cookie HttpOnly protege contra XSS, mas precisa de SameSite para CSRF. BCrypt protege o banco, mas pepper protege contra vazamento do banco. JWT elimina estado no servidor, mas exige tokens curtos e rotação de chaves.

Não existe sistema invulnerável. O objetivo é tornar um ataque suficientemente caro em tempo, recursos e conhecimento para que não valha o esforço. Cada decisão de segurança é um tradeoff entre proteção, usabilidade e custo operacional.

---

## Sinais de Problema

- Login retornando `403 Forbidden` (deveria ser `401 Unauthorized`)
- Token JWT com validade de 30 dias ou mais
- Chave JWT commitada no repositório
- Senhas sendo logadas em qualquer nível de log
- CORS configurado com `*` em produção
- Console H2 exposto em produção
- Endpoint de login sem rate limiting

---

## Outras Versões

Esta é a versão principal com Spring Boot 4. Para variações desta implementação:

- [`spring-3.x.x`](../../tree/spring-3.x.x): mesma implementação para Spring Boot 3.4.x / Spring Security 6. A diferença está no uso de `AntPathRequestMatcher` para definir URLs públicas, que foi removido no Spring Security 7.

- [`feature/argon2-pepper`](../../tree/feature/argon2-pepper): substitui BCrypt por Argon2id e adiciona Pepper via HMAC-SHA256. Recomendado para sistemas que precisam de maior resistência a ataques com GPU e proteção em cenários de vazamento total do banco.

---

*Projeto educacional | SPTech | Spring Boot 4.0.5 + Spring Security 7 + JJWT 0.12.6*
