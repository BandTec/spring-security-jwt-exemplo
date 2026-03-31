# Da Senha ao Token — Autenticação JWT com Spring Boot 4

> **Branch:** `feature/argon2-pepper` — Argon2id + Pepper | Spring Boot 4.0.5 | Java 21 LTS | JJWT 0.12.6
>
> Branch base: [`main`](../../tree/main) (BCrypt simples, sem pepper)
>
> Para a versão Spring Boot 3.x, veja a branch [`spring-3.x.x`](../../tree/spring-3.x.x)

---

## O que esta branch adiciona

Esta branch implementa as duas camadas de segurança marcadas como "não implementado (intencional)" na `main`:

| Proteção        | `main`          | `feature/argon2-pepper`                      |
|-----------------|-----------------|----------------------------------------------|
| Algoritmo       | BCrypt (cost=10) | **Argon2id** (memory-hard, 64 MB/hash)       |
| Pepper          | Não             | **Sim** — HMAC-SHA256(senha, pepper)         |
| Dado no banco   | Hash BCrypt     | Hash Argon2id (pepper **não** fica no banco) |

### Arquivos novos/alterados

| Arquivo | O que mudou |
|---------|-------------|
| `config/PepperPasswordEncoder.java` | Novo — aplica HMAC+pepper antes do Argon2 |
| `config/DataInitializer.java` | Novo — cria usuário de teste via código (hash gerado em runtime) |
| `config/SecurityConfiguracao.java` | `BCryptPasswordEncoder` → `PepperPasswordEncoder` |
| `config/AutenticacaoProvider.java` | Javadoc atualizado |
| `resources/application.properties` | Adicionada propriedade `security.pepper` |
| `resources/data.sql` | Esvaziado (substituído por `DataInitializer`) |
| `pom.xml` | Adicionado `bcprov-jdk18on` (BouncyCastle, necessário para Argon2) |

### Por que DataInitializer em vez de data.sql?

O hash do usuário de teste depende do `PasswordEncoder` ativo. Com Argon2+pepper,
o hash muda a cada execução (salt aleatório) e não pode ser pré-computado em SQL.
O `DataInitializer` usa o bean `PasswordEncoder` injetado para gerar o hash correto
na inicialização — funciona com qualquer encoder sem alterar o SQL.

### Como configurar em produção

```bash
# Variáveis de ambiente obrigatórias
export JWT_SECRET=<base64 de pelo menos 32 bytes>
export SECURITY_PEPPER=<string aleatória longa, ex: openssl rand -base64 48>
```

> **Nunca** use os valores padrão (`dev-pepper-nao-usar-em-producao...`) em produção.

---

## A História das Senhas

Para entender por que usamos BCrypt, Salt, Pepper e JWT, precisamos começar do início.

### Anos 90: Texto Puro (Plaintext)

Os primeiros sistemas simplesmente gravavam a senha diretamente no banco de dados:

```sql
-- Anos 90 — Não faça isso. Nunca. Em hipótese alguma.
INSERT INTO usuario (email, senha) VALUES ('john@doe.com', '123456');
```

O problema era óbvio: qualquer pessoa com acesso ao banco — um DBA malicioso, um backup vazado, um SQL Injection — via todas as senhas de todos os usuários, em texto claro.

Quando o Yahoo teve [3 bilhões de contas vazadas em 2013](https://en.wikipedia.org/wiki/Yahoo!_data_breaches), grande parte das senhas estava em plaintext ou em formatos equivalentemente frágeis.

---

### MD5 e SHA-1: A Ilusão de Segurança

A solução natural foi usar funções de hash. Em vez de gravar `123456`, gravava-se o hash:

```
MD5("123456")   = "e10adc3949ba59abbe56e057f20f883e"
SHA1("123456")  = "7c4a8d09ca3762af61e59520943dc26494f8941b"
```

Parecia seguro. Afinal, hash não tem inversa, certo?

O problema: hash é **determinístico**. A mesma entrada sempre produz a mesma saída. Isso abriu caminho para as **Rainbow Tables**.

---

### Rainbow Tables: Atacando o Hash

Rainbow Table é uma tabela precomputada com milhões (ou bilhões) de pares `hash → senha`:

```
e10adc3949ba59abbe56e057f20f883e  →  123456
5f4dcc3b5aa765d61d8327deb882cf99  →  password
827ccb0eea8a706c4c34a16891f84e7b  →  12345678
...
```

Com essa tabela em mãos, o atacante não precisa "quebrar" o hash — só precisa fazer uma consulta. Sites como [CrackStation](https://crackstation.net) e [WeakPass](https://weakpass.com) têm bilhões de hashes precomputados disponíveis gratuitamente.

```bash
# Teste você mesmo — cole esse hash no CrackStation:
e10adc3949ba59abbe56e057f20f883e
# Resultado imediato: "123456"
```

Resultado: MD5 e SHA-1 são **inúteis** para armazenar senhas. O NIST [desaconselha seu uso](https://csrc.nist.gov/projects/hash-functions) para autenticação desde 2005.

---

### Salt: Quebrando as Rainbow Tables

A resposta ao problema das Rainbow Tables é o **Salt**: um valor aleatório e único gerado para cada usuário, concatenado com a senha antes do hash.

```
salt_usuario_1 = "xK9p$2mR"
hash = MD5("xK9p$2mR" + "123456") = "3c59dc048e8850243be8079a5c74d079"

salt_usuario_2 = "7bQw#1nZ"
hash = MD5("7bQw#1nZ" + "123456") = "a2c28d7e6f1b3904d8f752c9e1470e2c"
```

Dois usuários com a mesma senha `123456` têm hashes completamente diferentes. As Rainbow Tables preexistentes tornam-se **inúteis** — seria necessário gerar uma tabela nova para cada salt possível, o que é computacionalmente inviável.

O salt não é secreto — fica armazenado junto com o hash no banco de dados. O que o torna efetivo é a unicidade: o atacante precisaria montar uma Rainbow Table específica para cada usuário individualmente.

---

### O Problema dos Hashes Rápidos

Mesmo com salt, MD5 e SHA-256 têm um problema fundamental: são **rápidos demais**.

Uma GPU moderna consegue calcular:

| Algoritmo  | Velocidade estimada (GPU)         |
|------------|-----------------------------------|
| MD5        | ~50 **bilhões** de hashes/segundo |
| SHA-256    | ~10 **bilhões** de hashes/segundo |
| BCrypt (cost 10) | ~20.000 hashes/segundo      |
| Argon2id   | Configurável (proposital)         |

Com MD5, um atacante que obtém o banco de dados pode tentar 50 bilhões de senhas por segundo. Uma senha de 8 caracteres alfanuméricos tem ~218 trilhões de combinações — quebrável em menos de 1 hora com hardware dedicado.

---

### BCrypt: Lento por Design

BCrypt foi criado em 1999 especificamente para armazenar senhas. Sua característica central é o **fator de custo** (cost factor), que controla quantas rodadas de processamento são executadas:

```
custo = 10  →  2^10  = 1.024 rodadas  →  ~100ms por hash
custo = 12  →  2^12  = 4.096 rodadas  →  ~400ms por hash
custo = 14  →  2^14  = 16.384 rodadas →  ~1,6s por hash
```

O fator de custo é **ajustável conforme o hardware evolui**. Em 2010, cost=10 era seguro. Em 2025, cost=12 ou 13 é mais adequado. O BCrypt acompanha o crescimento computacional.

#### Anatomia de um hash BCrypt

O usuário de teste deste projeto tem sua senha armazenada como:

```
$2a$10$0/TKTGxdREbWaWjWYhwf6e9P1fPOAMMNqEnZgOG95jnSkHSfkkIrC
```

Cada parte tem um significado:

```
$2a$        → versão do BCrypt (2a = versão atual recomendada)
$10$        → fator de custo (cost=10, ou seja, 2^10 = 1024 iterações)
0/TKTGxdREbWaWjWYhwf6e  → salt (22 caracteres Base64 = 16 bytes aleatórios)
9P1fPOAMMNqEnZgOG95jnSkHSfkkIrC → hash da senha + salt (31 caracteres)
```

O salt está embutido no próprio hash — não é necessário armazená-lo separadamente.

Como o Spring Boot utiliza BCrypt neste projeto:

```java
// SecurityConfiguracao.java — define o encoder como bean
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(); // cost padrão = 10
}

// UsuarioService.java — ao criar usuário, a senha é hasheada antes de salvar
String senhaCriptografada = passwordEncoder.encode(novoUsuario.getSenha());
novoUsuario.setSenha(senhaCriptografada);

// AutenticacaoProvider.java — ao fazer login, compara senha digitada com hash no banco
if (this.passwordEncoder.matches(senhaDigitada, hashNoBanco)) {
    // autenticado!
}
```

O método `matches()` extrai o salt do próprio hash, recalcula e compara — você nunca precisa gerenciar o salt manualmente.

---

### Argon2: Memory-Hard

BCrypt é **CPU-hard**: difícil de paralelizar porque exige muitas iterações de CPU. Mas GPUs modernas têm milhares de núcleos — mesmo lento, é possível rodar muitas instâncias de BCrypt em paralelo.

**Argon2** (vencedor da Password Hashing Competition em 2015) adiciona o conceito de **memory-hard**: além de CPU, o algoritmo exige grande quantidade de RAM.

```
Argon2id (configuração recomendada):
  - Memória: 64 MB por hash
  - Iterações: 3
  - Paralelismo: 4 threads
```

Uma GPU com 8 GB de VRAM consegue rodar apenas ~125 instâncias simultâneas de Argon2 com 64 MB cada. Isso torna ataques com GPU essencialmente inviável.

O Spring Security suporta Argon2 nativamente:

```java
// Alternativa ao BCrypt para maior segurança (requer spring-security-crypto)
@Bean
public PasswordEncoder passwordEncoder() {
    return new Argon2PasswordEncoder(
        16,   // tamanho do salt em bytes
        32,   // tamanho do hash em bytes
        1,    // paralelismo
        65536,// memória em KB (64 MB)
        3     // iterações
    );
}
```

> Para este projeto educacional usamos BCrypt (mais simples de entender e configurar).
> Em produção, Argon2id é a escolha mais robusta segundo o [OWASP](https://chefsec.io/owasp-password-storage-cheat-sheet).

---

### Pepper: A Camada que o Banco Não Conhece

Salt resolve as Rainbow Tables, e BCrypt/Argon2 torna o brute force lento. Mas existe ainda um cenário crítico: **vazamento completo do banco de dados**.

Se o atacante tem o banco, ele tem os salts e os hashes. Com tempo suficiente, pode tentar senhas por brute force (devagar, mas possível para senhas fracas).

O **Pepper** é uma chave secreta global da aplicação que é concatenada com a senha antes do hash — mas que **não fica no banco de dados**:

```
hash = BCrypt(senha + salt + pepper)

Onde:
  senha  = "123456"          (fornecida pelo usuário)
  salt   = "xK9p$2mR..."    (gerado automaticamente, salvo no banco)
  pepper = "chave-secreta"   (variável de ambiente, NUNCA no banco)
```

Resultado: mesmo com o banco vazado, o atacante não consegue calcular os hashes sem o pepper. Segundo estimativas da comunidade de segurança, a combinação Salt + Pepper + BCrypt/Argon2 reduz a efetividade de ataques de brute force em **mais de 99%** em cenários de vazamento de banco.

```bash
# application.properties (pepper como variável de ambiente)
security.pepper=${SENHA_PEPPER:valorPadraoDev}
```

> Este projeto não implementa pepper para manter o código simples e focado no JWT.
> Em produção, considere adicionar pepper como camada extra.

---

### Resumo: A Evolução da Segurança de Senhas

```
Anos 90      Plaintext          Senha visível diretamente no banco
             ↓
Anos 2000    MD5 / SHA-1        Hash determinístico, vulnerável a Rainbow Tables
             ↓
Mid-2000s    Salt + SHA-256     Derrota Rainbow Tables, mas ainda rápido demais
             ↓
1999-hoje    BCrypt             Lento por design (CPU-hard), salt embutido, cost ajustável
             ↓
2015-hoje    Argon2             Memory-hard, resistente a GPU, recomendado pelo OWASP
             ↓
Combinado    Salt+Pepper+Argon2 Prática mais robusta disponível atualmente
```

---

## O que Esta Implementação Resolve (e o que Deixa para Produção)

Esta tabela mostra explicitamente como cada problema discutido acima é endereçado — ou deixado como extensão consciente — neste projeto:

| Problema / Ameaça                    | Esta implementação resolve?  | Como / Onde no código                                                                 |
|--------------------------------------|------------------------------|---------------------------------------------------------------------------------------|
| Senha em texto puro no banco         | **Sim**                      | `UsuarioService.criar()` chama `passwordEncoder.encode()` antes de salvar             |
| Rainbow Tables                       | **Sim**                      | BCrypt gera salt automaticamente — cada hash é único mesmo para senhas iguais         |
| Hashes rápidos (MD5/SHA-1)           | **Sim**                      | `BCryptPasswordEncoder` (cost=10) leva ~100ms por hash                                |
| Brute force com GPU                  | **Sim**                      | Argon2id é memory-hard — exige ~64 MB de RAM por hash, inviabilizando ataques com GPU |
| Vazamento total do banco             | **Sim**                      | Argon2id + Pepper: sem o pepper (variável de ambiente), os hashes são inúteis         |
| Sessão stateful / problemas de escala| **Sim**                      | JWT stateless — servidor não guarda estado; qualquer instância valida o token         |
| Token adulterado pelo cliente        | **Sim**                      | Assinatura HMAC-SHA256 em `GerenciadorTokenJwt` — alteração invalida a signature     |
| Token expirado aceito                | **Sim**                      | JJWT valida claim `exp` automaticamente; `AutenticacaoFilter` trata `ExpiredJwtException` |
| Chave secreta exposta no repositório | **Não (intencional)**        | Em produção: `jwt.secret=${JWT_SECRET}` via variável de ambiente                     |
| Pepper para proteção extra           | **Sim**                      | `PepperPasswordEncoder` aplica HMAC-SHA256(senha, pepper) antes do Argon2            |
| Tokens de longa duração sem saída    | **Não (intencional)**        | Refresh Token e revogação ficam fora do escopo didático inicial                      |

---

## E Depois do Login? JWT

Agora que sabemos como armazenar senhas com segurança, surge uma nova questão:

> **O usuário já se autenticou. Como provamos isso nas próximas requisições sem pedir a senha de novo?**

A abordagem clássica era a **sessão HTTP**: o servidor guarda na memória que o usuário X está autenticado e envia um cookie de sessão para o browser. Funciona — mas não escala bem quando você tem múltiplos servidores (qual deles tem a sessão?).

A solução moderna para APIs REST envolve tokens. Mas nem todo token é igual.

---

### Token Opaco vs. Token Auto-contido (JWT)

Existem dois modelos fundamentais de token de autenticação. Entender a diferença é essencial para escolher a abordagem certa.

#### Token Opaco

Um token opaco é apenas uma string aleatória que não carrega informação alguma por si só:

```
a3f7b2c1-9e4d-4a8b-bc12-1f8e3d5a6c9f
```

O servidor precisa consultar um banco de dados (ou cache) para descobrir a quem esse token pertence:

```
Requisição → Token → Consulta BD → "esse token pertence ao usuário 42, que tem role ADMIN"
```

- **Vantagem**: pode ser **revogado instantaneamente** (basta deletar do BD)
- **Desvantagem**: toda requisição gera uma consulta ao banco → gargalo de escala

#### Token Auto-contido (JWT)

Um JWT carrega as informações diretamente no seu payload (codificado em Base64):

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huQGRvZS5jb20iLCJleHAiOjE3NDMzNTQwMDB9.xyz
```

Decodificando o payload:
```json
{
  "sub": "john@doe.com",
  "authorities": "",
  "iat": 1743350400,
  "exp": 1743354000
}
```

O servidor lê quem é o usuário **diretamente do token**, sem consultar banco de dados.

- **Vantagem**: stateless — qualquer servidor valida sem consultar BD
- **Desvantagem**: **não pode ser revogado antes da expiração** — se o token foi emitido, é válido até expirar

#### A Implicação Crítica do JWT

Como o JWT não pode ser revogado, o servidor não tem como "deslogar" um usuário remotamente. Se um token for comprometido (roubado), o atacante pode usá-lo até expirar.

A mitigação é usar **tokens de curta duração**:

```
Token opaco:    pode durar dias/semanas (revogável)
JWT típico:     15 min a 1 hora (curto para limitar dano)
JWT + Refresh:  access token curto (15 min) + refresh token longo (7 dias, opaco e revogável)
```

Neste projeto usamos JWT simples com 1 hora de validade — adequado para fins educacionais. Em produção, o padrão mais robusto é JWT de curta duração combinado com um Refresh Token opaco armazenado no servidor.

| Característica         | Token Opaco               | JWT (auto-contido)               |
|------------------------|---------------------------|----------------------------------|
| Conteúdo               | String aleatória opaca    | Payload legível (Base64)         |
| Validação              | Consulta ao banco         | Verifica assinatura local        |
| Revogação              | Imediata (delete no BD)   | Impossível antes de expirar      |
| Escala horizontal      | Requer BD compartilhado   | Qualquer servidor valida         |
| Dados do usuário       | Só no servidor            | No próprio token                 |
| Uso típico             | Session tokens, API keys  | APIs REST stateless              |

---

### O que é um JWT

JWT é um token autocontido e assinado digitalmente que o próprio cliente carrega. O servidor não armazena nada — ele apenas verifica a assinatura.

```
HEADER.PAYLOAD.SIGNATURE
  ↑          ↑           ↑
algoritmo  dados do   prova de
           usuário    autenticidade
```

Cada parte é codificada em Base64 (não criptografada — qualquer um pode ler o payload):

```json
// HEADER (decodificado)
{ "alg": "HS256", "typ": "JWT" }

// PAYLOAD (decodificado) — claims do token
{
  "sub": "john@doe.com",          // subject: quem é o usuário
  "authorities": "",              // roles/perfis do usuário
  "iat": 1743350400,              // issued at: quando foi emitido (Unix timestamp)
  "exp": 1743354000               // expiration: quando expira
}

// SIGNATURE
HMAC-SHA256(base64(header) + "." + base64(payload), chave-secreta)
```

> **Importante:** o payload é apenas Base64, não é criptografado. Não coloque senhas, números de cartão ou dados sensíveis no token. Use apenas o necessário para identificar o usuário.

A **assinatura** é o que garante a segurança: só o servidor conhece a chave secreta. Se alguém modificar o payload (ex: mudar o email ou adicionar uma role), a assinatura não vai bater e o token será rejeitado.

### Fluxo Completo

```
1. LOGIN
   Cliente → POST /usuarios/login { email, senha }
   Servidor → valida credenciais (BCrypt.matches)
            → gera token JWT assinado com HS256
   Resposta → { "token": "eyJ...", "nome": "John Doe" }

2. REQUISIÇÕES AUTENTICADAS
   Cliente → GET /usuarios
             Authorization: Bearer eyJ...
   Servidor → AutenticacaoFilter extrai o token
            → JJWT verifica assinatura e expiração
            → extrai email do payload
            → autentica o usuário no SecurityContext
   Resposta → 200 OK [ lista de usuários ]

3. TOKEN INVÁLIDO OU EXPIRADO
   Cliente → GET /usuarios
             Authorization: Bearer eyJ...EXPIRADO
   Servidor → JJWT lança ExpiredJwtException
            → 401 Unauthorized
```

### Como o Código Implementa Isso

**Gerando o token no login** (`GerenciadorTokenJwt.java`):
```java
return Jwts.builder()
    .subject(authentication.getName())        // claim "sub": email do usuário
    .claim("authorities", authorities)        // claim customizado: roles
    .issuedAt(new Date())                     // claim "iat": agora
    .expiration(new Date(now + validity))     // claim "exp": daqui a N segundos
    .signWith(parseSecret())                  // assina com HMAC-SHA256
    .compact();                               // serializa para String
```

**Validando a cada requisição** (`AutenticacaoFilter.java`):
```java
// Extrai "Bearer <token>" do header Authorization
jwtToken = requestTokenHeader.substring(7);

// JJWT valida assinatura e expiração automaticamente ao parsear
username = jwtTokenManager.getUsernameFromToken(jwtToken);

// Registra o usuário como autenticado no contexto da thread
SecurityContextHolder.getContext().setAuthentication(autenticacao);
```

**A chave secreta** (`application.properties`):
```properties
# Mínimo 256 bits (32 bytes) para HMAC-SHA256
# Em produção: jwt.secret=${JWT_SECRET}
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

API disponível em `http://localhost:8080`

**Usuário de teste pré-cadastrado:**

| Email         | Senha  | Hash BCrypt armazenado                                          |
|---------------|--------|-----------------------------------------------------------------|
| john@doe.com  | 123456 | `$2a$10$0/TKTGxdREbWaWjWYhwf6e9P1fPOAMMNqEnZgOG95jnSkHSfkkIrC` |

Decodificando o hash: `$2a$` (versão BCrypt) + `$10$` (cost=10) + salt (22 chars) + hash (31 chars).

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

### POST `/usuarios` — Criar usuário (requer token)

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
| H2 usuário/senha | `admin` / `admin`                      |

---

## O que NÃO Fazer em Produção

| Prática deste projeto (didática) | Versão para produção                          |
|----------------------------------|-----------------------------------------------|
| `jwt.secret` no .properties      | Variável de ambiente: `${JWT_SECRET}`         |
| H2 in-memory                     | PostgreSQL/MySQL com backup                   |
| `spring.h2.console.enabled=true` | `false` em produção                           |
| CORS com `*` (qualquer origem)   | `setAllowedOrigins(List.of("https://..."))`   |
| BCrypt cost=10                   | cost=12 ou 13 (ajuste conforme o hardware)    |
| Sem pepper                       | Adicionar pepper via variável de ambiente     |
| Token de 1 hora sem refresh      | Token curto (15 min) + Refresh Token          |

---

## Dependências

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

## Dicas e Cuidados

### Sobre Senhas

**Nunca reinvente o algoritmo de hash.**
Usar `SHA-256(senha + salt)` manualmente parece razoável mas é errado — você não consegue controlar a velocidade. Sempre use uma biblioteca consolidada: BCrypt, Argon2 ou scrypt.

**Ajuste o cost factor conforme o hardware evolui.**
BCrypt com cost=10 era adequado em 2010. Verifique periodicamente: o hash deve levar entre 100ms e 500ms no seu servidor. Se estiver muito rápido, aumente o cost.

**Salt não é secret, pepper é.**
Salt pode ficar no banco sem problema — sua função é apenas unicidade. Pepper deve ficar *fora* do banco (variável de ambiente), pois seu valor é que torna o hash inutilizável sem acesso ao servidor.

**Nunca logue senhas.**
Nem em modo debug. Nem "só por enquanto". Logs ficam em arquivos, que ficam em backups, que ficam em S3, que ficam...

**Cuidado com comparação de timing.**
`senha.equals(outraSenha)` retorna `false` mais rápido quando as strings diferem nos primeiros caracteres — isso permite ataques de timing. `BCryptPasswordEncoder.matches()` já resolve isso internamente.

---

### Sobre JWT

**Mantenha o tempo de expiração curto.**
1 hora é o máximo razoável para um access token. Prefira 15 minutos em produção e use Refresh Token para renovar silenciosamente no frontend.

**Não coloque dados sensíveis no payload.**
O payload é apenas Base64 — qualquer pessoa com o token pode decodificar e ler o conteúdo. `email`, `userId`, `roles` são ok. Números de cartão, CPF, dados pessoais sensíveis: nunca.

**A chave secreta é o calcanhar de Aquiles.**
Se `jwt.secret` vazar, todos os tokens emitidos por aquela chave podem ser forjados. Use:
- Chave de no mínimo 256 bits (32 bytes) para HS256
- Variável de ambiente em produção: `${JWT_SECRET}`
- Troca periódica da chave (key rotation) em sistemas críticos

**JWT não tem logout real — planeje para isso.**
Ao "deslogar", o frontend descarta o token, mas ele permanece válido até expirar. Estratégias:
- Tokens muito curtos (15 min) minimizam a janela de risco
- Blacklist de tokens (perde o benefício stateless)
- Refresh Token revogável no servidor (híbrido recomendado)

**Prefira `HttpOnly` cookies em vez de `localStorage`.**
`localStorage` é acessível por qualquer JavaScript na página — XSS pode roubar o token.
Cookies `HttpOnly` são inacessíveis ao JavaScript e podem ser configurados com `SameSite=Strict` para mitigar CSRF.

```http
Set-Cookie: authToken=eyJ...; HttpOnly; Secure; SameSite=Strict; Path=/
```

**Valide sempre no servidor — nunca confie só no cliente.**
O frontend pode esconder um botão, mas o endpoint protegido deve sempre verificar o token e as permissões. "Security through obscurity" não é segurança.

---

### Red Flags — Sinais de que algo está errado

- Endpoint de login retornando `403 Forbidden` (deveria ser `401 Unauthorized`)
- Token JWT com validade de 30 dias ou mais
- Secret JWT commitado no repositório Git (use `git-secrets` para prevenir)
- Senhas sendo logadas em qualquer nível de log
- CORS configurado com `*` em produção
- H2 console exposto em produção
- Endpoint de login sem rate limiting (sujeito a brute force)

---

*Projeto educacional — SPTech | `main`: Spring Boot 4.0.5 + Spring Security 7 + JJWT 0.12.6*
