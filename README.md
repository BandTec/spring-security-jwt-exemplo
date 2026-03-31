# Da Senha ao Token: Autenticação JWT com Spring Boot 3

> **Branch:** `spring-3.x.x` | Spring Boot 3.4.4 | Java 21 | JJWT 0.12.6
>
> Para o contexto completo sobre senhas, hashing, JWT e decisões de segurança, leia o README da branch [`main`](../../tree/main).

---

## O que esta branch é

Esta branch contém a mesma implementação da branch `main`, adaptada para Spring Boot 3.4.x e Spring Security 6. A lógica de negócio, a estrutura do projeto e as decisões de segurança são idênticas.

---

## O que muda em relação à main

### Spring Boot 3.4.4 e Spring Security 6

A diferença mais visível está na configuração das URLs públicas em `SecurityConfiguracao.java`.

**Spring Security 6 (esta branch):** usa `AntPathRequestMatcher` para definir os padrões de URL:

```java
private static final AntPathRequestMatcher[] URLS_PERMITIDAS = {
    new AntPathRequestMatcher("/swagger-ui/**"),
    new AntPathRequestMatcher("/usuarios/login/**"),
    new AntPathRequestMatcher("/h2-console/**"),
    // ...
};

// E na configuração do filtro:
.authorizeHttpRequests(authorize -> authorize
    .requestMatchers(URLS_PERMITIDAS).permitAll()
    .anyRequest().authenticated()
)
```

**Spring Security 7 (branch main):** `AntPathRequestMatcher` foi removido. As strings de padrão são passadas diretamente:

```java
private static final String[] URLS_PERMITIDAS = {
    "/swagger-ui/**",
    "/usuarios/login/**",
    "/h2-console/**",
    // ...
};

// Na configuração do filtro, exatamente igual:
.authorizeHttpRequests(authorize -> authorize
    .requestMatchers(URLS_PERMITIDAS).permitAll()
    .anyRequest().authenticated()
)
```

Essa mudança é apenas de forma. O comportamento é o mesmo.

### Versões das dependências

| Dependência      | spring-3.x.x | main         |
|------------------|--------------|--------------|
| Spring Boot      | 3.4.4        | 4.0.5        |
| Spring Security  | 6.x          | 7.x          |
| Java             | 21           | 21           |
| JJWT             | 0.12.6       | 0.12.6       |

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

## Outras Versões

- [`main`](../../tree/main): Spring Boot 4 com contexto completo e explicações detalhadas.
- [`feature/argon2-pepper`](../../tree/feature/argon2-pepper): Argon2id + Pepper, para maior resistência a ataques com GPU.

---

*Projeto educacional | SPTech | Spring Boot 3.4.4 + Spring Security 6 + JJWT 0.12.6*
