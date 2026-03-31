# Da Senha ao Token: Autenticação JWT com Argon2id + Pepper

> **Branch:** `feature/argon2-pepper` | Spring Boot 4.0.5 | Java 21 LTS | JJWT 0.12.6
>
> Para o contexto completo sobre senhas, hashing, JWT e decisões de segurança, leia o README da branch [`main`](../../tree/main).

---

## O que esta branch é

Esta branch parte da implementação da `main` e adiciona duas camadas de segurança que foram deixadas como extensão intencional: **Argon2id** no lugar do BCrypt e **Pepper** aplicado via HMAC-SHA256.

---

## O que muda em relação à main

### BCrypt vs Argon2id

BCrypt é CPU-hard: difícil de paralelizar em CPU convencional. O problema é que GPUs têm milhares de núcleos e conseguem rodar muitas instâncias de BCrypt em paralelo mesmo com o custo elevado.

Argon2id é **memory-hard**: além de CPU, cada operação de hash exige uma quantidade configurável de RAM. Com 64 MB por hash, uma GPU com 8 GB de VRAM consegue rodar no máximo ~125 instâncias simultâneas. Isso torna ataques via GPU inviáveis na prática.

### O que é Pepper e por que importa

Salt protege contra Rainbow Tables. BCrypt e Argon2 tornam o brute force lento. Mas se o atacante obtém o banco de dados completo, ele tem os salts e os hashes. Com tempo, pode tentar senhas por brute force, lento mas possível para senhas fracas.

O Pepper é uma chave secreta da aplicação que é incorporada à senha antes do hash, mas que **nunca fica no banco de dados**. Fica apenas nas variáveis de ambiente do servidor.

```
hash = Argon2id(HMAC-SHA256(senha, pepper))
```

Mesmo com o banco completamente vazado, o atacante não consegue calcular nenhum hash sem a chave pepper. Os hashes são inúteis sem ela.

### Por que HMAC em vez de simples concatenação

`pepper + senha` parece suficiente, mas é vulnerável a **length-extension attacks**. HMAC-SHA256 com o pepper como chave é a forma criptograficamente correta de derivar uma entrada a partir de um segredo. Além disso, HMAC produz output de tamanho fixo (32 bytes), eliminando qualquer problema de truncamento de senha.

---

## Arquivos alterados

| Arquivo                              | O que mudou                                                    |
|--------------------------------------|----------------------------------------------------------------|
| `config/PepperPasswordEncoder.java`  | Novo: aplica HMAC-SHA256(senha, pepper) e passa para Argon2id  |
| `config/DataInitializer.java`        | Novo: cria usuário de teste via código, hash gerado em runtime |
| `config/SecurityConfiguracao.java`   | `BCryptPasswordEncoder` substituído por `PepperPasswordEncoder` |
| `resources/application.properties`  | Adicionada propriedade `security.pepper`                       |
| `resources/data.sql`                 | Esvaziado, substituído pelo `DataInitializer`                  |
| `pom.xml`                            | Adicionado `bcprov-jdk18on` (BouncyCastle, necessário para Argon2) |

### Por que DataInitializer em vez de data.sql

O hash do usuário de teste depende do `PasswordEncoder` ativo e do valor do pepper. Com Argon2+pepper, o hash muda a cada execução (novo salt gerado automaticamente) e não pode ser pré-computado em SQL. O `DataInitializer` usa o bean `PasswordEncoder` injetado para gerar o hash correto na inicialização.

---

## Como funciona o PepperPasswordEncoder

```java
// Encode: aplica pepper via HMAC, passa o resultado para Argon2id
public String encode(CharSequence rawPassword) {
    return argon2.encode(applyPepper(rawPassword));
}

// Matches: aplica o mesmo pepper antes de comparar
public boolean matches(CharSequence rawPassword, String encodedPassword) {
    return argon2.matches(applyPepper(rawPassword), encodedPassword);
}

// Pepper via HMAC-SHA256, output em Base64 (tamanho fixo)
private String applyPepper(CharSequence rawPassword) {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(pepperBytes, "HmacSHA256"));
    byte[] hmac = mac.doFinal(rawPassword.toString().getBytes(UTF_8));
    return Base64.getEncoder().encodeToString(hmac);
}
```

O Argon2id cuida do salt automaticamente: gera um salt aleatório no encode e o armazena no próprio hash, sem necessidade de gerenciamento manual.

---

## Configuração em produção

```bash
# Variáveis de ambiente obrigatórias
export JWT_SECRET=<base64 de pelo menos 32 bytes>
export SECURITY_PEPPER=<string aleatória, ex: openssl rand -base64 48>
```

Nunca use os valores padrão (`dev-pepper-nao-usar-em-producao...`) em produção. Se o pepper vazar, a proteção extra é eliminada. Trate-o com o mesmo cuidado que uma chave de criptografia.

---

## O que esta implementação resolve

| Problema                    | main (BCrypt)      | Esta branch (Argon2id + Pepper)                               |
|-----------------------------|--------------------|-----------------------------------------------------------------|
| Rainbow Tables              | Sim                | Sim                                                            |
| Hashes rápidos              | Sim                | Sim                                                            |
| Brute force com GPU         | Parcialmente       | Sim: Argon2id é memory-hard, inviabiliza ataques com GPU       |
| Vazamento total do banco    | Parcialmente       | Sim: sem o pepper, os hashes são inúteis                       |
| Senhas fracas               | Não                | Não: pepper e Argon2 não tornam senhas fracas seguras, mas aumentam o custo de quebrá-las |

Segurança é sobre camadas. Nenhuma implementação garante que senhas fracas sejam seguras. O que estas camadas fazem é aumentar o custo de um ataque a ponto de torná-lo economicamente inviável para a maioria dos atacantes.

---

## Como Rodar

Requisitos: Java 21+ e Maven 3.8+

```bash
./mvnw spring-boot:run
```

API disponível em `http://localhost:8080`.

Usuário de teste criado automaticamente pelo `DataInitializer` na inicialização:

| Email         | Senha  |
|---------------|--------|
| john@doe.com  | 123456 |

---

## Outras Versões

- [`main`](../../tree/main): Spring Boot 4 com BCrypt, contexto completo e explicações detalhadas.
- [`spring-3.x.x`](../../tree/spring-3.x.x): Spring Boot 3.4.x com Spring Security 6.

---

*Projeto educacional | SPTech | Spring Boot 4.0.5 + Spring Security 7 + JJWT 0.12.6 + Argon2id*
