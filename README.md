# 🛡 spring-security-jwt-exemplo 🛡
Exemplo de implementação de autenticação baseada em token (JWT) utilizando Spring Security. Este projeto demonstra uma forma segura e eficaz de gerenciar a autenticação de usuários em aplicações Spring Boot, utilizando o banco de dados em memória H2 para simplificar o teste e a configuração.

## 🚀 Para Testar
Este projeto foi configurado para facilitar a sua experimentação e compreensão sobre a autenticação baseada em JWT com Spring Security.

### 📚 Swagger UI
Para uma interação visual e direta com a API, acesse a interface do Swagger UI:

- **Swagger UI:** `localhost:8080/swagger-ui/index.html`

Através dela, você pode facilmente testar os endpoints disponíveis, compreendendo o fluxo de autenticação e autorização.

### 🧑‍💼 Usuário Padrão para Testes
Para facilitar seus testes iniciais, você pode utilizar o usuário padrão abaixo:
- **E-mail:** `john@doe.com`
- **Senha:** `123456`

Este usuário já está pré-configurado no sistema, permitindo que você teste a autenticação e acesso aos recursos protegidos sem a necessidade de criar um novo usuário.

## 💻 Interface do Usuário com React
Para exemplificar a integração com uma aplicação cliente, disponibilizamos um frontend em React que consome a API protegida por JWT. Acesse o repositório do frontend para obter detalhes sobre a instalação e execução:

- **Repositório React:** [https://github.com/BandTec/spring-security-jwt-exemplo-react](https://github.com/BandTec/spring-security-jwt-exemplo-react)

## 📘 Pré-Requisitos
Antes de iniciar, certifique-se de ter os seguintes pré-requisitos instalados:
- **JDK 17**: Necessário para executar o projeto Spring Boot.