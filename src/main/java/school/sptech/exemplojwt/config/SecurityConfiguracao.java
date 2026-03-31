package school.sptech.exemplojwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import school.sptech.exemplojwt.service.AutenticacaoService;

import java.util.Arrays;
import java.util.List;

/**
 * Configuração central do Spring Security para autenticação JWT stateless.
 *
 * <p>Esta classe define toda a política de segurança da aplicação:</p>
 * <ul>
 *   <li>Quais endpoints são públicos e quais exigem autenticação</li>
 *   <li>Como o JWT é processado em cada requisição (via filtro customizado)</li>
 *   <li>Política de sessão, CORS e CSRF</li>
 *   <li>Algoritmo de hash de senha</li>
 * </ul>
 *
 * <p><b>Anotações utilizadas:</b></p>
 * <ul>
 *   <li>{@code @Configuration}: indica que esta classe contém definições de beans Spring</li>
 *   <li>{@code @EnableWebSecurity}: ativa a configuração do Spring Security via código Java</li>
 *   <li>{@code @EnableMethodSecurity}: habilita anotações de segurança nos métodos
 *       (ex: {@code @PreAuthorize("hasRole('ADMIN')")})</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguracao {

    @Autowired
    private AutenticacaoService autenticacaoService;

    // AutenticacaoEntryPoint é registrado como @Component, o Spring injeta automaticamente
    @Autowired
    private AutenticacaoEntryPoint autenticacaoJwtEntryPoint;

    /**
     * URLs que não exigem autenticação (acesso público).
     *
     * <p>Inclui documentação da API (Swagger/OpenAPI), console do H2, endpoints
     * de login e rotas de erro — tudo que deve funcionar sem token JWT.</p>
     *
     * <p><b>Spring Security 7 (Spring Boot 4):</b> {@code AntPathRequestMatcher} foi removido.
     * Utilize {@code requestMatchers(String...)} diretamente com padrões Ant.</p>
     */
    private static final String[] URLS_PERMITIDAS = {
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/api/public/**",
            "/api/public/authenticate",
            "/webjars/**",
            "/v3/api-docs/**",
            "/actuator/*",
            "/usuarios/login/**",
            "/usuarios/logout/**",
            "/h2-console/**",
            "/h2-console/*/**",
            "/error/**"
    };

    /**
     * Define a cadeia de filtros de segurança (Security Filter Chain).
     *
     * <p>Este é o bean mais importante da configuração. Ele define como cada
     * requisição HTTP é processada pelo Spring Security.</p>
     *
     * @param http objeto para construir as configurações de segurança HTTP
     * @return cadeia de filtros configurada
     * @throws Exception em caso de erro na configuração
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // Desabilita restrição de X-Frame-Options para permitir o console H2 no browser.
                // Em produção, remova isso — o H2 console não deve ser exposto.
                .headers(headers -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))

                // Habilita CORS com a configuração definida em corsConfigurationSource()
                .cors(Customizer.withDefaults())

                // Desabilita CSRF (Cross-Site Request Forgery):
                // APIs REST stateless com JWT não precisam de proteção CSRF porque:
                // 1. Não usam cookies para autenticação (usam header Authorization)
                // 2. Browsers não enviam headers customizados em requisições cross-origin automaticamente
                // ATENÇÃO: se usar cookies para armazenar o token, habilite o CSRF novamente!
                .csrf(CsrfConfigurer<HttpSecurity>::disable)

                // Define quais URLs são públicas e quais exigem autenticação
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(URLS_PERMITIDAS).permitAll()  // rotas públicas
                        .anyRequest().authenticated()                  // todas as outras exigem token
                )

                // Configura o handler para erros de autenticação (token ausente/inválido → 401/403)
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(autenticacaoJwtEntryPoint))

                // Define política de sessão: STATELESS
                // O servidor NÃO cria nem armazena sessões HTTP.
                // Cada requisição é autenticada de forma independente pelo token JWT.
                // Isso torna a API escalável horizontalmente (sem estado compartilhado entre servidores).
                .sessionManagement(management -> management
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // Adiciona o filtro JWT ANTES do filtro padrão de autenticação por usuário/senha.
        // Isso garante que o token seja processado antes que o Spring Security tente
        // qualquer outro mecanismo de autenticação.
        http.addFilterBefore(jwtAuthenticationFilterBean(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Configura o AuthenticationManager com o provider customizado.
     *
     * <p>O {@link AuthenticationManager} é o responsável por orquestrar a autenticação.
     * Aqui registramos nosso {@link AutenticacaoProvider}, que sabe validar credenciais
     * contra o banco de dados usando BCrypt.</p>
     */
    @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(
                new AutenticacaoProvider(autenticacaoService, passwordEncoder()));
        return authenticationManagerBuilder.build();
    }

    /**
     * Cria o filtro de autenticação JWT.
     *
     * <p>Este filtro intercepta todas as requisições e extrai/valida o token JWT
     * do header {@code Authorization: Bearer <token>}.</p>
     */
    @Bean
    public AutenticacaoFilter jwtAuthenticationFilterBean() {
        return new AutenticacaoFilter(autenticacaoService, jwtAuthenticationUtilBean());
    }

    /**
     * Cria o gerenciador de tokens JWT.
     *
     * <p>Responsável por gerar, parsear e validar tokens JWT usando a biblioteca JJWT.</p>
     */
    @Bean
    public GerenciadorTokenJwt jwtAuthenticationUtilBean() {
        return new GerenciadorTokenJwt();
    }

    /**
     * Define o algoritmo de hash para senhas: BCrypt.
     *
     * <p>BCrypt é um algoritmo de hash adaptativo que inclui um "salt" aleatório
     * automaticamente, tornando cada hash único mesmo para senhas idênticas.
     * O fator de custo padrão é 10, o que torna ataques de força bruta computacionalmente caros.</p>
     *
     * <p><b>Nunca armazene senhas em texto puro.</b> Sempre use um hash seguro como BCrypt.</p>
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configura a política de CORS (Cross-Origin Resource Sharing).
     *
     * <p><b>Por que não usar {@code *} com cookies?</b><br>
     * Quando o frontend usa {@code withCredentials: true} (necessário para enviar cookies),
     * o navegador exige que o servidor informe uma origem específica em
     * {@code Access-Control-Allow-Origin}. O valor {@code *} é rejeitado pelo browser
     * nesse contexto — isso é uma regra do padrão CORS, não do Spring.</p>
     *
     * <p>Em desenvolvimento, o Vite roda em {@code http://localhost:5173} por padrão.
     * Em produção, substitua pela URL real do frontend.</p>
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuracao = new CorsConfiguration();

        // Origens permitidas — deve ser explícita quando allowCredentials=true
        // Em produção: List.of("https://meuapp.com.br")
        configuracao.setAllowedOrigins(List.of(
                "http://localhost:5173",  // Vite dev server
                "http://localhost:3000"   // Create React App (alternativa)
        ));

        // Necessário para que o browser envie/receba cookies nas requisições cross-origin
        configuracao.setAllowCredentials(true);

        configuracao.setAllowedMethods(Arrays.asList(
                HttpMethod.GET.name(),
                HttpMethod.POST.name(),
                HttpMethod.PUT.name(),
                HttpMethod.PATCH.name(),
                HttpMethod.DELETE.name(),
                HttpMethod.OPTIONS.name(),
                HttpMethod.HEAD.name(),
                HttpMethod.TRACE.name()
        ));

        // Permite todos os headers de requisição (Content-Type, Authorization etc.)
        configuracao.setAllowedHeaders(List.of("*"));

        // Expõe o header Content-Disposition para download de arquivos
        configuracao.setExposedHeaders(List.of(HttpHeaders.CONTENT_DISPOSITION));

        UrlBasedCorsConfigurationSource origem = new UrlBasedCorsConfigurationSource();
        origem.registerCorsConfiguration("/**", configuracao);

        return origem;
    }
}
