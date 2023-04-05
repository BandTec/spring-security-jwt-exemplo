package school.sptech.exemplojwt.api.configuration.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import school.sptech.exemplojwt.api.configuration.security.jwt.GerenciadorTokenJwt;
import school.sptech.exemplojwt.service.usuario.autenticacao.AutenticacaoService;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguracao {

  @Autowired
  private AutenticacaoEntryPoint autenticacaoJwtEntryPoint;

  @Autowired
  private AutenticacaoService autenticacaoService;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            .cors()
            .configurationSource(request-> {
              CorsConfiguration configuration = new CorsConfiguration();
              configuration.setAllowedOrigins(List.of("*"));
              configuration.setAllowedMethods(List.of("*"));
              configuration.setAllowedHeaders(List.of("*"));
              return configuration;
            })
            .and()
            .csrf()
            .disable()
            .authorizeRequests()
            .antMatchers(
                    "/usuarios/login"
            ).permitAll()
            .antMatchers().hasAnyRole()
            .anyRequest().authenticated()
            .and()
            .exceptionHandling()
            .authenticationEntryPoint(autenticacaoJwtEntryPoint)
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    http.addFilterBefore(jwtAuthenticationFilterBean(), UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  @Bean
  public AuthenticationManager authManager(HttpSecurity http) throws Exception {
    AuthenticationManagerBuilder authenticationManagerBuilder =
            http.getSharedObject(AuthenticationManagerBuilder.class);
    authenticationManagerBuilder.authenticationProvider(new AutenticacaoProvider(autenticacaoService, passwordEncoder()));
    return authenticationManagerBuilder.build();
  }

  @Bean
  public AutenticacaoEntryPoint jwtAuthenticationEntryPointBean() {
    return new AutenticacaoEntryPoint();
  }

  @Bean
  public AutenticacaoFilter jwtAuthenticationFilterBean() {
    return new AutenticacaoFilter(autenticacaoService, jwtAuthenticationUtilBean());
  }

  @Bean
  public GerenciadorTokenJwt jwtAuthenticationUtilBean() {
    return new GerenciadorTokenJwt();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}