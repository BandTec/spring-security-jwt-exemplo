package school.sptech.exemplojwt.config;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SecurityException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import school.sptech.exemplojwt.controller.UsuarioController;
import school.sptech.exemplojwt.service.AutenticacaoService;

import java.io.IOException;

/**
 * Filtro de autenticação JWT que intercepta todas as requisições HTTP recebidas pela API.
 *
 * <p>Extende {@link OncePerRequestFilter} para garantir que a lógica de autenticação
 * seja executada <b>exatamente uma vez</b> por requisição.</p>
 *
 * <h3>Estratégia de leitura do token (dupla origem):</h3>
 * <ol>
 *   <li><b>Cookie HttpOnly</b> {@code authToken}: usado pelo browser. Enviado automaticamente
 *       e inacessível ao JavaScript (proteção contra XSS).</li>
 *   <li><b>Header Authorization: Bearer</b>: fallback para ferramentas como Swagger UI,
 *       Postman e chamadas server-to-server que não gerenciam cookies.</li>
 * </ol>
 *
 * <p>O cookie tem prioridade. Se ambos estiverem presentes, o cookie é usado.</p>
 *
 * <h3>Fluxo da requisição:</h3>
 * <pre>
 *   Requisição HTTP
 *     ↓ 1. Tenta extrair token do cookie "authToken"
 *     ↓ 2. Se não encontrar, tenta header "Authorization: Bearer"
 *     ↓ 3. JJWT valida assinatura e expiração
 *     ↓ 4. Carrega UserDetails do banco e registra autenticação no SecurityContext
 *     ↓ 5. Continua para os próximos filtros do Spring Security
 * </pre>
 */
public class AutenticacaoFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AutenticacaoFilter.class);

    private final AutenticacaoService autenticacaoService;
    private final GerenciadorTokenJwt jwtTokenManager;

    public AutenticacaoFilter(AutenticacaoService autenticacaoService, GerenciadorTokenJwt jwtTokenManager) {
        this.autenticacaoService = autenticacaoService;
        this.jwtTokenManager = jwtTokenManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String username = null;
        String jwtToken = extrairToken(request);

        if (jwtToken != null) {
            try {
                username = jwtTokenManager.getUsernameFromToken(jwtToken);

            } catch (ExpiredJwtException e) {
                LOGGER.warn("[AUTENTICACAO] Token expirado para o usuário '{}': {}",
                        e.getClaims().getSubject(), e.getMessage());

            } catch (MalformedJwtException e) {
                LOGGER.warn("[AUTENTICACAO] Token com formato inválido: {}", e.getMessage());

            } catch (UnsupportedJwtException e) {
                LOGGER.warn("[AUTENTICACAO] Token com algoritmo não suportado: {}", e.getMessage());

            } catch (SecurityException e) {
                LOGGER.warn("[AUTENTICACAO] Assinatura do token inválida (possível adulteração): {}", e.getMessage());

            } catch (IllegalArgumentException e) {
                LOGGER.warn("[AUTENTICACAO] Token ausente ou vazio: {}", e.getMessage());
            }
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            registrarAutenticacaoNoContexto(request, username, jwtToken);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extrai o token JWT da requisição, verificando duas origens possíveis:
     *
     * <ol>
     *   <li><b>Cookie HttpOnly</b>: preferencial para uso em browsers. Enviado automaticamente
     *       e protegido contra leitura via JavaScript (XSS).</li>
     *   <li><b>Authorization header</b>: fallback para Swagger, Postman e chamadas programáticas.
     *       Formato esperado: {@code Authorization: Bearer <token>}</li>
     * </ol>
     *
     * @param request requisição HTTP
     * @return token JWT ou {@code null} se nenhum for encontrado
     */
    private String extrairToken(HttpServletRequest request) {
        // Prioridade 1: cookie HttpOnly (browser)
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (UsuarioController.COOKIE_NOME.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        // Prioridade 2: header Authorization: Bearer (Swagger, Postman, server-to-server)
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        return null;
    }

    /**
     * Valida o token JWT e, se válido, registra o usuário autenticado no
     * {@link SecurityContextHolder} da thread atual.
     */
    private void registrarAutenticacaoNoContexto(HttpServletRequest request, String username, String jwtToken) {
        UserDetails userDetails = autenticacaoService.loadUserByUsername(username);

        if (jwtTokenManager.validateToken(jwtToken, userDetails)) {
            UsernamePasswordAuthenticationToken autenticacao = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());

            autenticacao.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(autenticacao);
        }
    }
}
