package school.sptech.exemplojwt.config;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SecurityException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import school.sptech.exemplojwt.service.AutenticacaoService;

import java.io.IOException;
import java.util.Objects;

/**
 * Filtro de autenticação JWT que intercepta todas as requisições HTTP recebidas pela API.
 *
 * <p>Extende {@link OncePerRequestFilter} para garantir que a lógica de autenticação
 * seja executada <b>exatamente uma vez</b> por requisição, mesmo em ambientes com
 * múltiplos dispatchers de servlet.</p>
 *
 * <h3>Por que um filtro e não um interceptor MVC?</h3>
 * <p>Filtros Servlet operam em um nível mais baixo que interceptors MVC. Isso permite
 * que o Spring Security tenha acesso à requisição <b>antes</b> que ela chegue ao controller,
 * podendo rejeitar requisições não autorizadas cedo no ciclo de vida.</p>
 *
 * <h3>Fluxo de autenticação JWT a cada requisição:</h3>
 * <pre>
 *   Requisição HTTP
 *     ↓ 1. Extrai header "Authorization: Bearer &lt;token&gt;"
 *     ↓ 2. Parseia o token e extrai o username (JJWT valida assinatura e expiração)
 *     ↓ 3. Carrega UserDetails do banco de dados via AutenticacaoService
 *     ↓ 4. Valida token vs. UserDetails (username bate? não expirou?)
 *     ↓ 5. Registra autenticação no SecurityContextHolder (contexto da thread atual)
 *     ↓ 6. Continua a cadeia de filtros → Spring Security verifica autorização
 * </pre>
 *
 * <p>Se qualquer etapa falhar, o usuário não é autenticado e o Spring Security
 * devolve 401 (Unauthorized) ou 403 (Forbidden) via {@link AutenticacaoEntryPoint}.</p>
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
        String jwtToken = null;

        // Passo 1: Extrair o token do header "Authorization"
        // O padrão Bearer Token é definido na RFC 6750.
        // Formato esperado: "Authorization: Bearer eyJhbGci..."
        String requestTokenHeader = request.getHeader("Authorization");

        if (Objects.nonNull(requestTokenHeader) && requestTokenHeader.startsWith("Bearer ")) {
            // Remove o prefixo "Bearer " (7 caracteres) para obter somente o token
            jwtToken = requestTokenHeader.substring(7);

            try {
                // Passo 2: Extrair o username do payload do token
                // O JJWT valida a assinatura e a expiração automaticamente neste ponto.
                // Se o token for inválido, uma das exceções abaixo será lançada.
                username = jwtTokenManager.getUsernameFromToken(jwtToken);

            } catch (ExpiredJwtException e) {
                // Token válido estruturalmente, mas passou do tempo de expiração (claim "exp")
                LOGGER.warn("[AUTENTICACAO] Token expirado para o usuário '{}': {}",
                        e.getClaims().getSubject(), e.getMessage());

            } catch (MalformedJwtException e) {
                // Token com estrutura inválida (não tem os 3 segmentos separados por ponto)
                LOGGER.warn("[AUTENTICACAO] Token com formato inválido: {}", e.getMessage());

            } catch (UnsupportedJwtException e) {
                // Token usa um algoritmo não suportado pela aplicação
                LOGGER.warn("[AUTENTICACAO] Token com algoritmo não suportado: {}", e.getMessage());

            } catch (SecurityException e) {
                // Assinatura não bate com a chave secreta — token pode ter sido adulterado
                LOGGER.warn("[AUTENTICACAO] Assinatura do token inválida (possível adulteração): {}", e.getMessage());

            } catch (IllegalArgumentException e) {
                // Token nulo, vazio ou com apenas espaços
                LOGGER.warn("[AUTENTICACAO] Token ausente ou vazio: {}", e.getMessage());
            }
        }

        // Passo 3 a 5: Autenticar o usuário no contexto do Spring Security
        // Condições para prosseguir:
        //   - username foi extraído com sucesso do token (não é null)
        //   - não há autenticação já registrada para esta thread (evita processar duas vezes)
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            registrarAutenticacaoNoContexto(request, username, jwtToken);
        }

        // Passo 6: Continua a cadeia de filtros independentemente do resultado acima.
        // Se o usuário não foi autenticado, o próximo filtro do Spring Security irá
        // verificar a autorização e retornar 401/403 via AutenticacaoEntryPoint.
        filterChain.doFilter(request, response);
    }

    /**
     * Valida o token JWT e, se válido, registra o usuário autenticado no
     * {@link SecurityContextHolder} da thread atual.
     *
     * <p>O {@link SecurityContextHolder} é o mecanismo central do Spring Security
     * para armazenar quem está autenticado na requisição corrente. Sem essa
     * informação, o framework trata a requisição como anônima e bloqueia o acesso
     * a endpoints protegidos.</p>
     *
     * <p>Importante: como a API é <b>stateless</b> (sem sessão), esse contexto é
     * criado do zero a cada requisição e descartado ao final dela.</p>
     *
     * @param request  requisição HTTP atual
     * @param username e-mail/username extraído do token JWT
     * @param jwtToken token JWT bruto
     */
    private void registrarAutenticacaoNoContexto(HttpServletRequest request, String username, String jwtToken) {
        // Carrega os detalhes completos do usuário do banco de dados
        UserDetails userDetails = autenticacaoService.loadUserByUsername(username);

        // Validação adicional: username do token corresponde ao usuário do banco e o token não expirou
        if (jwtTokenManager.validateToken(jwtToken, userDetails)) {

            // Cria o token de autenticação do Spring Security com as authorities do usuário
            // O segundo parâmetro (credentials) é null pois em JWT não trafegamos a senha após login
            UsernamePasswordAuthenticationToken autenticacao = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());

            // Adiciona metadados da requisição (IP de origem, session ID) ao objeto de autenticação
            autenticacao.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Registra a autenticação no contexto da thread atual
            SecurityContextHolder.getContext().setAuthentication(autenticacao);
        }
    }
}
