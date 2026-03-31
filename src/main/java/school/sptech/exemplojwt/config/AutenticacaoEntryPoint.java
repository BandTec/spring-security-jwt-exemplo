package school.sptech.exemplojwt.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Ponto de entrada para erros de autenticação na API.
 *
 * <p>O Spring Security invoca este componente sempre que uma requisição
 * a um endpoint protegido falha na autenticação — ou seja, quando o usuário
 * não está autenticado ou as credenciais são inválidas.</p>
 *
 * <p>Implementa {@link AuthenticationEntryPoint}, que é a interface do Spring Security
 * para personalizar a resposta em casos de falha de autenticação.</p>
 *
 * <h3>Diferença entre 401 e 403:</h3>
 * <ul>
 *   <li><b>401 Unauthorized</b>: o usuário não está autenticado (sem token, credenciais inválidas)</li>
 *   <li><b>403 Forbidden</b>: o usuário está autenticado mas não tem permissão para o recurso</li>
 * </ul>
 */
@Component
public class AutenticacaoEntryPoint implements AuthenticationEntryPoint {

    /**
     * Trata erros de autenticação e define o código de status HTTP da resposta.
     *
     * @param request       requisição HTTP que falhou na autenticação
     * @param response      resposta HTTP a ser enviada ao cliente
     * @param authException exceção de autenticação que foi lançada
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        if (authException instanceof BadCredentialsException
                || authException instanceof InsufficientAuthenticationException) {
            // 401: credenciais inválidas ou ausentes (sem token JWT no header)
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        } else {
            // 403: autenticado, mas sem permissão suficiente para o recurso
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
        }
    }
}
