package school.sptech.exemplojwt.config;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import school.sptech.exemplojwt.service.AutenticacaoService;

/**
 * Provider de autenticação customizado responsável por validar as credenciais do usuário.
 *
 * <p>Implementa {@link AuthenticationProvider}, que é a interface do Spring Security
 * para definir a lógica de autenticação. O {@link AuthenticationProvider} é chamado
 * pelo {@link org.springframework.security.authentication.AuthenticationManager} quando
 * o usuário tenta fazer login.</p>
 *
 * <h3>Por que criar um provider customizado?</h3>
 * <p>O Spring Security possui providers padrão (ex: {@code DaoAuthenticationProvider}),
 * mas criar um provider explícito dá controle total sobre o processo de autenticação,
 * incluindo como a senha é verificada e quais exceções são lançadas.</p>
 *
 * <h3>Fluxo de autenticação no login:</h3>
 * <pre>
 *   POST /usuarios/login {email, senha}
 *     → UsuarioService.autenticar()
 *       → AuthenticationManager.authenticate()
 *         → AutenticacaoProvider.authenticate()  ← você está aqui
 *           → AutenticacaoService.loadUserByUsername()  (busca no banco)
 *           → BCrypt.matches(senhaDigitada, hashNoBanco)
 *           → retorna autenticação válida ou lança BadCredentialsException
 * </pre>
 */
public class AutenticacaoProvider implements AuthenticationProvider {

    private final AutenticacaoService usuarioAutorizacaoService;
    private final PasswordEncoder passwordEncoder;

    public AutenticacaoProvider(AutenticacaoService usuarioAutorizacaoService, PasswordEncoder passwordEncoder) {
        this.usuarioAutorizacaoService = usuarioAutorizacaoService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Autentica o usuário verificando e-mail e senha.
     *
     * <p>A senha digitada é comparada com o hash BCrypt armazenado no banco usando
     * {@link PasswordEncoder#matches}. O BCrypt inclui o salt no próprio hash,
     * então a comparação é feita diretamente (sem gerar o salt separadamente).</p>
     *
     * @param authentication objeto contendo username (e-mail) e password (senha digitada)
     * @return token de autenticação com UserDetails e authorities se as credenciais forem válidas
     * @throws BadCredentialsException se o usuário não existir ou a senha não bater
     */
    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final String username = authentication.getName();
        final String password = authentication.getCredentials().toString();

        // Carrega o usuário do banco de dados pelo e-mail
        // Lança UsernameNotFoundException se o usuário não existir
        UserDetails userDetails = this.usuarioAutorizacaoService.loadUserByUsername(username);

        // Compara a senha digitada com o hash BCrypt armazenado no banco
        if (this.passwordEncoder.matches(password, userDetails.getPassword())) {
            // Credenciais válidas: retorna autenticação com authorities (perfis do usuário)
            return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        } else {
            // Lança exceção genérica para não revelar se o erro foi no e-mail ou na senha
            throw new BadCredentialsException("Usuário ou Senha inválidos");
        }
    }

    /**
     * Indica que este provider suporta autenticação por username/password.
     *
     * <p>O Spring Security usa este método para selecionar o provider correto
     * quando há múltiplos providers registrados.</p>
     */
    @Override
    public boolean supports(final Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
