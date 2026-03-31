package school.sptech.exemplojwt.controller;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import school.sptech.exemplojwt.dto.*;
import school.sptech.exemplojwt.entity.Usuario;
import school.sptech.exemplojwt.service.UsuarioService;

import java.time.Duration;
import java.util.List;

@RestController
@RequestMapping("/usuarios")
public class UsuarioController {

    // Nome do cookie — definido em um só lugar para evitar typos
    public static final String COOKIE_NOME = "authToken";

    @Value("${jwt.validity}")
    private long jwtValidity;

    @Autowired
    private UsuarioService usuarioService;

    @PostMapping
    @SecurityRequirement(name = "Bearer")
    public ResponseEntity<Void> criar(@RequestBody @Valid UsuarioCriacaoDto usuarioCriacaoDto) {
        final Usuario novoUsuario = UsuarioMapper.of(usuarioCriacaoDto);
        this.usuarioService.criar(novoUsuario);
        return ResponseEntity.status(201).build();
    }

    /**
     * Autentica o usuario e retorna o token JWT como cookie HttpOnly.
     *
     * <p><b>Por que HttpOnly?</b> Um cookie HttpOnly nao e acessivel via JavaScript
     * ({@code document.cookie}), o que impede que ataques XSS roubem o token.
     * Com {@code sessionStorage} ou {@code localStorage}, um script malicioso
     * injetado na pagina consegue ler o token trivialmente.</p>
     *
     * <p><b>SameSite=Strict</b> impede que o cookie seja enviado em requisicoes
     * cross-site (ex: link de outro dominio), o que mitiga ataques CSRF sem
     * precisar de CSRF tokens.</p>
     *
     * <p><b>Secure</b> deve ser {@code true} em producao (HTTPS obrigatorio).
     * Em desenvolvimento local (HTTP) usamos {@code false}.</p>
     */
    @PostMapping("/login")
    public ResponseEntity<UsuarioSessaoDto> login(
            @RequestBody UsuarioLoginDto usuarioLoginDto,
            HttpServletResponse response) {

        final Usuario usuario = UsuarioMapper.of(usuarioLoginDto);

        // autenticar() gera o token internamente — precisamos dele apenas para o cookie
        UsuarioTokenDto autenticado = this.usuarioService.autenticar(usuario);

        // Token vai para o cookie HttpOnly — inacessível ao JavaScript (proteção XSS)
        ResponseCookie cookie = ResponseCookie.from(COOKIE_NOME, autenticado.getToken())
                .httpOnly(true)                          // inacessivel ao JavaScript
                .secure(false)                           // true em producao (exige HTTPS)
                .sameSite("Strict")                      // bloqueia envio cross-site (mitiga CSRF)
                .path("/")                               // valido para toda a aplicacao
                .maxAge(Duration.ofSeconds(jwtValidity)) // expira junto com o token JWT
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        // Body retorna apenas dados de sessão — sem o token
        UsuarioSessaoDto sessao = UsuarioMapper.ofSessao(autenticado);
        return ResponseEntity.ok(sessao);
    }

    /**
     * Invalida a sessao do usuario limpando o cookie de autenticacao.
     *
     * <p>Como JWT e stateless, o servidor nao pode "cancelar" o token.
     * O logout aqui funciona removendo o cookie do browser (maxAge=0),
     * o que impede que o token seja enviado nas proximas requisicoes.</p>
     *
     * <p>O token ainda estaria tecnicamente valido ate expirar — por isso
     * tokens de curta duracao (15 min a 1 hora) sao importantes.</p>
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(COOKIE_NOME, "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Strict")
                .path("/")
                .maxAge(0)  // maxAge=0 instrui o browser a deletar o cookie imediatamente
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.noContent().build();
    }

    @GetMapping
    @SecurityRequirement(name = "Bearer")
    public ResponseEntity<List<UsuarioListarDto>> listarTodos() {
        List<UsuarioListarDto> usuariosEncontrados = this.usuarioService.listarTodos();

        if (usuariosEncontrados.isEmpty()) {
            return ResponseEntity.status(204).build();
        }
        return ResponseEntity.ok(usuariosEncontrados);
    }
}
