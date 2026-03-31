package school.sptech.exemplojwt.dto;

/**
 * Dados do usuário retornados no body da resposta de login.
 *
 * <p>Intencionalmente <b>não contém o token JWT</b> — o token é enviado
 * como cookie HttpOnly via header {@code Set-Cookie}, inacessível ao JavaScript.
 * Expô-lo no body seria contraditório com essa estratégia de segurança.</p>
 *
 * <p>O frontend usa esses dados apenas para fins de UX (exibir o nome,
 * controlar rotas). A autenticação real continua sendo validada pelo
 * cookie em cada requisição.</p>
 */
public class UsuarioSessaoDto {

    private Long userId;
    private String nome;
    private String email;

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
