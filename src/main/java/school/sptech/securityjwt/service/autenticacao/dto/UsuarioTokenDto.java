package school.sptech.securityjwt.service.autenticacao.dto;

public class UsuarioTokenDto {

    private Long userId;
    private String nome;
    private String email;
    private String token;

    public UsuarioTokenDto(Long userId, String nome, String email, String token) {
        this.userId = userId;
        this.nome = nome;
        this.email = email;
        this.token = token;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
