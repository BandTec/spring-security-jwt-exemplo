package school.sptech.exemplojwt.service.usuario.autenticacao.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public class UsuarioLoginDto {

  @Schema(description = "E-mail do usuário", example = "john@doe.com")
  private String email;
  @Schema(description = "Senha do usuário", example = "123456")
  private String senha;

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public String getSenha() {
    return senha;
  }

  public void setSenha(String senha) {
    this.senha = senha;
  }
}
