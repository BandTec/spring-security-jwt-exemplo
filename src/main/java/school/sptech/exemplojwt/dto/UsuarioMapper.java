package school.sptech.exemplojwt.dto;

import school.sptech.exemplojwt.entity.Usuario;

public class UsuarioMapper {

  public static Usuario of(UsuarioCriacaoDto usuarioCriacaoDto) {
    Usuario usuario = new Usuario();

    usuario.setEmail(usuarioCriacaoDto.getEmail());
    usuario.setNome(usuarioCriacaoDto.getNome());
    usuario.setSenha(usuarioCriacaoDto.getSenha());

    return usuario;
  }

  public static Usuario of(UsuarioLoginDto usuarioLoginDto) {
    Usuario usuario = new Usuario();

    usuario.setEmail(usuarioLoginDto.getEmail());
    usuario.setSenha(usuarioLoginDto.getSenha());

    return usuario;
  }

  public static UsuarioTokenDto of(Usuario usuario, String token) {
    UsuarioTokenDto usuarioTokenDto = new UsuarioTokenDto();

    usuarioTokenDto.setUserId(usuario.getId());
    usuarioTokenDto.setEmail(usuario.getEmail());
    usuarioTokenDto.setNome(usuario.getNome());
    usuarioTokenDto.setToken(token);

    return usuarioTokenDto;
  }

  /**
   * Mapeia para o DTO de resposta do login — sem o token.
   *
   * <p>O token não pertence ao body: ele é enviado como cookie HttpOnly
   * via {@code Set-Cookie}. Este DTO carrega apenas os dados necessários
   * para o frontend identificar o usuário na sessão.</p>
   */
  public static UsuarioSessaoDto ofSessao(UsuarioTokenDto tokenDto) {
    UsuarioSessaoDto dto = new UsuarioSessaoDto();

    dto.setUserId(tokenDto.getUserId());
    dto.setEmail(tokenDto.getEmail());
    dto.setNome(tokenDto.getNome());

    return dto;
  }

  public static UsuarioListarDto of(Usuario usuario) {
    UsuarioListarDto usuarioListarDto = new UsuarioListarDto();

    usuarioListarDto.setId(usuario.getId());
    usuarioListarDto.setEmail(usuario.getEmail());
    usuarioListarDto.setNome(usuario.getNome());

    return usuarioListarDto;
  }
}
