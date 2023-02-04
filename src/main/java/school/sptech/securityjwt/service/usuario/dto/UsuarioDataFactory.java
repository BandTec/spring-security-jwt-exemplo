package school.sptech.securityjwt.service.usuario.dto;

import school.sptech.securityjwt.domain.usuario.Usuario;

public class UsuarioDataFactory {

    public static Usuario of(UsuarioCriarDto usuarioCriarDto) {
        Usuario usuario = new Usuario();

        usuario.setEmail(usuarioCriarDto.getEmail());
        usuario.setNome(usuarioCriarDto.getNome());
        usuario.setSenha(usuarioCriarDto.getSenha());

        return usuario;
    }

}
