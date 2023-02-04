package school.sptech.securityjwt.service.usuario;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import school.sptech.securityjwt.api.configuration.security.jwt.GerenciadorTokenJwt;
import school.sptech.securityjwt.domain.usuario.Usuario;
import school.sptech.securityjwt.domain.usuario.repository.UsuarioRepository;
import school.sptech.securityjwt.service.usuario.dto.UsuarioCriarDto;
import school.sptech.securityjwt.service.usuario.dto.UsuarioDataFactory;
import school.sptech.securityjwt.service.autenticacao.dto.UsuarioLoginDto;
import school.sptech.securityjwt.service.autenticacao.dto.UsuarioTokenDto;

import java.util.List;
import java.util.Optional;

@Service
public class UsuarioService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private GerenciadorTokenJwt gerenciadorTokenJwt;

    @Autowired
    private AuthenticationManager authenticationManager;

    public List<Usuario> buscarTodos(){
        return this.usuarioRepository.findAll();
    }

    public void criar(UsuarioCriarDto usuarioCriarDto){

        final Usuario novoUsuario = UsuarioDataFactory.of(usuarioCriarDto);

        String senhaCriptografada = passwordEncoder.encode(novoUsuario.getSenha());
        novoUsuario.setSenha(senhaCriptografada);

        this.usuarioRepository.save(novoUsuario);
    }

    public UsuarioTokenDto autenticar(UsuarioLoginDto usuarioLoginDto){

        final UsernamePasswordAuthenticationToken credentials = new UsernamePasswordAuthenticationToken(
                usuarioLoginDto.getEmail(), usuarioLoginDto.getSenha());

        final Authentication authentication = this.authenticationManager.authenticate(credentials);

        //TODO: Implementar tratamento de erro
        Optional<Usuario> usuarioAutenticadoOpt = usuarioRepository.findByEmail(usuarioLoginDto.getEmail());

        Usuario usuarioAutenticado = usuarioAutenticadoOpt.get();

        SecurityContextHolder.getContext().setAuthentication(authentication);

        final String token = gerenciadorTokenJwt.generateToken(authentication);

        return new UsuarioTokenDto(usuarioAutenticado.getId(), usuarioAutenticado.getNome(), usuarioAutenticado.getEmail(), token);
    }
}
