package school.sptech.exemplojwt.service;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import school.sptech.exemplojwt.config.GerenciadorTokenJwt;
import school.sptech.exemplojwt.dto.UsuarioListarDto;
import school.sptech.exemplojwt.entity.Usuario;
import school.sptech.exemplojwt.repository.UsuarioRepository;
import school.sptech.exemplojwt.dto.UsuarioLoginDto;
import school.sptech.exemplojwt.dto.UsuarioTokenDto;
import school.sptech.exemplojwt.dto.UsuarioCriacaoDto;
import school.sptech.exemplojwt.dto.UsuarioMapper;

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

  public void criar(Usuario novoUsuario) {


    String senhaCriptografada = passwordEncoder.encode(novoUsuario.getSenha());
    novoUsuario.setSenha(senhaCriptografada);

    this.usuarioRepository.save(novoUsuario);
  }

  public UsuarioTokenDto autenticar(Usuario usuario) {

    final UsernamePasswordAuthenticationToken credentials = new UsernamePasswordAuthenticationToken(
          usuario.getEmail(), usuario.getSenha());

    final Authentication authentication = this.authenticationManager.authenticate(credentials);

    Usuario usuarioAutenticado =
            usuarioRepository.findByEmail(usuario.getEmail())
                    .orElseThrow(
                            () -> new ResponseStatusException(404, "Email do usuário não cadastrado", null)
                    );

    SecurityContextHolder.getContext().setAuthentication(authentication);

    final String token = gerenciadorTokenJwt.generateToken(authentication);

    return UsuarioMapper.of(usuarioAutenticado, token);
  }

  public List<UsuarioListarDto> listarTodos() {

    List<Usuario> usuariosEncontrados = usuarioRepository.findAll();
    return usuariosEncontrados.stream().map(UsuarioMapper::of).toList();

  }
}