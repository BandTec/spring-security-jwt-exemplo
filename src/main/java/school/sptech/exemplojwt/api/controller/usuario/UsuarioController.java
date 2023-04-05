package school.sptech.exemplojwt.api.controller.usuario;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import school.sptech.exemplojwt.service.usuario.UsuarioService;
import school.sptech.exemplojwt.service.usuario.autenticacao.dto.UsuarioLoginDto;
import school.sptech.exemplojwt.service.usuario.autenticacao.dto.UsuarioTokenDto;
import school.sptech.exemplojwt.service.usuario.dto.UsuarioCriacaoDto;

@RestController
@RequestMapping("/usuarios")
public class UsuarioController {

  @Autowired
  private UsuarioService usuarioService;

  @PostMapping("/criar")
  public ResponseEntity<Void> criar(@RequestBody UsuarioCriacaoDto usuarioCriacaoDto) {
    this.usuarioService.criar(usuarioCriacaoDto);
    return ResponseEntity.status(201).build();
  }

  @PostMapping("/login")
  public ResponseEntity<UsuarioTokenDto> login(@RequestBody UsuarioLoginDto usuarioLoginDto) {
    UsuarioTokenDto usuarioTokenDto = this.usuarioService.autenticar(usuarioLoginDto);

    return ResponseEntity.status(200).body(usuarioTokenDto);
  }
}