package school.sptech.securityjwt.api.controller;

import org.springframework.http.ResponseEntity;
import school.sptech.securityjwt.domain.usuario.Usuario;
import org.springframework.web.bind.annotation.*;
import school.sptech.securityjwt.service.usuario.UsuarioService;
import school.sptech.securityjwt.service.usuario.dto.UsuarioCriarDto;
import org.springframework.beans.factory.annotation.Autowired;
import school.sptech.securityjwt.service.autenticacao.dto.UsuarioLoginDto;
import school.sptech.securityjwt.service.autenticacao.dto.UsuarioTokenDto;

import java.util.List;

@RestController
@RequestMapping("/usuarios")
public class UsuarioController {

    @Autowired
    private UsuarioService usuarioService;

    @GetMapping
    public ResponseEntity<List<Usuario>> findAll(){
        List<Usuario> todosUsuarios = usuarioService.buscarTodos();

        if (todosUsuarios.isEmpty()){
            return ResponseEntity.status(201).build();
        }

        return ResponseEntity.status(200).body(todosUsuarios);
    }

    @PostMapping("/login")
    public ResponseEntity<UsuarioTokenDto> login(@RequestBody UsuarioLoginDto usuarioLoginDto){
        UsuarioTokenDto usuarioToken = this.usuarioService.autenticar(usuarioLoginDto);
        return ResponseEntity.status(200).body(usuarioToken);
    }

    @PostMapping
    public ResponseEntity<Void> criar(@RequestBody UsuarioCriarDto usuarioCriarDto){
        this.usuarioService.criar(usuarioCriarDto);
        return ResponseEntity.status(201).build();
    }
}
