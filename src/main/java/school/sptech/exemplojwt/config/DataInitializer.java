package school.sptech.exemplojwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import school.sptech.exemplojwt.entity.Usuario;
import school.sptech.exemplojwt.repository.UsuarioRepository;

/**
 * Inicializa os dados de teste ao subir a aplicação.
 *
 * <p>Substitui o {@code data.sql} nesta branch porque o hash do usuário de
 * teste depende do PasswordEncoder ativo (Argon2+Pepper), que não pode ser
 * computado de forma estática em SQL.</p>
 *
 * <p>O usuário só é criado se ainda não existir — seguro para reinicializações.</p>
 */
@Component
public class DataInitializer implements ApplicationRunner {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        if (usuarioRepository.findByEmail("john@doe.com").isEmpty()) {
            Usuario usuario = new Usuario();
            usuario.setNome("John Doe");
            usuario.setEmail("john@doe.com");
            // A senha é hasheada aqui com Argon2+Pepper via PasswordEncoder injetado
            usuario.setSenha(passwordEncoder.encode("123456"));
            usuarioRepository.save(usuario);
        }
    }
}
