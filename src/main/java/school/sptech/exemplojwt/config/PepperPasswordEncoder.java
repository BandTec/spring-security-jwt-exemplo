package school.sptech.exemplojwt.config;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * {@link PasswordEncoder} que combina <b>Argon2id</b> com <b>Pepper</b>.
 *
 * <h3>Por que Argon2 em vez de BCrypt?</h3>
 * <p>BCrypt é CPU-hard: difícil de paralelizar em CPU, mas GPUs modernas têm
 * milhares de núcleos que conseguem rodar muitas instâncias em paralelo.
 * Argon2id é <b>memory-hard</b>: além de CPU, exige grande quantidade de RAM
 * por operação, tornando ataques com GPU inviáveis na prática.</p>
 *
 * <h3>Por que Pepper?</h3>
 * <p>Salt (já incluído pelo Argon2) protege contra Rainbow Tables mas fica
 * no banco — se o banco vazar, o atacante tem os salts e pode tentar brute
 * force (lento, mas possível para senhas fracas). O Pepper é uma chave
 * secreta que <b>não fica no banco</b> (variável de ambiente), tornando os
 * hashes inutilizáveis mesmo com o banco completamente exposto.</p>
 *
 * <h3>Fluxo de encode</h3>
 * <pre>
 *   rawPassword  ──┐
 *                  ├─► HMAC-SHA256(senha, pepper) ──► Base64 ──► Argon2id.encode() ──► hash
 *   pepper       ──┘
 * </pre>
 *
 * <p>HMAC é usado em vez de simples concatenação porque:</p>
 * <ul>
 *   <li>É resistente a length-extension attacks</li>
 *   <li>Produz output de tamanho fixo (32 bytes → 44 chars Base64)</li>
 *   <li>É o padrão criptográfico correto para "keyed hash"</li>
 * </ul>
 */
public class PepperPasswordEncoder implements PasswordEncoder {

    private final Argon2PasswordEncoder argon2;
    private final byte[] pepperBytes;

    /**
     * @param pepper valor do pepper (deve vir de variável de ambiente em produção)
     */
    public PepperPasswordEncoder(String pepper) {
        // Parâmetros recomendados pelo OWASP / Spring Security padrão v5.8+:
        //   saltLength=16, hashLength=32, parallelism=1, memory=65536 KB (64 MB), iterations=3
        this.argon2 = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        this.pepperBytes = pepper.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return argon2.encode(applyPepper(rawPassword));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return argon2.matches(applyPepper(rawPassword), encodedPassword);
    }

    /**
     * Aplica o pepper via HMAC-SHA256 e retorna o resultado em Base64.
     *
     * <p>O resultado é uma string de 44 caracteres, bem abaixo de qualquer
     * limite de tamanho de entrada do Argon2 — o que evita truncamentos silenciosos.</p>
     */
    private String applyPepper(CharSequence rawPassword) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(pepperBytes, "HmacSHA256"));
            byte[] hmac = mac.doFinal(rawPassword.toString().getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hmac);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao aplicar pepper na senha", e);
        }
    }
}
