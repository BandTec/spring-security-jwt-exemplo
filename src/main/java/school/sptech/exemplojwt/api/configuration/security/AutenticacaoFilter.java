package school.sptech.exemplojwt.api.configuration.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.context.SecurityContextHolder;
import school.sptech.exemplojwt.api.configuration.security.jwt.GerenciadorTokenJwt;
import school.sptech.exemplojwt.service.usuario.autenticacao.AutenticacaoService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.Objects;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AutenticacaoFilter extends OncePerRequestFilter {

  private static final Logger LOGGER = LoggerFactory.getLogger(AutenticacaoFilter.class);

  private final AutenticacaoService autenticacaoService;

  private final GerenciadorTokenJwt jwtTokenManager;

  public AutenticacaoFilter(AutenticacaoService autenticacaoService, GerenciadorTokenJwt jwtTokenManager) {
    this.autenticacaoService = autenticacaoService;
    this.jwtTokenManager = jwtTokenManager;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

    String username = null;
    String jwtToken = null;

    String requestTokenHeader = request.getHeader("Authorization");

    if (Objects.nonNull(requestTokenHeader) && requestTokenHeader.startsWith("Bearer ")) {
      jwtToken = requestTokenHeader.substring(7);

      try {
        username = jwtTokenManager.getUsernameFromToken(jwtToken);
      } catch (ExpiredJwtException exception) {

        LOGGER.info("[FALHA AUTENTICACAO] - Token expirado, usuario: {} - {}",
                exception.getClaims().getSubject(), exception.getMessage());

        LOGGER.trace("[FALHA AUTENTICACAO] - stack trace: %s", exception);

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      }

    }

    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      addUsernameInContext(request, username, jwtToken);
    }

    filterChain.doFilter(request, response);
  }

  private void addUsernameInContext(HttpServletRequest request, String username, String jwtToken) {

    UserDetails userDetails = autenticacaoService.loadUserByUsername(username);

    if (jwtTokenManager.validateToken(jwtToken, userDetails)) {

      UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
              userDetails, null, userDetails.getAuthorities());

      usernamePasswordAuthenticationToken
              .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

      SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }
  }
}