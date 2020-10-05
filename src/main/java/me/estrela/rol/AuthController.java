package me.estrela.rol;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.view.RedirectView;

@Controller
public class AuthController {

    @Value("${readme.hub.url}")
    private String readmeHubUrl;

    @Value("${readme.secret}")
    private String readmeJwtSecret;

    @GetMapping(value = "/auth")
    public RedirectView auth(@AuthenticationPrincipal OidcUser user) {
        RedirectView redirectView = new RedirectView();
        String jwt = sign(user);
        redirectView.setUrl(readmeHubUrl + "?auth_token=" + jwt);
        return redirectView;
    }

    private String sign(OidcUser user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(readmeJwtSecret);
            return JWT.create()
                    .withClaim("name", user.getName())
                    .withClaim("mail", user.getEmail())
                    .withClaim("isAdmin", true)
                    .withClaim("apiKey", user.getIdToken().getTokenValue())
                    .withClaim("isReadOnly", false)
                    .withClaim("version", 1)
                    .sign(algorithm);
        } catch (JWTCreationException ignore) {
            throw new IllegalStateException("failed to sign JWT");
        }
    }

}