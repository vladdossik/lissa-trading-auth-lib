package lissa.trading.lissa.auth.lib.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
public abstract class BaseAuthTokenFilter<T> extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        if (shouldSkipFilter(request)) {
            log.info("Skipping JWT filter for URI: {} in Thread: {}", request.getRequestURI(), Thread.currentThread().getName());
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String token = parseJwt(request);
            if (token == null || !validateJwtToken(token)) {
                log.warn("Token is null or invalid for request URI: {}", request.getRequestURI());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
                return;
            }

            T userInfo = retrieveUserInfo(token);
            if (userInfo == null) {
                log.warn("No user info found for token: {}", token);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "No user info found");
                return;
            }

            List<String> roles = parseRoles(userInfo);
            if (roles.isEmpty()) {
                log.warn("No roles found for token: {}", token);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "No roles found");
                return;
            }

            setAuthentication(userInfo, roles, request);

        } catch (Exception ex) {
            log.error("Cannot set user authentication: {}", ex.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
            return;
        }
        filterChain.doFilter(request, response);
    }

    private void setAuthentication(T userInfo, List<String> roles, HttpServletRequest request) {
        List<SimpleGrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();

        log.debug("Setting authentication for token");

        String tinkoffToken = decodeTinkoffToken(userInfo);
        if (tinkoffToken != null) {
            updateTinkoffToken(tinkoffToken);
        }

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userInfo, null, authorities);
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }


    protected abstract List<String> parseRoles(T userInfo);

    protected abstract T retrieveUserInfo(String token);

    protected boolean validateJwtToken(String token) {
        return token != null && !token.isEmpty();
    }

    protected String decodeTinkoffToken(T userInfo) {
        log.debug("Base implementation of decodeTinkoffToken - no action taken.");
        return null; // Override in subclass if needed
    }

    protected void updateTinkoffToken(String tinkoffToken) {
        log.debug("Base implementation of updateTinkoffToken - no action taken.");
    }

    protected boolean shouldSkipFilter(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return requestURI.startsWith("/swagger-ui/") ||
                requestURI.startsWith("/v3/api-docs/");
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        log.info("Invalid token format, missing 'Bearer' prefix. Token: {}", headerAuth);
        return null;
    }
}