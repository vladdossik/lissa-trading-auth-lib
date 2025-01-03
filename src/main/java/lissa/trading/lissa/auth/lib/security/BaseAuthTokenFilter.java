package lissa.trading.lissa.auth.lib.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lissa.trading.lissa.auth.lib.dto.UpdateTinkoffTokenResponce;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Abstract base class for JWT authentication filters.
 * This filter processes incoming HTTP requests to authenticate users based on JWT tokens.
 *
 * @param <T> The type of user information object.
 */
@Slf4j
public abstract class BaseAuthTokenFilter<T> extends OncePerRequestFilter {

    /**
     * Filters incoming requests to authenticate users based on JWT tokens.
     *
     * @param request     the HTTP request
     * @param response    the HTTP response
     * @param filterChain the filter chain
     * @throws ServletException if an error occurs during filtering
     * @throws IOException      if an I/O error occurs during filtering
     */
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

    /**
     * Sets the authentication for the current request.
     *
     * @param userInfo the user information object
     * @param roles    the list of roles
     * @param request  the HTTP request
     */
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

    /**
     * Parses the roles from the user information object.
     *
     * @param userInfo the user information object
     * @return the list of roles
     */
    protected abstract List<String> parseRoles(T userInfo);

    /**
     * Retrieves the user information object from the JWT token.
     *
     * @param token the JWT token
     * @return the user information object
     */
    protected abstract T retrieveUserInfo(String token);

    /**
     * Validates the JWT token.
     *
     * @param token the JWT token
     * @return true if the token is valid, false otherwise
     */
    protected boolean validateJwtToken(String token) {
        return token != null && !token.isEmpty();
    }

    /**
     * Decodes the Tinkoff token from the user information object.
     *
     * @param userInfo the user information object
     * @return the Tinkoff token, or null if not applicable
     */
    protected String decodeTinkoffToken(T userInfo) {
        log.debug("Base implementation of decodeTinkoffToken - no action taken.");
        return null; // Override in subclass if needed
    }

    /**
     * Updates the Tinkoff token.
     *
     * @param tinkoffToken the Tinkoff token
     */
    protected UpdateTinkoffTokenResponce updateTinkoffToken(String tinkoffToken) {
        log.debug("Base implementation of updateTinkoffToken - no action taken.");
        return new UpdateTinkoffTokenResponce();
    }

    /**
     * Determines whether the filter should be skipped for the given request.
     *
     * @param request the HTTP request
     * @return true if the filter should be skipped, false otherwise
     */
    protected boolean shouldSkipFilter(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return requestURI.startsWith("/swagger-ui/") ||
                requestURI.startsWith("/v3/api-docs/") ||
                requestURI.startsWith("/v1/internal/") ||
                shouldSkipFilterAddons(requestURI);
    }

    /**
     * Additional conditions to determine whether the filter should be skipped.
     *
     * @param requestURI the request URI
     * @return true if the filter should be skipped, false otherwise
     */
    protected boolean shouldSkipFilterAddons(String requestURI) {
        return false; // Override in subclass if needed
    }

    /**
     * Parses the JWT token from the HTTP request.
     *
     * @param request the HTTP request
     * @return the JWT token, or null if not found or invalid
     */
    protected String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        log.info("Invalid token format, missing 'Bearer' prefix. Token: {}", headerAuth);
        return null;
    }
}