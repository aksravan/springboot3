package com.example.TEST.config;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

public class AuthSuccessHandler implements AuthenticationSuccessHandler {

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request,
      HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    HttpSession session = request.getSession();
    User authUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    session.setAttribute("user", authUser);
    session.setAttribute("username", authUser.getUsername());
    session.setAttribute("authorities", authentication.getAuthorities());

    // set our response to OK status
    response.setStatus(HttpServletResponse.SC_OK);

    String targetUrl = determineTargetUrl(authentication);

    // since we have created our custom success handler, its up to us, to where
    // we will redirect the user after successfully login
    response.sendRedirect(targetUrl); // requestUrl!=null?requestUrl:
  }

  protected String determineTargetUrl(final Authentication authentication) {

        Map<String, String> roleTargetUrlMap = new HashMap<>();
        roleTargetUrlMap.put("ROLE_ADMIN", "/home");
        roleTargetUrlMap.put("ROLE_USER", "/home");

        final Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        for (final GrantedAuthority grantedAuthority : authorities) {
            String authorityName = grantedAuthority.getAuthority();
            if (roleTargetUrlMap.containsKey(authorityName)) {
                return roleTargetUrlMap.get(authorityName);
            } else {
                return roleTargetUrlMap.get("both");
            }
        }

        throw new IllegalStateException();
    }
}