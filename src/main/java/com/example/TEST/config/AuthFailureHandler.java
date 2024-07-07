package com.example.TEST.config;

import java.io.IOException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class AuthFailureHandler implements AuthenticationFailureHandler {

    public void onAuthenticationFailure(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {

        String targetUrl = "/login?error=Bad Request";
        if (exception.getMessage().equals("Access Denied")) {
            response.sendRedirect("/login?error=Access Denied");
        } else if (exception.getMessage().equals("Bad Credentials")) {
            response.sendRedirect("/login?error=Bad Credentials");
        }
        response.sendRedirect(targetUrl); // requestUrl!=null?requestUrl:
    }

}
