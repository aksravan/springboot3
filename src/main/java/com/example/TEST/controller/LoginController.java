package com.example.TEST.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class LoginController {

    @GetMapping("/")
    public String defaultPage() {
        return new String("redirect:/login");
    }

    @GetMapping("/login")
    public String showIndexPage(final Model model, HttpServletRequest request, Authentication auth,
            @RequestParam(value = "error", required = false) String error)
            throws Exception {
        if (auth != null && auth.isAuthenticated()) {
            model.addAttribute("user", auth.getAuthorities());
            return "redirect:home";
        }

        if (error != null && error.length() != 0) {
            model.addAttribute("error", error);
        }
        return "login";
    }

    @GetMapping("/home")
    public String home() {
        return new String("home");
    }

}
