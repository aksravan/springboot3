package com.example.TEST.config;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.GenericFilterBean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class SessionCookieFilter extends GenericFilterBean {

	private final List<String> PATHS_TO_IGNORE_SETTING_SAMESITE = Arrays.asList("resources");
	private final String SESSION_PATH_ATTRIBUTE = ";Path=";
	private final String ROOT_CONTEXT = "/";
	private final String SAME_SITE_ATTRIBUTE_VALUES = ";HttpOnly;Secure;SameSite=Strict";

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse resp = (HttpServletResponse) response;
		String requestUrl = req.getRequestURL().toString();
		boolean isResourceRequest = requestUrl != null ? StringUtils.isNoneBlank(
				PATHS_TO_IGNORE_SETTING_SAMESITE.stream().filter(s -> requestUrl.contains(s)).findFirst().orElse(null))
				: null;
		if (!isResourceRequest) {
			Cookie[] cookies = ((HttpServletRequest) request).getCookies();
			if (cookies != null && cookies.length > 0) {
				List<Cookie> cookieList = Arrays.asList(cookies);
				for (Cookie cocks : cookieList) {
					String contextPath = request.getServletContext() != null
							&& StringUtils.isNotBlank(request.getServletContext().getContextPath())
									? request.getServletContext().getContextPath()
									: ROOT_CONTEXT;
					resp.setHeader(HttpHeaders.SET_COOKIE, cocks.getName() + "=" + cocks.getValue()
							+ SESSION_PATH_ATTRIBUTE + contextPath + SAME_SITE_ATTRIBUTE_VALUES);
				}
			}
		}

		chain.doFilter(request, response);
	}
}