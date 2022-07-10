package com.barbera.bestudy.configures;

import com.barbera.bestudy.oauth2.OAuth2AuthenticationSuccessHandler;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Override
    // Note : AuthenticationManagerBuilder를 이용하면 로그인 가능한 계정을 추가해 줄 수 있음
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("user").password("{noop}user123").roles("USER")
            .and()
            .withUser("admin").password("{noop}admin123").roles("ADMIN")
        ;
    }

    @Override
    // Note : 해당 경로의 파일들은 필터를 거치지 않도록 설정함
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/assets/**");
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // Note: 권한 설정
            .authorizeRequests()
                .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                // admin 페이지에는 ADMIN권한을 가지고, remember-me로 접근하지 않고 정상적으로 로그인한 사용자만 접근가능
                .antMatchers("/admin").access("hasRole('ADMIN') and isFullyAuthenticated()")
                .anyRequest().permitAll()
                .and()
            // Note: 로그인 설정
            .formLogin()
                .defaultSuccessUrl("/")
                .permitAll()
                .and()
            // Note: 로그아웃 설정
            .logout()
                // 아래의 4개의 체인메서드는 Logout Filter에서 default값으로 설정된 값이므로 삭제해도 ㄱㅊ
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .and()
            // Note: 쿠키 기반의 자동로그인(remember-me) 활성화, 저장된 쿠키가 있으면 autoLogin
            .rememberMe()
                .rememberMeParameter("remember-me")
                .tokenValiditySeconds(300)
                .and()
            // Note: 전송 레이어 보안 적용 (ChannelProcessingFilter) - HTTPS 채널을 통해 처리해야 하는 웹 요청을 정의
            .requiresChannel()
//                .antMatchers("/api/**").requiresSecure() // /api 하위경로 요청이 HTTPS로 동작하도록 설정
                .anyRequest().requiresSecure() // 모든 요청이 HTTPS로 동작해야만 하도록 설정
                .and()
            // Note: (AnonymousAuthenticationFilter) 에 요청이 도달할때까지 사용자가 인증되지 않았다면, 사용자를 null 대신 Anonymous 인증 타입으로 표현해 줌
            .anonymous()
                .principal("thisIsAnonymousUser") // default: anonymousUser
                .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN") // default: ROLE_ANONYMOUS 한개
                .and()

            .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
                .and()
            // Note: OAuth2 로그인 설정
            .oauth2Login()
                .successHandler(oAuth2AuthenticationSuccessHandler()) // OAuth2 인증 이후 핸들러 호출
        ;
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain");
            response.getWriter().write("## ACCESS DENIED ##");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    @Bean
    // Note: 위의 configure에서 사용할 Bean 생성
    public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler();
    }

}