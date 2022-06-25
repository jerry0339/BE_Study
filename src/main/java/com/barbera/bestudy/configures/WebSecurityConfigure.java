package com.barbera.bestudy.configures;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    // Note : AuthenticationManagerBuilder를 이용하면 로그인 가능한 계정을 추가해 줄 수 있다.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("user").password("{noop}user123").roles("USER")
            .and()
            .withUser("admin").password("{noop}admin123").roles("ADMIN")
        ;
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/assets/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                .anyRequest().permitAll()
                .and()
            .formLogin()
                .defaultSuccessUrl("/")
                .permitAll()
                .and()
            .logout()
                // Note: 아래의 4개의 체인메서드는 Logout Filter에서 default값으로 설정된 값이므로 삭제해도 ㄱㅊ
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .and()
            .rememberMe()
                // Note: 쿠키 기반의 자동로그인(remember-me) 활성화, 저장된 쿠키가 있으면 autoLogin
                .rememberMeParameter("remember-me")
                .tokenValiditySeconds(300)
//                .and()
//            .requiresChannel()
//                // Note: 모든 요청이 HTTPS로 동작해야만 하도록 설정
//                .anyRequest().requiresSecure()
        ;
    }

}