package kopo.poly.config;

import kopo.poly.auth.JwtTokenProvider;
import kopo.poly.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        log.info(this.getClass().getName() + ".PasswordEncoder Start!");
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        log.info(this.getClass().getName() + ".filterChain Start!");

        // POST 방식 전송을 위해 csrf 막기
        http.csrf().disable();

        http
                .authorizeHttpRequests(authz -> authz // 페이지 접속 권한 설정
                        // USER 권한
                        .antMatchers("/user/**", "/notice/**").hasAnyAuthority("ROLE_USER")

                        // 관리자 권한
                        .antMatchers("/admin/**").hasAnyAuthority("ROLE_ADMIN")
                        .anyRequest().permitAll() // 그 외 나머지 url 요청은 인증 받지 않아도 접속 가능함
                )
                .formLogin(login -> login // 로그인 페이지 설정
                        .loginPage("/ss/loginForm")
                        .loginProcessingUrl("/ss/loginProc")
                        .usernameParameter("user_id") // 로그인 ID로 사용할 html의 input객체의 name 값
                        .passwordParameter("password") // 로그인 패스워드로 사용할 html의 input객체의 name 값

                        // 로그인 성공
                        .successForwardUrl("/jwt/loginSuccess") // Web MVC, Controller 사용할 때 적용 / 로그인 성공 URL
                        .failureForwardUrl("/jwt/loginFail") // Web MVC, Controller 사용할 때 적용 / 로그인 실패 URL

                )
                .logout(logout -> logout // 로그 아웃 처리
                        .logoutSuccessUrl("/")
                )
                // Spring Security의 UsernamePasswordAuthenticationFilter가 실행되지 전에
                // 내가 만든 JwtAuthenticationFilter 필터가 실행되도록 설정함
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider),
                        UsernamePasswordAuthenticationFilter.class)

                // 세션 사용하지 않도록 설정함
                .sessionManagement(ss -> ss.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

}
