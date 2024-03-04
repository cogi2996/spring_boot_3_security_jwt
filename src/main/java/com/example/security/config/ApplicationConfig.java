package com.example.security.config;

import com.example.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor

public class ApplicationConfig {

    private final UserRepository userRepository;
    // UserDetailsService: cung cấp thông tin người dùng để Spring Security sử dụng
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User with email " + username + " not found"));
    }
    // AuthenticationProvider: cung cấp cơ chế xác thực cho Spring Security
    //Lấy thông tin người dùng từ cơ sở dữ liệu hoặc nguồn khác (ví dụ: sử dụng UserDetailsService)
    //So sánh thông tin đăng nhập do người dùng cung cấp (ví dụ: tên người dùng, mật khẩu) với thông tin được lưu trữ (ví dụ: sử dụng PasswordEncoder)
    //Trả về đối tượng người dùng đã được xác thực nếu thông tin đăng nhập khớp hoặc ném ngoại lệ nếu không khớp.
    @Bean
    public AuthenticationProvider authenticationProvider() {
        //DaoAuthenticationProvider: cung cấp cơ chế xác thực cho Spring Security
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
    // AuthenticationManager: quản lý việc xác thực người dùng
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
