package com.example.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request
            ,@NonNull HttpServletResponse response
            , @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        // lấy ra jwt từ request
        final String authHeader = request.getHeader("Authorization");
        System.out.println(authHeader);
        final String jwt;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        System.out.println(jwt);
        // lấy ra email từ jwt
        userEmail = jwtService.extractUsername(jwt);
        System.out.println("userEmail: " + userEmail);

        // kiểm tra xem email có tồn tại trong hệ thống không
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            // kiểm tra xem jwt có hợp lệ không ( user jwt này mapp đúng với user trong hệ thống không)
            if(jwtService.isTokenValid(jwt, userDetails)){
                // tạo ra thông tin xác thực và lưu vào context của hệ thống
                // thông tin xác thực này được dùng cho các request tiếp theo
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                // phương thức setDetails() được tạo bên ngoài object authToken, trỏ đến context request đã gửi của user
                // nó sẽ được sử dụng để xác thực user
                // thêm  địa chỉ IP của người dùng, trình duyệt web và các thông tin khác của user vào authToken
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // sau khi xác thực thành công, lưu thông tin vào context của hệ thống
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        // chuyển request và response cho filter tiếp theo vì người dùng đã có trong context của hệ thống
        filterChain.doFilter(request, response);


    }
}
