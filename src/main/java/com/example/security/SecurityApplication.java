package com.example.security;

import com.example.security.auth.AuthenticationService;
import com.example.security.auth.RegisterRequest;
import com.example.security.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.transaction.annotation.Transactional;

@SpringBootApplication
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

//    @Bean
//    @Transactional
//    public CommandLineRunner commandLineRunner() {
//        return args -> {
//            try {
//                System.out.println("ket noi thanh cong");
//                // Do your database operations here
//            } catch (Exception e) {
//                System.err.println("Ket noi that bai" + e.getMessage());
//            }
//        };
//    }

    // input có thể inject bất kì bean nào khác
    @Bean
    CommandLineRunner commandLineRunner(
            AuthenticationService service
    ) {
        return args -> {
            var admin = new RegisterRequest().builder()
                    .firstName("Admin")
                    .lastName("Admin")
                    .email("admin@gmail.com")
                    .password("password")
                    .role(Role.ADMIN)
                    .build();
			var manager = new RegisterRequest().builder()
					.firstName("Admin")
					.lastName("Admin")
					.email("manager@gmail.com")
					.password("password")
					.role(Role.MANAGER)
					.build();
			System.out.println("Admin token : "+ service.register(admin).getAccessToken());
			System.out.println("Manager token : "+ service.register(manager).getAccessToken());

        };
    }
}
