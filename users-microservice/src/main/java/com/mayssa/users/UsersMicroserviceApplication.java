package com.mayssa.users;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.mayssa.users.entities.Role;
import com.mayssa.users.entities.User;
import com.mayssa.users.service.UserService;

import jakarta.annotation.PostConstruct;

@SpringBootApplication
public class UsersMicroserviceApplication {

    public static void main(String[] args) {
        SpringApplication.run(UsersMicroserviceApplication.class, args);
    }

    @Autowired
    UserService userService;
/*
    @PostConstruct
    void init_users() {
        // Ajouter les rôles
        userService.addRole(new Role(null, "ADMIN"));
        userService.addRole(new Role(null, "USER"));

        // Ajouter les utilisateurs
        userService.saveUser(new User(null, "admin", "123", true, null));
        userService.saveUser(new User(null, "nadhem", "123", true, null));
        userService.saveUser(new User(null, "yassine", "123", true, null));

        // Ajouter les rôles aux utilisateurs
        userService.addRoleToUser("admin", "ADMIN");
        userService.addRoleToUser("admin", "USER");
        userService.addRoleToUser("nadhem", "USER");
        userService.addRoleToUser("yassine", "USER");
    }*/

    @Bean
    BCryptPasswordEncoder getBCE() {
        return new BCryptPasswordEncoder();
    }
}
