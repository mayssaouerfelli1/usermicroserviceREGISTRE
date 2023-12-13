package com.mayssa.users.restControllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mayssa.users.entities.User;
import com.mayssa.users.repos.UserRepository;
import com.mayssa.users.service.UserService;
import com.mayssa.users.service.register.RegistrationRequest;

@RestController
@CrossOrigin(origins = "http://localhost:4200")
public class UserRestController {
    
    @Autowired
    private UserRepository userRep;

    @Autowired
    private UserService userService;

    @GetMapping("/allUsers")
    @PreAuthorize("hasAuthority('ADMIN')")
    public List<User> getAllUsers() {
        return userService.findAllUsers();
    }

    @PostMapping("/register")
    public User register(@RequestBody RegistrationRequest request) {
        return userService.registerUser(request);
    }
    
    @GetMapping("/verifyEmail/{token}")
    public User verifyEmail(@PathVariable("token") String token){ 
   return userService.validateToken(token);
    }

    
    
    
    
}
