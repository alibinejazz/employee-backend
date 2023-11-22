package com.bankalfalah.app.employeeportal.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bankalfalah.app.employeeportal.models.ERole;
import com.bankalfalah.app.employeeportal.models.Role;
import com.bankalfalah.app.employeeportal.models.User;
import com.bankalfalah.app.employeeportal.payload.request.LoginRequest;
import com.bankalfalah.app.employeeportal.payload.request.PasswordRequest;
import com.bankalfalah.app.employeeportal.payload.request.SignupRequest;
import com.bankalfalah.app.employeeportal.payload.response.JwtResponse;
import com.bankalfalah.app.employeeportal.payload.response.MessageResponse;
import com.bankalfalah.app.employeeportal.repository.RoleRepository;
import com.bankalfalah.app.employeeportal.repository.UserRepository;
import com.bankalfalah.app.employeeportal.security.jwt.JwtUtils;
import com.bankalfalah.app.employeeportal.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager
        .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
    List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
        .collect(Collectors.toList());
    JwtResponse resp = new JwtResponse(jwt, userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles);
    resp.setFullName(userDetails.getUserFullName());
    return ResponseEntity
        .ok(resp);
  }

  @PostMapping("/resetpassword")
  public ResponseEntity<?> resetPassword(@Valid @RequestBody PasswordRequest passwordRequest) {
    String message = "Verfication Code sent on your registered email.";
    Optional<User> user = userRepository.findByUsername(passwordRequest.getUsername());
    if (!user.isPresent()) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: User does not exist!"));
    }
    User obUser = user.get();
    if(passwordRequest.getOtp() == null || "".equals(passwordRequest.getOtp())){
        String otp = String.format("%04d", new Random().nextInt(10000));
        obUser.setOtp(otp);
        userRepository.save(obUser);
        message = "Verfication Code sent on your registered email.";
    }else if((obUser.getOtp().equals(passwordRequest.getOtp()))){

      if(passwordRequest.getPassword()!= null && !"".equals(passwordRequest.getPassword())){
          obUser.setPassword(encoder.encode(passwordRequest.getPassword()));
          obUser.setOtp(null);
          userRepository.save(obUser);
          message = "All Done!";
      }else{
          message = "Error: Password is empty";  
      }
      
    }else{
      message = "Error:Incorrect OTP.";  
      return ResponseEntity.badRequest().body(new MessageResponse(message));
    }

    return ResponseEntity.ok(new MessageResponse(message));
    
  }

  //

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already taken!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create new user's account
    User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),"");
        user.setFullName(signUpRequest.getFullName());

      String otp = String.format("%04d", new Random().nextInt(10000));
      user.setOtp(otp);


    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
        case "admin":
          Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(adminRole);

          break;
        case "mod":
          Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(modRole);

          break;
        default:
          Role userRole = roleRepository.findByName(ERole.ROLE_USER)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(userRole);
        }
      });
    }

    user.setRoles(roles);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }
}
