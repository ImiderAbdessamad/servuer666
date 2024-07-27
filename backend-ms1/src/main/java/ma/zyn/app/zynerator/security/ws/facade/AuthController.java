package ma.zyn.app.zynerator.security.ws.facade;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import ma.zyn.app.zynerator.security.bean.User;
import ma.zyn.app.zynerator.security.common.SecurityParams;
import ma.zyn.app.zynerator.security.dao.facade.core.RoleDao;
import ma.zyn.app.zynerator.security.service.facade.UserService;
import ma.zyn.app.zynerator.security.ws.dto.UserDto;
import ma.zyn.app.zynerator.security.ws.dto.ForgetPasswordRequest;
import ma.zyn.app.zynerator.security.ws.converter.UserConverter;

import ma.zyn.app.zynerator.security.jwt.JwtUtils;
import ma.zyn.app.zynerator.security.payload.request.LoginRequest;
import ma.zyn.app.zynerator.security.payload.response.JwtResponse;

import ma.zyn.app.zynerator.transverse.emailling.EmailRequest;
import ma.zyn.app.zynerator.transverse.emailling.EmailService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.web.bind.annotation.*;


import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.stream.Collectors;

import java.io.IOException;

//@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserService userService;

  @Autowired
  UserConverter userConverter;

  @Autowired
  EmailService emailService;

  @Autowired
  RoleDao roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @PostMapping("register")
  public ResponseEntity<Map<String, String>> register(@RequestBody UserDto userDto) {

    if (userService.findByUsername(userDto.getUsername()) != null) {
      return ResponseEntity
              .badRequest()
              .body(Collections.singletonMap("error", "This username has already been taken"));
    }
    if (userService.findByEmail(userDto.getEmail()) != null) {
      return ResponseEntity
              .badRequest()
              .body(Collections.singletonMap("error", "This email is already on use "));
    }


    LocalDateTime expirationDate = LocalDateTime.now().plus(24, ChronoUnit.HOURS);
    userDto.setEnabled(false);
    userDto.setExpirationLinkDate(expirationDate);
    userDto.setLinkValidationCode(userService.generateCode(8));
    EmailRequest emailRequest = new EmailRequest();
    emailRequest.setFrom("votre email");
    emailRequest.setBcc(userDto.getEmail());
    emailRequest.setCc(userDto.getEmail());
    emailRequest.setTo(userDto.getEmail());
    emailRequest.setSubject("Verify your email");
    emailRequest.setBody("Welcome to Zynerator !! Your activation code is" + userDto.getLinkValidationCode());
    userConverter.setRoleUsers(true);
    User user = userConverter.toItem(userDto);

    userService.createAndDisable(user);
    emailService.sendSimpleMessage(emailRequest);

    Map<String, String> response = new HashMap<>();
    response.put("message", "You have registered successfully");
    return ResponseEntity.ok(response);
  }
  
  
  @GetMapping("verify")
  public void verifyUser(@RequestParam("code") String code, HttpServletResponse response) throws IOException {
    User user = userService.findByLinkValidationCode(code);
    if (user != null) {
      if (isActivationLinkValid(user)) { // Vérifier la validité du lien
        user.setEnabled(true);
        userService.update(user);

        response.sendRedirect("http://localhost:4200/login");
      } else {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Le lien d'activation du compte a expiré.");
      }
    } else {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Code de vérification invalide.");
    }
  }


  private boolean isActivationLinkValid(User user) {
    LocalDateTime now = LocalDateTime.now();
    LocalDateTime expiry = user.getExpirationLinkDate();
    return expiry != null && now.isBefore(expiry);
  }
  
  @PostMapping("login")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);
    User userDetails = (User) authentication.getPrincipal();
    List<String> roles = userDetails.getRoleUsers().stream()
            .map(item -> item.getRole().getAuthority())
            .collect(Collectors.toList());

    HttpHeaders headers = new HttpHeaders();
    headers.add(SecurityParams.JWT_HEADER_NAME,SecurityParams.HEADER_PREFIX+jwt);
    return ResponseEntity.ok()
            .headers(headers)
            .body(new JwtResponse(jwt,
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    roles));
  }
  
   
    @PutMapping("forgetPassword")
    public ResponseEntity<Map<String, String>> forgetPassword(@RequestBody ForgetPasswordRequest forgetPasswordRequest) {
        User user = userService.findByEmail(forgetPasswordRequest.getEmail());

        if (user != null) {
            if (user.getLinkValidationCode().equals(forgetPasswordRequest.getLinkValidationCode())) {

                boolean passwordChanged = userService.changePassword(user.getUsername(), forgetPasswordRequest.getNewPassword());

                if (passwordChanged) {
                    EmailRequest emailRequest = new EmailRequest();
                    emailRequest.setFrom(user.getEmail());
                    emailRequest.setBcc(user.getEmail());
                    emailRequest.setCc(user.getEmail());
                    emailRequest.setTo(user.getEmail());
                    emailRequest.setSubject("Verify your email");
                    emailRequest.setBody("your password has been changed");
                    emailService.sendSimpleMessage(emailRequest);
                    Map<String, String> response = new HashMap<>();
                    response.put("message", "check your email");
                    return ResponseEntity.ok(response);
                }
            } else {
                ResponseEntity.badRequest().body(Collections.singletonMap("error", "invalid verification code"));
            }
        }
        return ResponseEntity.badRequest().body(Collections.singletonMap("error", "Your email  is uncorrect"));
    }


}
