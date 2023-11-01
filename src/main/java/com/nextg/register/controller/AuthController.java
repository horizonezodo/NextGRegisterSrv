package com.nextg.register.controller;

import com.nextg.register.jwt.JwtUtils;
import com.nextg.register.model.Account;
import com.nextg.register.model.ERole;
import com.nextg.register.model.Role;
import com.nextg.register.repo.AccountRepository;
import com.nextg.register.repo.RoleRepository;
import com.nextg.register.request.*;
import com.nextg.register.response.MessageResponse;
import com.nextg.register.response.RegisterReponse;
import com.nextg.register.response.UserInfoResponse;
import com.nextg.register.service.AccountDetailsImpl;
import com.nextg.register.service.MailService;
import com.nextg.register.service.OtpService;
import com.nextg.register.service.SmsService;
import jakarta.mail.MessagingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    AuthenticationManager manager;

    @Autowired
    AccountRepository accRepo;

    @Autowired
    RoleRepository roleRepo;

    @Autowired
    JwtUtils untils;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    private MailService mailService;

    @Autowired
    private OtpService otpService;

    @Autowired
    private SmsService smsService;

    @Value("${signup.port}")
    private String portSignup;

    @PostMapping("/login")
    public ResponseEntity<?> authenticationUserUsingEmail(@RequestBody LoginRequest request){
        Authentication authentication = manager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        AccountDetailsImpl accDetails = (AccountDetailsImpl) authentication.getPrincipal();
        String jwt = untils.generateJwtTokenForLogin(accDetails);

        List<String> roles = accDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());


        return ResponseEntity.ok(
                new UserInfoResponse(
                        accDetails.getId(), accDetails.getUsername(),
                        accDetails.getEmail(), accDetails.getPhone()
                        , roles, jwt
                ));
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUserUsingEmail(@RequestBody RegisterRequest request){
        String tokenSigunp = request.getTokenSignup();
        if((!untils.validateEmail(request.getEmail(), tokenSigunp)) && (untils.validateJwtToken(tokenSigunp))){
            return new ResponseEntity<>(new MessageResponse("Error: Email has not valid"),HttpStatus.NO_CONTENT);
        }

        Account createAccount = new Account(request.getUsername(), request.getEmail(),
                encoder.encode(request.getPassword()), request.getPhone(), request.getFirstName(), request.getLastName(), request.getStatus());

        Set<String> strRole = request.getRoles();
        Set<Role> roles = new HashSet<>();

        if(strRole == null){
            Role userRole = roleRepo.findByName(ERole.ROLE_USER)
                    .orElseThrow(()-> new RuntimeException("Error: Role is not found"));
            roles.add(userRole);
        }else{
            strRole.forEach(role ->{
                switch (role){
                    case "admin":
                        Role admin = roleRepo.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(()-> new RuntimeException("Error: Role is not found"));
                        roles.add(admin);
                        break;
                    case "manager":
                        Role manager = roleRepo.findByName(ERole.ROLE_MANAGER)
                                .orElseThrow(()-> new RuntimeException("Error: Role is not found"));
                        roles.add(manager);
                        break;
                    case "mod":
                        Role mod = roleRepo.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(()-> new RuntimeException("Error: Role is not found"));
                        roles.add(mod);
                        break;
                    default:
                        Role userRole = roleRepo.findByName(ERole.ROLE_USER)
                                .orElseThrow(()-> new RuntimeException("Error: Role is not found"));
                        roles.add(userRole);
                        break;
                }
            });
        }
        createAccount.setRoles(roles);
        accRepo.save(createAccount);

        RegisterReponse res = new RegisterReponse();
        res.setEmail(createAccount.getEmail());
        res.setPassword(request.getPassword());

        return new ResponseEntity<>(res, HttpStatus.CREATED);
    }

    @PostMapping("/verifyEmail")
    public ResponseEntity<?> getEmailVerification(@RequestParam String email) throws MessagingException {
        if(accRepo.existsByEmail(email)){
            return new ResponseEntity<>(new MessageResponse("Your email has been registered"),HttpStatus.BAD_REQUEST);
        }

        String jwt = untils.generateTokenToSignup(email);
        mailService.SendMail(email,jwt);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @GetMapping("/verifySuccess")
    public RedirectView verifySuccess(@RequestParam String email, @RequestParam String token){

        System.out.println("token " + token + " email : " + email);
        if(untils.validateEmail(email,token)){
            return new RedirectView(portSignup + "?email="+email+"&token="+token+"");
        }
        return new RedirectView("");
    }

    @PostMapping("/verifyPhone")
    public ResponseEntity<?> getPhoneVerification(@RequestBody OtpRequest req) throws MessagingException {
        if(accRepo.existsByPhone(req.getPhoneNumber())){
            return new ResponseEntity<>(new MessageResponse("Your phone has been registered"),HttpStatus.BAD_REQUEST);
        }
//        otpService.sendOtp(phone);
          smsService.sendSMS(req);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @GetMapping("/verifyPhoneSuccess")
    public ResponseEntity<?> verifyPhoneSuccess(@RequestBody OtpValidationRequest req){

        return new ResponseEntity<>(smsService.validateOtp(req),HttpStatus.OK);
    }

    @PostMapping("/registerByPhone")
    public ResponseEntity<?> registerUserUsingPhone(@RequestBody RegisterRequest request){
        String tokenSigunp = request.getTokenSignup();

        if((!untils.validatePhone(request.getPhone(), tokenSigunp)) && (untils.validateJwtToken(tokenSigunp))){
            return new ResponseEntity<>(new MessageResponse("Error: Phone has not valid"),HttpStatus.NO_CONTENT);
        }

        Account createAccount = new Account(request.getUsername(), request.getEmail(),
                encoder.encode(request.getPassword()), request.getPhone(), request.getFirstName(), request.getLastName(), request.getStatus());

        Set<String> strRole = request.getRoles();
        Set<Role> roles = new HashSet<>();

        if(strRole == null){
            Role userRole = roleRepo.findByName(ERole.ROLE_USER)
                    .orElseThrow(()-> new RuntimeException("Error: Role is not found"));
            roles.add(userRole);
        }else{
            strRole.forEach(role ->{
                switch (role){
                    case "admin":
                        Role admin = roleRepo.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(()-> new RuntimeException("Error: Role is not found"));
                        roles.add(admin);
                        break;
                    case "manager":
                        Role manager = roleRepo.findByName(ERole.ROLE_MANAGER)
                                .orElseThrow(()-> new RuntimeException("Error: Role is not found"));
                        roles.add(manager);
                        break;
                    case "mod":
                        Role mod = roleRepo.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(()-> new RuntimeException("Error: Role is not found"));
                        roles.add(mod);
                        break;
                    default:
                        Role userRole = roleRepo.findByName(ERole.ROLE_USER)
                                .orElseThrow(()-> new RuntimeException("Error: Role is not found"));
                        roles.add(userRole);
                        break;
                }
            });
        }
        createAccount.setRoles(roles);
        accRepo.save(createAccount);

        RegisterReponse res = new RegisterReponse();
        res.setEmail(createAccount.getEmail());
        res.setPassword(request.getPassword());

        return new ResponseEntity<>(res, HttpStatus.CREATED);
    }

    @PostMapping("/loginByPhone")
    public ResponseEntity<?> authenticationUserUsingPhong(@RequestBody LoginByPhoneRequest request){
        Authentication authentication = manager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getPhone(), request.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        AccountDetailsImpl accDetails = (AccountDetailsImpl) authentication.getPrincipal();
        String jwt = untils.generateJwtTokenForLogin(accDetails);

        List<String> roles = accDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());


        return ResponseEntity.ok(
                new UserInfoResponse(
                        accDetails.getId(), accDetails.getUsername(),
                        accDetails.getEmail(), accDetails.getPhone()
                        , roles, jwt
                ));
    }


}
