package com.nextg.register.controller;

import com.nextg.register.jwt.JwtUtils;
import com.nextg.register.model.Account;
import com.nextg.register.model.ERole;
import com.nextg.register.model.Role;
import com.nextg.register.repo.AccountRepository;
import com.nextg.register.repo.RoleRepository;
import com.nextg.register.request.*;
import com.nextg.register.response.*;
import com.nextg.register.service.AccountDetailsImpl;
import com.nextg.register.service.AccountServiceImpl;
import com.nextg.register.service.MailService;
import com.nextg.register.service.OtpService;
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

import java.util.ArrayList;
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
    private AccountServiceImpl accountService;

    @Value("${signup.port}")
    private String portSignup;

    @Value("${changePassword}")
    private String portChangePass;

    @PostMapping("/login")
    public ResponseEntity<?> authenticationUserUsingEmail(@RequestBody LoginRequest request){
        Account tmpAccount = accountService.findByEmail(request.getEmail());
        if(accountService.checkStatusAccount(tmpAccount.getStatus())) {
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
        return new ResponseEntity<>(new MessageResponse("Your account has been locked"), HttpStatus.BAD_REQUEST);
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

    @PostMapping("/send-otp")
    public ResponseEntity<?> sendOtp(@RequestBody OtpRequest otpRequest) {
        String phone = "+84"+ otpRequest.getPhoneNumber();
        OtpRequest req = new OtpRequest(phone);
        if(accRepo.existsByPhone(phone)){
            return new ResponseEntity<>( new MessageResponse("Phone number has been taken"), HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(otpService.sendSMS(req), HttpStatus.OK);
    }

//    @PostMapping("/validate-otp")
//    public RedirectView validateOtp(@RequestBody OtpValidationRequest otpValidationRequest) {
//        if(otpService.validateOtp(otpValidationRequest)){
//            return new RedirectView(portSignup + "?phone="+otpValidationRequest.getPhoneNumber()+"&otp="+otpValidationRequest.getOtpNumber()+"");
//        }
//        return new RedirectView("");
//    }

    @PostMapping("/validate-otp")
    public RedirectView validateOtp(@RequestParam String phone,@RequestParam String otp) {
        String tmpPhone = "+84" + phone;
        OtpValidationRequest otpValidationRequest = new OtpValidationRequest(tmpPhone,otp);
        if(otpService.validateOtp(otpValidationRequest)){
            return new RedirectView(portSignup + "?phone="+otpValidationRequest.getPhoneNumber()+"&otp="+otpValidationRequest.getOtpNumber()+"");
        }
        return new RedirectView("");
    }

    @PostMapping("/send-otp-login")
    public ResponseEntity<?> sendOtpLogin(@RequestBody OtpRequest otpRequest) {
        String phone = "+84"+ otpRequest.getPhoneNumber();
        OtpRequest req = new OtpRequest(phone);
        return new ResponseEntity<>(otpService.sendSMS(req), HttpStatus.OK);
    }

    @PostMapping("/loginByPhone")
    public ResponseEntity<?> loginByPhone(@RequestBody OtpValidationRequest request){

        String tmpPhone = "+84"+request.getPhoneNumber();
        System.out.println("Phone number " + tmpPhone+ " pasword: " + request.getOtpNumber());
        OtpValidationRequest req = new OtpValidationRequest(tmpPhone,request.getOtpNumber());
        Account acc = accountService.findByPhone(tmpPhone);
        if(accountService.checkStatusAccount(acc.getStatus())){
            if(otpService.validateOtp(req)){
                String jwt = untils.generateTokenFromPhone(tmpPhone);
                List<String> strRole= new ArrayList<String>();
                strRole.add("ROLE_USER");
                return ResponseEntity.ok(
                        new UserInfoResponse(
                                acc.getId(), acc.getUsername(),
                                acc.getEmail(), acc.getPhone()
                                ,strRole, jwt
                        ));
            }
            return new ResponseEntity<>(new MessageResponse("Otp is not valid"), HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(new MessageResponse("Your account is locked"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/registerByPhone")
    public ResponseEntity<?> registerUserUsingPhone(@RequestBody RegisterByPhoneRequest request){
        OtpValidationRequest req = new OtpValidationRequest();
        req.setPhoneNumber("+84" + request.getPhone());
        req.setOtpNumber(req.getOtpNumber());
        if(otpService.validateOtp(req)){
            return new ResponseEntity<>(new MessageResponse("Error: Phone has not valid"),HttpStatus.NO_CONTENT);
        }

        Account createAccount = new Account(request.getUsername(), request.getEmail(),
                encoder.encode(request.getPassword()),"+"+(request.getPhone().trim()), request.getFirstName(), request.getLastName(), request.getStatus());

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

        RegisterByPhoneResponse res = new RegisterByPhoneResponse();
        res.setPhone(createAccount.getPhone());
        res.setPassword(request.getPassword());
        res.setEmail(createAccount.getEmail());

        return new ResponseEntity<>(res, HttpStatus.CREATED);
    }

    @PutMapping("/changePassword-using-mail")
    public ResponseEntity<?> changePasswordUsingEmail(@RequestBody ChangePasswordByEmail req){
        if(untils.validateEmail(req.getEmail(), req.getTokenChangePass())){
            Account account = accountService.findByEmail(req.getEmail());
            account.setPassword(encoder.encode(req.getNewPassword()));
            accRepo.save(account);
            return new ResponseEntity<>(new MessageResponse("Your password has been changed"), HttpStatus.OK);
        }
        return new ResponseEntity<>(new MessageResponse("Your email is not valid"), HttpStatus.BAD_REQUEST);
    }

    @PutMapping("/changePassword-using-phone")
    public ResponseEntity<?> changePasswordUsingPhone(@RequestBody ChangePasswordByPhone req){
        OtpValidationRequest request = new OtpValidationRequest("+84"+req.getPhoneNumber(), req.getOtpChangePass());
        if(otpService.validateOtp(request)){
            Account account = accountService.findByPhone(req.getPhoneNumber());
            account.setPassword(encoder.encode(req.getNewPassword()));
            accRepo.save(account);
            return new ResponseEntity<>(new MessageResponse("Your password has been changed"), HttpStatus.OK);
        }
        return new ResponseEntity<>(new MessageResponse("Your email is not valid"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/verifyEmailChangePass")
    public RedirectView getEmailChangePassVerification(@RequestParam String email) throws MessagingException {
        String jwt = untils.generateTokenToSignup(email);
        mailService.SendMail(email,jwt);
        return new RedirectView(portChangePass + "?email="+email+"&token="+jwt+"");
    }

    @PostMapping("/validate-otp-change-pass")
    public RedirectView validateOtpChangePass(@RequestBody OtpValidationRequest otpValidationRequest) {
        String tmpPhone = "+84" + otpValidationRequest.getOtpNumber();
        OtpValidationRequest req = new OtpValidationRequest(tmpPhone,otpValidationRequest.getOtpNumber());
        if(otpService.validateOtp(req)){
            return new RedirectView(portChangePass + "?phone="+req.getPhoneNumber()+"&otp="+otpValidationRequest.getOtpNumber()+"");
        }
        return new RedirectView("");
    }


}
