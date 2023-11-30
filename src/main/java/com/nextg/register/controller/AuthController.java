package com.nextg.register.controller;

import com.nextg.register.exception.TokenRefreshException;
import com.nextg.register.jwt.JwtUtils;
import com.nextg.register.model.Account;
import com.nextg.register.model.ERole;
import com.nextg.register.model.RefreshToken;
import com.nextg.register.model.Role;
import com.nextg.register.repo.AccountRepository;
import com.nextg.register.repo.RoleRepository;
import com.nextg.register.request.*;
import com.nextg.register.response.*;
import com.nextg.register.service.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import javax.mail.MessagingException;
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/auth")
@Slf4j
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

    @Autowired
    private RefreshTokenServiceImpl refreshService;

    @PostMapping("/login")
    public ResponseEntity<?> authenticationUserUsingEmail(@RequestBody LoginRequest request){
        Account tmpAccount = new Account();
        try{
            tmpAccount = accountService.findByEmail(request.getEmail());
        }catch (RuntimeException e){
            return new ResponseEntity<>(new ErrorCode("822"), HttpStatus.BAD_REQUEST);
        }
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

            RefreshToken refreshToken = refreshService.createRefreshToken(accDetails.getId());
            log.info("Login Success : " + accDetails.getFirstName());
//            return ResponseEntity.ok(
//                    new UserInfoResponse(
//                            accDetails.getId(), accDetails.getFirstName(),
//                            accDetails.getEmail(), accDetails.getPhone()
//                            , roles, jwt,refreshToken.getToken(), accDetails.getImageUrl()
//                    ));
            return ResponseEntity.ok(
                    new UserInfoResponse(
                             jwt,refreshToken.getToken()
                    ));
        }
        log.error("Account has been locked : " + request.getEmail());
        return new ResponseEntity<>(new ErrorCode("801"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUserUsingEmail(@RequestBody RegisterRequest request){

        String tokenSigunp = request.getTokenSignup();
        if((!untils.validateEmail(request.getEmail(), tokenSigunp)) && (untils.validateJwtToken(tokenSigunp))){
            log.error("Email has been registered : " + request.getEmail());
            return new ResponseEntity<>(new ErrorCode("803"),HttpStatus.BAD_REQUEST);
        }

        Account createAccount = new Account(request.getUsername(), request.getEmail(),
                encoder.encode(request.getPassword()), request.getPhone(), request.getFirstName(), request.getLastName(), request.getStatus());

        Set<String> strRole = request.getRoles();
        Set<Role> roles = new HashSet<>();

        if(strRole == null){
            Role userRole = roleRepo.findByName(ERole.ROLE_USER)
                    .orElseThrow(()-> new RuntimeException("811"));
            roles.add(userRole);
        }else{
            strRole.forEach(role ->{
                switch (role){
                    case "admin":
                        Role admin = roleRepo.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(()-> new RuntimeException("811"));
                        roles.add(admin);
                        break;
                    case "manager":
                        Role manager = roleRepo.findByName(ERole.ROLE_MANAGER)
                                .orElseThrow(()-> new RuntimeException("811"));
                        roles.add(manager);
                        break;
                    case "mod":
                        Role mod = roleRepo.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(()-> new RuntimeException("811"));
                        roles.add(mod);
                        break;
                    default:
                        Role userRole = roleRepo.findByName(ERole.ROLE_USER)
                                .orElseThrow(()-> new RuntimeException("811"));
                        roles.add(userRole);
                        break;
                }
            });
        }
        createAccount.setRoles(roles);
        createAccount.setPhoneVerifired(false);
        createAccount.setEmailVerifired(true);
        createAccount.setRank_account(1);
        accRepo.save(createAccount);

        RegisterReponse res = new RegisterReponse();
        res.setEmail(createAccount.getEmail());
        res.setPassword(request.getPassword());

        log.info("Register Success : " + createAccount.getFirstName());

        return new ResponseEntity<>(res, HttpStatus.CREATED);
    }

    @PostMapping("/verifyEmail")
    public ResponseEntity<?> getEmailVerification(@RequestBody EmailVerifyRequest request) throws MessagingException {
        if(accRepo.existsByEmail(request.getEmail())){
            log.error("Email has been registered : " + request.getEmail());
            return new ResponseEntity<>(new ErrorCode("803"),HttpStatus.BAD_REQUEST);
        }

        String jwt = untils.generateTokenToSignup(request.getEmail());
        mailService.SendMail(request.getEmail(), jwt);

        log.info("Send email verify Success : " + request.getEmail());
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping("/send-otp")
    public ResponseEntity<?> sendOtp(@RequestBody OtpRequest otpRequest) {
        if(accRepo.existsByPhone(otpRequest.getPhoneNumber())){
            log.error("Phone has been registered : " + otpRequest.getPhoneNumber());
            return new ResponseEntity<>( new ErrorCode("805"), HttpStatus.BAD_REQUEST);
        }
        log.info("Sent otp Success : " + otpRequest.getPhoneNumber());
        return new ResponseEntity<>(otpService.sendSMS(otpRequest), HttpStatus.OK);

    }

    @PostMapping("/validate-otp")
    public ResponseEntity<?> validateOtpRegister(@RequestBody OtpValidationRequest request) {
        if(otpService.validateOtp(request)){
            ValidateSuccessOtpResponse res = new ValidateSuccessOtpResponse();
            res.setPhoneNumber(request.getPhoneNumber());
            String jwt = untils.generateTokenFromPhone(request.getPhoneNumber());
            res.setToken(jwt);
            log.info("Validate otp Success : " + request.getPhoneNumber());
            return new ResponseEntity<>(res,HttpStatus.OK);
        }
        log.error("Otp is not valid : " + request.getOtpNumber());
        return new ResponseEntity<>(new ErrorCode("806"),HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/send-otp-login")
    public ResponseEntity<?> sendOtpLogin(@RequestBody OtpRequest otpRequest) {
        if(accRepo.existsByPhone(otpRequest.getPhoneNumber())){
            log.info("Send Otp Login Success : " + otpRequest.getPhoneNumber());
            return new ResponseEntity<>(otpService.sendSMS(otpRequest), HttpStatus.OK);
        }
        log.error("Phone is exists : " + otpRequest.getPhoneNumber());
        return new ResponseEntity<>( new ErrorCode("823"), HttpStatus.BAD_REQUEST);

    }

    @PostMapping("/loginByPhone")
    public ResponseEntity<?> loginByPhone(@RequestBody OtpValidationRequest request){

//        String tmpPhone = "+84"+request.getPhoneNumber();
//        System.out.println("Phone number " + tmpPhone+ " pasword: " + request.getOtpNumber());
//        OtpValidationRequest req = new OtpValidationRequest(tmpPhone,request.getOtpNumber());
        Account acc = new Account();
        try{
            acc = accountService.findByPhone(request.getPhoneNumber());
        }catch (RuntimeException e){
            return new ResponseEntity<>(new ErrorCode("823"), HttpStatus.BAD_REQUEST);
        }
        if((accountService.checkStatusAccount(acc.getStatus())) && (accRepo.existsByPhone(request.getPhoneNumber()))){
            if(otpService.validateOtp(request)){
                String jwt = untils.generateTokenFromPhone(request.getPhoneNumber());
                List<String> strRole= new ArrayList<String>();
                RefreshToken refreshToken = refreshService.createRefreshToken(acc.getId());
                strRole.add("ROLE_USER");
                log.info("Login with phone Success : " + request.getPhoneNumber());
//                return ResponseEntity.ok(
//                        new UserInfoResponse(
//                                acc.getId(), acc.getFirstName(),
//                                acc.getEmail(), acc.getPhone()
//                                ,strRole, jwt,refreshToken.getToken(),acc.getImageUrl()
//                        ));
                return ResponseEntity.ok(
                        new UserInfoResponse(
                                jwt,refreshToken.getToken()
                        ));
            }
            log.error("Otp is not valid : " + request.getPhoneNumber());
            return new ResponseEntity<>(new ErrorCode("806"), HttpStatus.BAD_REQUEST);
        }
        log.error("Account has been locked : " + request.getPhoneNumber());
        return new ResponseEntity<>(new ErrorCode("801"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/registerByPhone")
    public ResponseEntity<?> registerUserUsingPhone(@RequestBody RegisterByPhoneRequest request){
        if(!untils.validatePhone(request.getPhone(), request.getToken())){
            log.error("Phone is not valid : " + request.getPhone());
            return new ResponseEntity<>(new ErrorCode("807"),HttpStatus.BAD_REQUEST);
        }

        Account createAccount = new Account(request.getUsername(), request.getEmail(),
                encoder.encode(request.getPassword()),request.getPhone(), request.getFirstName(), request.getLastName(), request.getStatus());

        Set<String> strRole = request.getRoles();
        Set<Role> roles = new HashSet<>();

        if(strRole == null){
            Role userRole = roleRepo.findByName(ERole.ROLE_USER)
                    .orElseThrow(()-> new RuntimeException("811"));
            roles.add(userRole);
        }else{
            strRole.forEach(role ->{
                switch (role){
                    case "admin":
                        Role admin = roleRepo.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(()-> new RuntimeException("811"));
                        roles.add(admin);
                        break;
                    case "manager":
                        Role manager = roleRepo.findByName(ERole.ROLE_MANAGER)
                                .orElseThrow(()-> new RuntimeException("811"));
                        roles.add(manager);
                        break;
                    case "mod":
                        Role mod = roleRepo.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(()-> new RuntimeException("811"));
                        roles.add(mod);
                        break;
                    default:
                        Role userRole = roleRepo.findByName(ERole.ROLE_USER)
                                .orElseThrow(()-> new RuntimeException("811"));
                        roles.add(userRole);
                        break;
                }
            });
        }
        createAccount.setRoles(roles);
        createAccount.setPhoneVerifired(true);
        createAccount.setEmailVerifired(false);
        createAccount.setRank_account(1);
        accRepo.save(createAccount);

        RegisterByPhoneResponse res = new RegisterByPhoneResponse();
        res.setPhone(createAccount.getPhone());
        res.setPassword(request.getPassword());
        res.setEmail(createAccount.getEmail());
        log.info("Register with phone Success : " + request.getPhone());
        return new ResponseEntity<>(res, HttpStatus.OK);
    }

    @PutMapping("/changePassword-using-mail")
    public ResponseEntity<?> changePasswordUsingEmail(@RequestBody ChangePasswordByEmail req){
        if(untils.validateEmail(req.getEmail(), req.getTokenChangePass())){
            Account account = new Account();
            try{
                account=accountService.findByEmail(req.getEmail());
            }catch (RuntimeException e){
                return new ResponseEntity<>(new ErrorCode("822"), HttpStatus.BAD_REQUEST);
            }
            account.setPassword(encoder.encode(req.getNewPassword()));
            accRepo.save(account);
            ChangePasswordByEmailResponse res = new ChangePasswordByEmailResponse();
            res.setEmail(account.getEmail());
            res.setNewPass(req.getNewPassword());
            log.info("Change password with email Success : " + req.getEmail());
            return new ResponseEntity<>(res, HttpStatus.OK);
        }
        log.error("Email is not valid : " + req.getEmail());
        return new ResponseEntity<>(new ErrorCode("802"), HttpStatus.BAD_REQUEST);
    }

    @PutMapping("/changePassword-using-phone")
    public ResponseEntity<?> changePasswordUsingPhone(@RequestBody ChangePasswordByPhone req){
        if(untils.validatePhone(req.getPhoneNumber(), req.getTokenChangePass())){
            Account account = accountService.findByPhone(req.getPhoneNumber());
            account.setPassword(encoder.encode(req.getNewPassword()));
            accRepo.save(account);
            ChangePassByPhoneResponse res = new ChangePassByPhoneResponse();
            res.setEmail(account.getEmail());
            res.setNewPass(req.getNewPassword());
            log.info("Change password with phone Success : " + req.getPhoneNumber());
            return new ResponseEntity<>(res, HttpStatus.OK);
        }
        log.error("Phone is not valid : " + req.getPhoneNumber());
        return new ResponseEntity<>(new ErrorCode("807"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/verifyEmailChangePass")
    public ResponseEntity<?> getEmailChangePassVerification(@RequestBody EmailVerifyRequest request) {
        if(!accRepo.existsByEmail(request.getEmail())){
            log.error("Email not found : " + request.getEmail());
            return new ResponseEntity<>(new ErrorCode("822"),HttpStatus.BAD_REQUEST);
        }

    	String jwt = null;
        try {
        	jwt = untils.generateTokenToSignup(request.getEmail());
			mailService.SendMailChangePass(request.getEmail(), jwt);
		} catch (MessagingException e) {
            log.error("Verify Email Change Pass failure : " + request.getEmail());
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        VerifyResponse res = new VerifyResponse(request.getEmail(), jwt);
        log.info("Verify Email Change Pass Success : " + request.getEmail());
        return new ResponseEntity<>(res,HttpStatus.OK);
    }

    @PostMapping("/validate-otp-change-pass")
    public ResponseEntity<?> validateOtp(@RequestBody OtpValidationRequest otpValidationRequest) {
        if(otpService.validateOtp(otpValidationRequest)){
            String jwt = untils.generateTokenFromPhone(otpValidationRequest.getPhoneNumber());
            ValidateSuccessOtpChangePassResponse res = new ValidateSuccessOtpChangePassResponse();
            res.setPhoneNumber(otpValidationRequest.getPhoneNumber());
            res.setToken(jwt);
            log.info("validate otp change pass Success : " + otpValidationRequest.getPhoneNumber());
            return new ResponseEntity<>(res,HttpStatus.OK);
        }
        log.error("Otp is not valid : " + otpValidationRequest.getPhoneNumber());
        return new ResponseEntity<>(new ErrorCode("806"),HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken( @RequestBody RefreshTokenRequest  request) {
        String requestRefreshToken = request.getRefreshToken();
        return refreshService.findByToken(requestRefreshToken)
                .map(refreshService::verifyExpiration)
                .map(RefreshToken::getAccount)
                .map(acc -> {
                    if(acc.getEmail() ==null){
                        String token = untils.generateTokenFromPhone(acc.getPhone());
                        log.info("refresh token Success : " + token);
                        return ResponseEntity.ok(new RefreshTokenResponse(token, requestRefreshToken));
                    }
                    String token = untils.generateTokenFromEmail(acc.getEmail());
                    log.info("refresh token Success : " + token);
                    return ResponseEntity.ok(new RefreshTokenResponse(token, requestRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "810"));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        AccountDetailsImpl accDetails = (AccountDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        System.out.println(accDetails);
        Long userId = accDetails.getId();
        refreshService.deleteByUserId(userId);
        log.info("Logout user Success : " + accDetails.getFirstName());
        return ResponseEntity.ok(new MessageResponse("Log out successful!"));
    }

    @PostMapping("/emailVerify")
    public ResponseEntity<?> getEmailVerify(@RequestBody EmailVerifyRequest request, @RequestHeader("Authorization")String token) throws MessagingException {
        if(accRepo.existsByEmail(request.getEmail())){
            log.error("Email has been registered : " + request.getEmail());
            return new ResponseEntity<>(new ErrorCode("803"),HttpStatus.BAD_REQUEST);
        }
        String oldPhone="";
        if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            String tmpToken = token.substring(7, token.length());
            oldPhone = untils.getPhoneFromJwtToken(tmpToken);
        }

        String jwt = untils.generateTokenToSignup(request.getEmail());
        mailService.SendMailVerifyed(request.getEmail(), jwt,oldPhone);
        log.info("Email verify Success : " + request.getEmail());
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @GetMapping("/verifiedSuccess")
    public ResponseEntity<?> verifySuccessEmail(@RequestParam String email,@RequestParam String token, @RequestParam String phone){
        phone = "+"+phone.trim();
            if(untils.validateEmail(email,token)) {
                Account acc = accountService.findByPhone(phone);
                acc.setEmail(email);
                acc.setEmailVerifired(true);
                accRepo.save(acc);
                log.info("Email verify Success : " + email);
                String frontEnd = "http://localhost:4200/settings";
                java.net.URI location = ServletUriComponentsBuilder.fromUriString(frontEnd).build().toUri();
                return ResponseEntity.status(HttpStatus.FOUND).location(location).build();
            }
        log.error("Email has been registered : " + email);
        return new ResponseEntity<>(new ErrorCode("803"),HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/validate-otp-success")
    public ResponseEntity<?> validatePhoneNumber(@RequestBody OtpValidationRequest request,@RequestHeader("Authorization")String jwt) {
        if(otpService.validateOtp(request)){
            String tmpEmail="";
            if (StringUtils.hasText(jwt) && jwt.startsWith("Bearer ")) {
                String tmpToken = jwt.substring(7, jwt.length());
                tmpEmail = untils.getEmailFromJwtToken(tmpToken);
            }

            Account acc = accountService.findByEmail(tmpEmail);
            acc.setPhone(request.getPhoneNumber());
            acc.setPhoneVerifired(true);
            accRepo.save(acc);
            log.info("Otp validate Success : " + request.getPhoneNumber());
            return new ResponseEntity<>(HttpStatus.OK);
        }
        log.error("Otp is not valid : " + request.getOtpNumber());
        return new ResponseEntity<>(new ErrorCode("806"),HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/checkToken")
    public ResponseEntity<?> checkToken(@RequestBody checkTokenRequest request){
        if(untils.validateJwtToken(request.getToken())){
            log.info("Token checked : " + request.getToken());
            return new ResponseEntity<>(HttpStatus.OK);
        }
        log.error("Token has been expired date : " + request.getToken());
        return new ResponseEntity<>(new ErrorCode("829"),HttpStatus.BAD_REQUEST);
    }
}
