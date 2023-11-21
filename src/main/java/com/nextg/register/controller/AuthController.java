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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.util.*;
import java.util.stream.Collectors;

import javax.mail.MessagingException;
@CrossOrigin(origins = "*", maxAge = 3600)
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
            return ResponseEntity.ok(
                    new UserInfoResponse(
                            accDetails.getId(), accDetails.getUsername(),
                            accDetails.getEmail(), accDetails.getPhone()
                            , roles, jwt,refreshToken.getToken(), accDetails.getImageUrl()
                    ));
        }
        return new ResponseEntity<>(new ErrorCode("801"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUserUsingEmail(@RequestBody RegisterRequest request){
        String tokenSigunp = request.getTokenSignup();
        if((!untils.validateEmail(request.getEmail(), tokenSigunp)) && (untils.validateJwtToken(tokenSigunp))){
            return new ResponseEntity<>(new ErrorCode("803"),HttpStatus.NO_CONTENT);
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

        return new ResponseEntity<>(res, HttpStatus.CREATED);
    }

    @PostMapping("/verifyEmail")
    public ResponseEntity<?> getEmailVerification(@RequestBody EmailVerifyRequest request) throws MessagingException {
        if(accRepo.existsByEmail(request.getEmail())){
            return new ResponseEntity<>(new MessageResponse("Your email has been registered"),HttpStatus.BAD_REQUEST);
        }

        String jwt = untils.generateTokenToSignup(request.getEmail());
        mailService.SendMail(request.getEmail(), jwt);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @GetMapping("/verifySuccess")
    public ResponseEntity<?> verifySuccess(@RequestBody VerifyEmailRequest req){
        if((untils.validateEmail(req.getEmail(), req.getToken())) && (!accRepo.existsByEmail(req.getEmail()))){
            VerifyResponse res = new VerifyResponse(req.getEmail(), req.getToken());
            return new ResponseEntity<>(res,HttpStatus.OK);
        }
        return new ResponseEntity<>(new ErrorCode("804"),HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/send-otp")
    public ResponseEntity<?> sendOtp(@RequestBody OtpRequest otpRequest) {
        if(accRepo.existsByPhone(otpRequest.getPhoneNumber())){
            return new ResponseEntity<>( new ErrorCode("805"), HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(otpService.sendSMS(otpRequest), HttpStatus.OK);

    }

    @PostMapping("/validate-otp")
    public ResponseEntity<?> validateOtpRegister(@RequestBody OtpValidationRequest request) {
        if(otpService.validateOtp(request)){
            ValidateSuccessOtpResponse res = new ValidateSuccessOtpResponse();
            res.setPhoneNumber(request.getPhoneNumber());
            String jwt = untils.generateTokenFromPhone(request.getPhoneNumber());
            res.setToken(jwt);
            return new ResponseEntity<>(res,HttpStatus.OK);
        }
        return new ResponseEntity<>(new ErrorCode("806"),HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/send-otp-login")
    public ResponseEntity<?> sendOtpLogin(@RequestBody OtpRequest otpRequest) {
        return new ResponseEntity<>(otpService.sendSMS(otpRequest), HttpStatus.OK);
    }

    @PostMapping("/loginByPhone")
    public ResponseEntity<?> loginByPhone(@RequestBody OtpValidationRequest request){

//        String tmpPhone = "+84"+request.getPhoneNumber();
//        System.out.println("Phone number " + tmpPhone+ " pasword: " + request.getOtpNumber());
//        OtpValidationRequest req = new OtpValidationRequest(tmpPhone,request.getOtpNumber());
        Account acc = new Account();
        try{
            acc = accountService.findByEmail(request.getPhoneNumber());
        }catch (RuntimeException e){
            return new ResponseEntity<>(new ErrorCode("823"), HttpStatus.BAD_REQUEST);
        }
        if((accountService.checkStatusAccount(acc.getStatus())) && (accRepo.existsByPhone(request.getPhoneNumber()))){
            if(otpService.validateOtp(request)){
                String jwt = untils.generateTokenFromPhone(request.getPhoneNumber());
                List<String> strRole= new ArrayList<String>();
                RefreshToken refreshToken = refreshService.createRefreshToken(acc.getId());
                strRole.add("ROLE_USER");
                return ResponseEntity.ok(
                        new UserInfoResponse(
                                acc.getId(), acc.getUsername(),
                                acc.getEmail(), acc.getPhone()
                                ,strRole, jwt,refreshToken.getToken(),acc.getImageUrl()
                        ));
            }
            return new ResponseEntity<>(new ErrorCode("806"), HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(new ErrorCode("801"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/registerByPhone")
    public ResponseEntity<?> registerUserUsingPhone(@RequestBody RegisterByPhoneRequest request){
//        OtpValidationRequest req = new OtpValidationRequest();
//        req.setPhoneNumber("+84" + request.getPhone());
//        req.setOtpNumber(req.getOtpNumber());
        if(untils.validatePhone(request.getPhone(), request.getToken())){
            return new ResponseEntity<>(new ErrorCode("805"),HttpStatus.NO_CONTENT);
        }

        Account createAccount = new Account(request.getUsername(), request.getEmail(),
                encoder.encode(request.getPassword()),"+84"+(request.getPhone().trim()), request.getFirstName(), request.getLastName(), request.getStatus());

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

        return new ResponseEntity<>(res, HttpStatus.CREATED);
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
            return new ResponseEntity<>(res, HttpStatus.OK);
        }
        return new ResponseEntity<>(new ErrorCode("802"), HttpStatus.BAD_REQUEST);
    }

    @PutMapping("/changePassword-using-phone")
    public ResponseEntity<?> changePasswordUsingPhone(@RequestBody ChangePasswordByPhone req){
        String tmpPhone = "+84"+req.getPhoneNumber();
        if(untils.validatePhone(tmpPhone, req.getTokenChangePass())){
            Account account = accountService.findByPhone(tmpPhone);
            account.setPassword(encoder.encode(req.getNewPassword()));
            accRepo.save(account);
            ChangePassByPhoneResponse res = new ChangePassByPhoneResponse();
            res.setEmail(account.getEmail());
            res.setNewPass(req.getNewPassword());
            return new ResponseEntity<>(res, HttpStatus.OK);
        }
        return new ResponseEntity<>(new ErrorCode("802"), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/verifyEmailChangePass")
    public ResponseEntity<?> getEmailChangePassVerification(@RequestBody EmailVerifyRequest request) {
    	String jwt = null;
        try {
        	jwt = untils.generateTokenToSignup(request.getEmail());
			mailService.SendMailChangePass(request.getEmail(), jwt);
		} catch (MessagingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        VerifyResponse res = new VerifyResponse(request.getEmail(), jwt);
        return new ResponseEntity<>(res,HttpStatus.OK);
    }

    @PostMapping("/validate-otp-change-pass")
    public ResponseEntity<?> validateOtp(@RequestBody OtpValidationRequest otpValidationRequest) {
        if(otpService.validateOtp(otpValidationRequest)){
            String jwt = untils.generateTokenFromPhone(otpValidationRequest.getPhoneNumber());
            ValidateSuccessOtpChangePassResponse res = new ValidateSuccessOtpChangePassResponse();
            res.setPhoneNumber(otpValidationRequest.getPhoneNumber());
            res.setToken(jwt);
            return new ResponseEntity<>(res,HttpStatus.OK);
        }
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

                        return ResponseEntity.ok(new RefreshTokenResponse(token, requestRefreshToken));
                    }
                    String token = untils.generateTokenFromEmail(acc.getEmail());
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
        return ResponseEntity.ok(new MessageResponse("Log out successful!"));
    }

    @PostMapping("/emailVerify")
    public ResponseEntity<?> getEmailVerify(@RequestBody EmailVerifyRequest request, @RequestHeader("Authorization")String token) throws MessagingException {
        if(accRepo.existsByEmail(request.getEmail())){
            return new ResponseEntity<>(new ErrorCode("804"),HttpStatus.BAD_REQUEST);
        }
        String oldPhone="";
        if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            String tmpToken = token.substring(7, token.length());
            oldPhone = untils.getPhoneFromJwtToken(tmpToken);
        }

        String jwt = untils.generateTokenToSignup(request.getEmail());
        mailService.SendMailVerifyed(request.getEmail(), jwt,oldPhone);
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
                return new ResponseEntity<>(HttpStatus.OK);
            }
        return new ResponseEntity<>(new ErrorCode("805"),HttpStatus.BAD_REQUEST);
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
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(new ErrorCode("806"),HttpStatus.BAD_REQUEST);
    }
}
