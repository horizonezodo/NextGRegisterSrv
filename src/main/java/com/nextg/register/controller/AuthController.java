package com.nextg.register.controller;

import com.nextg.register.entity.Account;
import com.nextg.register.exception.AccountException;
import com.nextg.register.jwt.JwtUtils;
import com.nextg.register.payload.request.LoginRequest;
import com.nextg.register.payload.response.AuthResponse;
import com.nextg.register.repository.AccountRepository;
import com.nextg.register.service.Impl.AccountDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin("*")
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AccountRepository accRepo;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private AccountDetailsServiceImpl accountService;

    private Authentication authenticate(String email,String password){
        UserDetails userDetails =accountService.loadUserByUsername(email);
        if(userDetails==null){
            throw new BadCredentialsException("Invalid Username");
        }
        if(encoder.matches(password,userDetails.getPassword())){
            throw new BadCredentialsException("Invalid Password");
        }
        return new UsernamePasswordAuthenticationToken(userDetails,null, userDetails.getAuthorities());
    }


    @PostMapping("/signupEmail")
    public ResponseEntity<AuthResponse>createAccountByEmailHandler(@RequestBody Account acc) throws AccountException{
        String email = acc.getEmail();
        String password = acc.getPassword();
        String username = acc.getUsername();

        Account isEmailExists = accRepo.findByEmail(email);
        if(isEmailExists != null){
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        Account createAccount = new Account();
        createAccount.setEmail(email);
        createAccount.setPassword(encoder.encode(password));
        createAccount.setUsername(username);

        Account saveAccount = accRepo.save(createAccount);

        Authentication authentication = new UsernamePasswordAuthenticationToken(saveAccount.getEmail(),saveAccount.getPassword());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = jwtUtils.generateToken(authentication);
        AuthResponse response = new AuthResponse(token, "Signup Success");
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @PostMapping("/signinEmail")
    public ResponseEntity<AuthResponse> loginAccountByEmailHandler(@RequestBody LoginRequest request){
        String email = request.getEmail();
        String password = request.getPassword();

        Authentication authentication=authenticate(email,encoder.encode(password));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtUtils.generateToken(authentication);
        AuthResponse response = new AuthResponse(token,"Signin Success");
        return new ResponseEntity<AuthResponse>(response, HttpStatus.CREATED);

    }

    @PostMapping("/changePassword")
    public ResponseEntity<?> changePassword(String jwt, @RequestParam("newPass") String newPass){
        String email = jwtUtils.getEmailFromToken(jwt);
        Account acc = accRepo.findByEmail(email);
        if(acc == null){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }else{
            acc.setPassword(encoder.encode(newPass));
        }
        return new ResponseEntity<>(accRepo.save(acc), HttpStatus.OK);

    }
}
