package com.nextg.register.jwt;

import com.auth0.jwt.JWTVerifier;
import com.nextg.register.service.AccountDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtils {
    private static final Logger log = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${secret}")
    private String SECRET;

    @Value("${jwtExpirationMs}")
    private long jwtDurationMs;

    public String generateJwtTokenForLogin(AccountDetailsImpl userDetails){
        return generateTokenFromEmail(userDetails.getEmail());
    }
    public String generateTokenFromEmail(String email){
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtDurationMs))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }
    public String getEmailFromJwtToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key()).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    private Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET));
    }

    public boolean validateJwtToken(String token){
        try{
            Jwts.parserBuilder().setSigningKey(key()).build().parse(token);
            return true;
        }catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    public boolean validateEmail(String email , String token){
         String temEmail = getEmailFromJwtToken(token);
         if(temEmail.equals(email)){
             return true;
         }
         return false;
    }

    public String generateTokenToSignup(String email){
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + 86400000))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateTokenFromPhoneNumber(String phone){
        return Jwts.builder()
                .setSubject(phone)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtDurationMs))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String getPhoneFromJwtToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key()).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    public String generateJwtTokenForLoginWithPhone(AccountDetailsImpl userDetails){
        return generateTokenFromEmail(userDetails.getPhone());
    }


    public boolean validatePhone(String phone , String token){
        String temEmail = getEmailFromJwtToken(token);
        if(temEmail.equals(phone)){
            return true;
        }
        return false;
    }

    public String generateTokenToSignupByPhone(String phone){
        return Jwts.builder()
                .setSubject(phone)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + 86400000))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

}
