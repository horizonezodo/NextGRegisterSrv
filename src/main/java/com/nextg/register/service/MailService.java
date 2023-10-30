package com.nextg.register.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailService {

    @Value("${spring.mail.username}")
    private String to;

    @Autowired
    private JavaMailSender mailSender;

    public void SendMail(String mail,String token) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();

        message.setFrom(to);
        message.setRecipients(MimeMessage.RecipientType.TO, mail);
        message.setSubject("Thank you for validate your email");

        String htmlContent = "<h1>Account Authentication</h1>"+
                "<button><a href='http://localhost:8989/auth/verifySuccess?email="+mail + "&token="+token+"'>Verify</button>";
        message.setContent(htmlContent,"text/html; charset=utf-8");
        mailSender.send(message);
    }
//    public final JavaMailSender mailSender;
//
//    public MailService(JavaMailSender mailSender){
//        this.mailSender = mailSender;
//    }
//
//
//    public void sendMail(String to, String subject, String text) {
//        SimpleMailMessage message = new SimpleMailMessage();
//        message.setFrom("thiensutoiloi3@gmail.com");
//        message.setTo(to);
//        message.setSubject(subject);
//        message.setText(text);
//        mailSender.send(message);
//    }
}
