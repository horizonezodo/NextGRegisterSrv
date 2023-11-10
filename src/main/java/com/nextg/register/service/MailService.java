package com.nextg.register.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

@Service
public class MailService {

    @Value("${spring.mail.username}")
    private String to;

    @Value("${app.client.url}")
    private String portUrl;

    @Value("${server.url}")
    private String backendUrl;

    @Autowired
    private JavaMailSender mailSender;

    public void SendMail(String mail,String token) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();

        message.setFrom(to);
        message.setRecipients(MimeMessage.RecipientType.TO, mail);
        message.setSubject("Verification Email");
        String htmlContent = readHtmlEmailTemplate();
        htmlContent = htmlContent.replace("{{var_href}}", portUrl+"register?email="+mail + "&token="+token);
        message.setContent(htmlContent,"text/html; charset=utf-8");
        mailSender.send(message);
    }

    // Hàm để đọc nội dung từ tệp HTML
    public String readHtmlEmailTemplate() {
        try {
            ClassPathResource resource = new ClassPathResource("email-template.html");
            byte[] fileData = FileCopyUtils.copyToByteArray(resource.getInputStream());
            return new String(fileData, StandardCharsets.UTF_8);
        } catch (IOException e) {
            e.printStackTrace();
            // Handle the exception appropriately
            return null;
        }
    }

    public void SendMailChangePass(String mail,String token) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();

        message.setFrom(to);
        message.setRecipients(MimeMessage.RecipientType.TO, mail);
        message.setSubject("Verification Email");
        String htmlContent = readHtmlEmailTemplate();
        htmlContent = htmlContent.replace("{{var_href}}", portUrl+"resetPassword?email="+mail + "&token="+token);
        message.setContent(htmlContent,"text/html; charset=utf-8");
        mailSender.send(message);
    }

    public void SendMailVerifyed(String mail,String token,String phone) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();

        message.setFrom(to);
        message.setRecipients(MimeMessage.RecipientType.TO, mail);
        message.setSubject("Verification Email");
        String htmlContent = readHtmlEmailTemplate();
        htmlContent = htmlContent.replace("{{var_href}}", backendUrl+"auth/verifiedSuccess?email="+mail + "&token="+token + "&phone="+phone);
        message.setContent(htmlContent,"text/html; charset=utf-8");
        mailSender.send(message);
    }

}
