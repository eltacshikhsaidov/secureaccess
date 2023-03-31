package io.shikhsaidov.secureaccess.service.impl;

import io.shikhsaidov.secureaccess.entity.EmailInfo;
import io.shikhsaidov.secureaccess.service.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Log4j2
@Service
@RequiredArgsConstructor
@PropertySource("classpath:email.properties")
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    @Value("${sender}")
    public String sender;

    @Async
    @Override
    public void sendEmail(EmailInfo emailInfo) {
        try {

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper messageHelper = new MimeMessageHelper(message, "UTF-8");
            messageHelper.setText(new String(emailInfo.content), true);
            messageHelper.setTo(emailInfo.emailTo);
            messageHelper.setFrom(sender);
            messageHelper.setSubject(emailInfo.subject);

            mailSender.send(message);
        } catch (MessagingException e) {
            log.warn("Failed to send email, exception message: {}", e.getMessage());
        }
    }
}
