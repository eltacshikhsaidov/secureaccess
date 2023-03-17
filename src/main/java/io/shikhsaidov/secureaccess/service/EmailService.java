package io.shikhsaidov.secureaccess.service;


public interface EmailService {
    void sendEmail(String to, String subject, String content);
}
