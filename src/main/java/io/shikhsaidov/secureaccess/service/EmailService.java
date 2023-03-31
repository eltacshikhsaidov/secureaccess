package io.shikhsaidov.secureaccess.service;


import io.shikhsaidov.secureaccess.entity.EmailInfo;

public interface EmailService {
    void sendEmail(EmailInfo emailInfo);
}
