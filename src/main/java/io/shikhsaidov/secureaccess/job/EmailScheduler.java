package io.shikhsaidov.secureaccess.job;

import lombok.extern.log4j.Log4j2;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Log4j2
@Component
@EnableAsync
public class EmailScheduler {

    @Scheduled(cron = "0 */2 * ? * *")
    public void retryConfirmationEmailSending() {
        log.info("Retrying to send confirmation emails which is not sent");


        log.info("retryConfirmationEmailSending ended");
    }
}
