package io.shikhsaidov.secureaccess.job;

import io.shikhsaidov.secureaccess.entity.EmailInfo;
import io.shikhsaidov.secureaccess.enums.EmailStatus;
import io.shikhsaidov.secureaccess.repository.EmailInfoRepository;
import io.shikhsaidov.secureaccess.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

import static java.util.Objects.isNull;

@Log4j2
@Component
@EnableAsync
@RequiredArgsConstructor
public class EmailScheduler {

    private final EmailInfoRepository emailInfoRepository;
    private final EmailService emailService;

    @Scheduled(cron = "0 */2 * ? * *")
    @Transactional
    public void retryConfirmationEmailSending() {
        log.info("Retrying to send confirmation emails which is not sent");
        List<EmailInfo> emailInfoList = emailInfoRepository.getEmailInfoByStatus(EmailStatus.RETRY);
        log.info("emailInfoList: {}", emailInfoList);

        if (isNull(emailInfoList)) {
            log.info("There is not any email with retry status");
            return;
        }

        emailInfoList.forEach(
                emailInfo -> {

                    try {

                        log.info("Retrying to send confirmation email to: {}", emailInfo.emailTo);
                        emailService.sendEmail(emailInfo);

                        emailInfo.setStatus(EmailStatus.SENT);
                        emailInfo.setRetriedAt(LocalDateTime.now());
                        emailInfo.setRetryCount(emailInfo.getRetryCount() + 1);

                    } catch (Exception e) {
                        log.info("Exception occurred while sending an email: {}", e.getMessage());
                        emailInfo.setRetriedAt(LocalDateTime.now());
                        if (emailInfo.retryCount >= 3) {
                            emailInfo.setStatus(EmailStatus.FAILED);
                        } else {
                            emailInfo.setStatus(EmailStatus.RETRY);
                            emailInfo.setRetryCount(emailInfo.getRetryCount() + 1);
                        }

                    } finally {
                        emailInfoRepository.updateEmailInfoById(
                                emailInfo.id,
                                emailInfo.retriedAt,
                                emailInfo.retryCount,
                                emailInfo.status
                        );
                    }

                }
        );

        log.info("retryConfirmationEmailSending ended");
    }
}
