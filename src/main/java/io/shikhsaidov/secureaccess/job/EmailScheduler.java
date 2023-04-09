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


@Log4j2
@Component
@EnableAsync
@RequiredArgsConstructor
public class EmailScheduler {

    private final EmailInfoRepository emailInfoRepository;
    private final EmailService emailService;

    @Scheduled(cron = "0 */2 * ? * *")
    @Transactional
    public void retryEmailSending() {
        log.info("method: '[retryEmailSending]', schedule function started");
        List<EmailInfo> emailInfoList = emailInfoRepository.getEmailInfoByStatus(EmailStatus.RETRY);

        String functionMessage = emailInfoList.size() == 0
                ? "There is not any failed email"
                : (emailInfoList.size() == 1 ?
                emailInfoList.size() + "email" :
                emailInfoList.size() + "emails")
                + " will be retried to send to users";
        log.info("method: '[retryEmailSending]', fetching failed emails response : {}", functionMessage);

        if (emailInfoList.size() == 0) {
            log.info("method: '[retryEmailSending]', schedule function ended");
            return;
        }

        emailInfoList.forEach(
                emailInfo -> {

                    try {

                        log.info("method: '[retryEmailSending]', schedule function response: {}",
                                "Sending email to " + emailInfo.emailTo
                        );
                        emailService.sendEmail(emailInfo);

                        emailInfo.setStatus(EmailStatus.SENT);
                        emailInfo.setRetriedAt(LocalDateTime.now());
                        emailInfo.setRetryCount(emailInfo.getRetryCount() + 1);

                    } catch (Exception e) {
                        log.warn(
                                "method: '[retryEmailSending]', schedule function response: {}, " +
                                        "exception message: {}",
                                "Exception occurred while sending email to: " + emailInfo.emailTo,
                                e.getMessage()
                        );
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

        log.info("method: '[retryEmailSending]' schedule function ended");
    }
}
