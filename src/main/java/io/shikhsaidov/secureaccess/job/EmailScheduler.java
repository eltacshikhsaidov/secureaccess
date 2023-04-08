package io.shikhsaidov.secureaccess.job;

import io.shikhsaidov.secureaccess.entity.EmailInfo;
import io.shikhsaidov.secureaccess.enums.EmailStatus;
import io.shikhsaidov.secureaccess.repository.EmailInfoRepository;
import io.shikhsaidov.secureaccess.service.EmailService;
import io.shikhsaidov.secureaccess.util.LogDetail;
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
    private final LogDetail logDetail;

    @Scheduled(cron = "0 */2 * ? * *")
    @Transactional
    public void retryEmailSending() {
        log.info(
                "requestPath: '{}', serverIp: '{}', [retryEmailSending] schedule function started",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
        List<EmailInfo> emailInfoList = emailInfoRepository.getEmailInfoByStatus(EmailStatus.RETRY);

        String functionMessage = emailInfoList.size() == 0
                ? "There is not any failed email"
                : (emailInfoList.size() == 1 ?
                "email" :
                "emails")
                + " will be retried to send to users";
        log.info(
                "requestPath: '{}', serverIp: '{}', [retryEmailSending] " +
                        "fetching failed emails response : {}",
                logDetail.getRequestPath(),
                logDetail.getIp(),
                functionMessage
        );

        if (emailInfoList.size() == 0) {
            log.info(
                    "requestPath: '{}', serverIp: '{}', [retryEmailSending] schedule function ended",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return;
        }

        emailInfoList.forEach(
                emailInfo -> {

                    try {

                        log.info(
                                "requestPath: '{}', serverIp: '{}', " +
                                        "[retryEmailSending] schedule function response: {}",
                                logDetail.getRequestPath(),
                                logDetail.getIp(),
                                emailInfo.emailTo
                        );
                        emailService.sendEmail(emailInfo);

                        emailInfo.setStatus(EmailStatus.SENT);
                        emailInfo.setRetriedAt(LocalDateTime.now());
                        emailInfo.setRetryCount(emailInfo.getRetryCount() + 1);

                    } catch (Exception e) {
                        log.warn(
                                "requestPath: '{}', serverIp: '{}', " +
                                        "[retryEmailSending] schedule function response: {}, " +
                                        "exception message: {}",
                                logDetail.getRequestPath(),
                                logDetail.getIp(),
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

        log.info(
                "requestPath: '{}', serverIp: '{}', [retryEmailSending] schedule function ended",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
    }
}
