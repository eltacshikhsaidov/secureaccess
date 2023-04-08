package io.shikhsaidov.secureaccess.service.impl;

import io.shikhsaidov.secureaccess.dto.*;
import io.shikhsaidov.secureaccess.entity.*;
import io.shikhsaidov.secureaccess.enums.*;
import io.shikhsaidov.secureaccess.exception.TokenNotFound;
import io.shikhsaidov.secureaccess.holder.HeaderHolder;
import io.shikhsaidov.secureaccess.repository.*;
import io.shikhsaidov.secureaccess.response.model.*;
import io.shikhsaidov.secureaccess.response.Response;
import io.shikhsaidov.secureaccess.service.*;
import io.shikhsaidov.secureaccess.util.*;
import io.shikhsaidov.secureaccess.util.validator.EmailValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static io.shikhsaidov.secureaccess.response.Response.*;
import static io.shikhsaidov.secureaccess.response.ResponseCodes.*;
import static io.shikhsaidov.secureaccess.util.Utility.isNull;
import static io.shikhsaidov.secureaccess.util.Utility.randomBetween;
import static java.util.Objects.nonNull;

@Log4j2
@Service
@RequiredArgsConstructor
@PropertySource("classpath:config-${application.environment}.properties")
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final LogDetail logDetail;
    private final AuthenticationManager authenticationManager;
    private final EmailValidator emailValidator;
    private final EmailUtil emailUtil;
    private final EmailService emailService;
    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final EmailInfoRepository emailInfoRepository;
    private final ResetPasswordTokenRepository resetPasswordTokenRepository;
    private final LoginHistoryRepository loginHistoryRepository;
    private final IpDataUtil ipDataUtil;
    private final LoginLocationRepository loginLocationRepository;
    private final HeaderHolder headerHolder;
    private final UserRecognizedDevicesRepository userRecognizedDevicesRepository;
    private final UserBlockedDeviceRepository userBlockedDeviceRepository;

    @Value("${url}")
    public String url;

    @Value("${reset.password.token.regex.regexp}")
    public String RESET_PASSWORD_TOKEN_REGEX;

    @Override
    public Response<?> register(RegisterDTO request) {


        log.info(
                "requestPath: '{}', clientIp: '{}', function calling with request",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
        String email = request.email();
        String password = request.password();
        String firstName = request.firstName();
        String lastName = request.lastName();

        if (isNull(email, password, firstName, lastName)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: invalid request data",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(INVALID_REQUEST_DATA);
        }

        if (emailValidator.validate(email)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email format is incorrect",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(EMAIL_FORMAT_IS_INCORRECT);
        }

        // check if user is exists
        var checkUserInDB = userRepository.findByEmail(request.email());

        if (checkUserInDB.isPresent()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email is taken",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(EMAIL_IS_TAKEN);
        }

        var user = new User(
                request.firstName(),
                request.lastName(),
                request.email(),
                passwordEncoder.encode(request.password()),
                Role.USER
        );

        var savedUser = userRepository.save(user);

        String token = generateToken();

        ConfirmationToken confirmationToken = ConfirmationToken.builder()
                .token(token)
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .user(savedUser)
                .confirmationTokenType(ConfirmationTokenType.EMAIL_CONFIRMATION)
                .build();

        confirmationTokenRepository.save(confirmationToken);

        var emailInfo = EmailInfo.builder()
                .emailTo(email)
                .subject("Confirm Email")
                .content(
                        emailUtil.confirmationTemplate(
                                firstName,
                                url + "v1/auth/confirm?token=".concat(token)
                        ).getBytes()
                )
                .type(EmailType.CONFIRMATION)
                .user(user)
                .build();

        // send mail
        try {
            log.info("Sending email to user");
            emailService.sendEmail(emailInfo);
            emailInfo.setStatus(EmailStatus.SENT);
        } catch (Exception e) {
            log.warn("Sending email failed, but user registered successfully," +
                    " exception message: {}", e.getMessage());
            emailInfo.setStatus(EmailStatus.RETRY);
        }

        emailInfoRepository.save(emailInfo);

        log.info(
                "requestPath: '{}', clientIp: '{}', function response: success",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
        return Response.success(
                RegisterResponse.builder()
                        .message("confirmation link sent to your email address")
                        .build()
        );
    }

    @Override
    public Response<?> login(LoginDTO request) {

        log.info(
                "requestPath: '{}', clientIp: '{}', function calling with request",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );

        String email = request.email();
        String password = request.password();

        if (isNull(email, password)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: invalid request data",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(INVALID_REQUEST_DATA);
        }

        if (emailValidator.validate(email)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email format is incorrect",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(EMAIL_FORMAT_IS_INCORRECT);
        }

        var checkUserInDB = userRepository.findByEmail(email);
        if (checkUserInDB.isEmpty()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: user is not registered",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(USER_IS_NOT_REGISTERED);
        }

        if (!checkUserInDB.get().isEnabled()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email is not confirmed",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(EMAIL_IS_NOT_CONFIRMED);
        }

        if (!checkUserInDB.get().isAccountNonLocked()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: user is locked by admin",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(USER_IS_LOCKED_BY_ADMIN);
        }

        int countLoginTryByIpAddress
                = loginHistoryRepository.countLoginHistoriesByIpAddressAndLoginStatusAndLoginTimeBetween(
                logDetail.getIp(),
                LoginStatus.UNSUCCESSFUL,
                LocalDateTime.now().minusMinutes(randomBetween(3, 7)),
                LocalDateTime.now()
        );

        if (countLoginTryByIpAddress >= 3) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: please try again later",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(TRY_AGAIN_LATER);
        }

        var loginLocation = ipDataUtil.loginLocation(logDetail.getIp());
        loginLocationRepository.save(loginLocation);

        String deviceName = headerHolder.getUserAgent();
        var loginHistory = LoginHistory.builder()
                .ipAddress(logDetail.getIp())
                .user(checkUserInDB.get())
                .loginLocation(loginLocation)
                .deviceName(deviceName)
                .build();

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.email(),
                            request.password()
                    )
            );

            List<LoginHistory> loginHistories = loginHistoryRepository.findAllByLoginStatus(
                    LoginStatus.SUCCESSFUL
            );

            if (loginHistories.size() == 0) {
                log.info(
                        "requestPath: '{}', clientIp: '{}', (continued) function response: " +
                                "adding first device as recognized for this user",
                        logDetail.getRequestPath(),
                        logDetail.getIp()
                );

                var userRecognizedDevice = UserRecognizedDevice.builder()
                        .deviceName(deviceName)
                        .ipAddress(logDetail.getIp())
                        .user(checkUserInDB.get())
                        .build();
                userRecognizedDevicesRepository.save(userRecognizedDevice);
            } else {
                // check if next device is used as recognized or not
                var userRecognisedDevices = userRecognizedDevicesRepository.findAllByUser(checkUserInDB.get());
                boolean isDeviceRecognised = userRecognisedDevices.stream().anyMatch(
                        recognizedDevice -> recognizedDevice.getDeviceName().equalsIgnoreCase(deviceName)
                );

                if (!isDeviceRecognised) {
                    log.warn(
                            "requestPath: '{}', clientIp: '{}', function response: new device detected",
                            logDetail.getRequestPath(),
                            logDetail.getIp()
                    );

                    String token = generateToken();

                    // automatically add device as blocked while user accepts it
                    var userBlockedDevice = UserBlockedDevice.builder()
                            .deviceName(deviceName)
                            .user(checkUserInDB.get())
                            .token(token)
                            .ipAddress(logDetail.getIp())
                            .build();
                    userBlockedDeviceRepository.save(userBlockedDevice);

                    ConfirmationToken confirmationToken = ConfirmationToken.builder()
                            .token(token)
                            .expiresAt(LocalDateTime.now().plusMinutes(5))
                            .user(checkUserInDB.get())
                            .confirmationTokenType(ConfirmationTokenType.NEW_DEVICE_CONFIRMATION)
                            .build();

                    confirmationTokenRepository.save(confirmationToken);

                    var emailInfo = EmailInfo.builder()
                            .emailTo(email)
                            .subject("Unrecognized device")
                            .content(
                                    emailUtil.informNewDeviceTemplate(
                                            checkUserInDB.get().getFirstname(),
                                            loginLocation.getLatitude(),
                                            loginLocation.getLongitude(),
                                            url + "v1/auth/verify-device?token=".concat(token)
                                    ).getBytes()
                            )
                            .type(EmailType.INFO)
                            .user(checkUserInDB.get())
                            .build();

                    // send mail
                    try {
                        log.info("Sending email to user");
                        emailService.sendEmail(emailInfo);
                        emailInfo.setStatus(EmailStatus.SENT);
                    } catch (Exception e) {
                        log.warn("Sending email failed," +
                                " exception message: {}", e.getMessage());
                        emailInfo.setStatus(EmailStatus.RETRY);
                    }

                    emailInfoRepository.save(emailInfo);


                    return response(VERIFY_NEW_DEVICE);
                }
            }

            loginHistory.setLoginStatus(LoginStatus.SUCCESSFUL);
            loginHistoryRepository.save(loginHistory);
        } catch (Exception e) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: {}",
                    logDetail.getRequestPath(),
                    logDetail.getIp(),
                    e.getMessage()
            );
            loginHistory.setLoginStatus(LoginStatus.UNSUCCESSFUL);
            loginHistoryRepository.save(loginHistory);
            return response(BAD_CREDENTIALS);
        }

        var user = userRepository.findByEmail(request.email())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);

        log.info(
                "requestPath: '{}', clientIp: '{}', function response: success",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
        return success(LoginResponse.builder().token(jwtToken).build());
    }

    @Override
    public Response<?> confirmToken(String token) {
        log.info(
                "requestPath: '{}', clientIp: '{}', function calling with request: {}",
                logDetail.getRequestPath(),
                logDetail.getIp(),
                token
        );

        ConfirmationToken confirmationToken = confirmationTokenRepository
                .findByToken(token)
                .orElseThrow(
                        () -> new TokenNotFound("token not found")
                );

        if (nonNull(confirmationToken.getConfirmedAt())) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email is already confirmed",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(EMAIL_IS_ALREADY_CONFIRMED);
        }

        LocalDateTime expiresAt = confirmationToken.getExpiresAt();
        if (expiresAt.isBefore(LocalDateTime.now())) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: confirmation token expired",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(CONFIRMATION_TOKEN_EXPIRED);
        }

        confirmationTokenRepository.updateConfirmedAt(token, LocalDateTime.now());
        userRepository.enableUser(confirmationToken.getUser().getEmail());

        log.info(
                "requestPath: '{}', clientIp: '{}', function response: success",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
        return success(
                RegisterResponse.builder()
                        .message("token confirmed successfully")
                        .build()
        );
    }

    @Override
    public Response<?> forgotPassword(ForgotPasswordDTO forgotPasswordDTO) {

        log.info(
                "requestPath: '{}', clientIp: '{}', function calling with request: {}",
                logDetail.getRequestPath(),
                logDetail.getIp(),
                forgotPasswordDTO
        );
        String email = forgotPasswordDTO.email();

        if (isNull(email)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: invalid request data",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(INVALID_REQUEST_DATA);
        }

        if (emailValidator.validate(email)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email format is incorrect",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(EMAIL_FORMAT_IS_INCORRECT);
        }

        Optional<User> user = userRepository.findByEmail(email);

        if (user.isEmpty()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: " +
                            "email will be sent if user exists",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(EMAIL_SENT_WITH_PASSWORD_RESET);
        }

        if (!user.get().isEnabled()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email is not confirmed",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(EMAIL_IS_NOT_CONFIRMED);
        }

        if (!user.get().isAccountNonLocked()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: user is locked by admin",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(USER_IS_LOCKED_BY_ADMIN);
        }

        String token = generateToken();

        var resetPasswordToken = ResetPasswordToken.builder()
                .token(token)
                .expiresAt(LocalDateTime.now().plusMinutes(1))
                .user(user.get())
                .status(Status.ACTIVE)
                .build();

        int countDisabledTokens = disableAllActiveResetTokens(user.get());

        if (countDisabledTokens >= 3) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: " +
                            "daily email sending limit exceeded",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(DAILY_EMAIL_LIMIT_EXCEEDED);
        }

        resetPasswordTokenRepository.save(resetPasswordToken);

        var emailInfo = EmailInfo.builder()
                .emailTo(user.get().getEmail())
                .type(EmailType.RESET_PASSWORD)
                .user(user.get())
                .subject("Reset password")
                .content(
                        emailUtil.resetPasswordTemplate(
                        user.get().getFirstname(),
                        token
                    ).getBytes()
                )
                .build();

        try {
            log.info("Trying to send an reset email");
            emailService.sendEmail(emailInfo);
            emailInfo.setStatus(EmailStatus.SENT);

        } catch (Exception e) {
            log.warn("Exception occurred while sending an email");
            emailInfo.setStatus(EmailStatus.RETRY);
        } finally {
            emailInfoRepository.save(emailInfo);
        }

        log.info(
                "requestPath: '{}', clientIp: '{}', function response: success",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
        return success(
                ForgotPasswordResponse.builder()
                        .message("Reset instructions sent to your email address")
                        .build()
        );
    }

    @Override
    public Response<?> resetPassword(ResetPasswordDTO resetPasswordDTO) {
        log.info(
                "requestPath: '{}', clientIp: '{}', function calling with parameters",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );

        String password = resetPasswordDTO.newPassword();
        String confirmPassword = resetPasswordDTO.confirmNewPassword();
        String token = resetPasswordDTO.token();

        if (isNull(password, confirmPassword, token)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: invalid request data",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(INVALID_REQUEST_DATA);
        }

        if (!token.matches(RESET_PASSWORD_TOKEN_REGEX)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: invalid token",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(INVALID_RESET_PASSWORD_TOKEN);
        }

        ResetPasswordToken resetPasswordToken =
                resetPasswordTokenRepository.findResetPasswordTokenByToken(token).orElse(null);

        if (Objects.isNull(resetPasswordToken)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: token not found",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(RESET_PASSWORD_TOKEN_NOT_FOUND);
        }

        LocalDateTime currentTime = LocalDateTime.now();
        if (currentTime.isAfter(resetPasswordToken.expiresAt)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: token expired",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(RESET_PASSWORD_TOKEN_EXPIRED);
        }

        if (resetPasswordToken.status.equals(Status.INACTIVE)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: token is used",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(RESET_PASSWORD_TOKEN_IS_DISABLED);
        }

        User user = resetPasswordTokenRepository.getUserByActiveToken(token).orElse(null);

        if (isNull(user)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: user not found",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(USER_NOT_FOUND);
        }

        if (!password.equals(confirmPassword)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: passwords did not match",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(PASSWORDS_DID_NOT_MATCH);
        }

        try {
            log.info("Updating user data");
            userRepository.updatePasswordByUserId(
                    Objects.requireNonNull(user).getId(), passwordEncoder.encode(password)
            );
            resetPasswordTokenRepository.updateAllByStatusAndUser(Status.INACTIVE, user);
        } catch (Exception e) {
            log.warn("Exception occurred while updating user, message: {}", e.getMessage());
            return failed(EXCEPTION_OCCURRED);
        }


        log.info(
                "requestPath: '{}', clientIp: '{}', function response: success",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
        return success(null);
    }

    @Override
    public Response<?> verifyDevice(String token) {
        log.info(
                "requestPath: '{}', clientIp: '{}', function calling with parameters: {}",
                logDetail.getRequestPath(),
                logDetail.getIp(),
                token
        );

        if (isNull(token)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: verification token is null",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(DEVICE_VERIFICATION_TOKEN_IS_NULL);
        }

        // regex is same with reset password token
        if (!token.matches(RESET_PASSWORD_TOKEN_REGEX)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: " +
                            "device verification token is invalid",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(DEVICE_VERIFICATION_TOKEN_IS_NOT_VALID);
        }

        ConfirmationToken confirmationToken = confirmationTokenRepository
                .findByToken(token)
                .orElseThrow(
                        () -> new TokenNotFound("token not found")
                );

        if (nonNull(confirmationToken.getConfirmedAt())) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: " +
                            "device verification token is already confirmed",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(DEVICE_VERIFICATION_TOKEN_IS_ALREADY_CONFIRMED);
        }

        LocalDateTime expiresAt = confirmationToken.getExpiresAt();
        if (expiresAt.isBefore(LocalDateTime.now())) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: confirmation token expired",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(CONFIRMATION_TOKEN_EXPIRED);
        }

        var userBlockedDevice = userBlockedDeviceRepository.findByToken(token);
        var userRecognizedDevice = UserRecognizedDevice.builder()
                .deviceName(userBlockedDevice.getDeviceName())
                .ipAddress(logDetail.getIp())
                .user(userBlockedDevice.user)
                .build();
        userRecognizedDevicesRepository.save(userRecognizedDevice);
        confirmationTokenRepository.updateConfirmedAt(token, LocalDateTime.now());
        userBlockedDeviceRepository.updateUserBlockedDeviceByToken(token, Status.INACTIVE);


        log.info(
                "requestPath: '{}', clientIp: '{}', function response: success",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
        return success(null);
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    private String generateToken() {
        return UUID.randomUUID().toString();
    }

    public int disableAllActiveResetTokens(User user) {
        resetPasswordTokenRepository.updateAllByStatusAndUser(Status.INACTIVE, user);

        LocalDateTime localDateTime = LocalDateTime.now();
        LocalDateTime startedAt
                = localDateTime.withHour(0).withMinute(0).withSecond(0).withNano(0);
        LocalDateTime endsAt
                = localDateTime.withHour(23).withMinute(59).withSecond(59).withNano(9999999);
        return resetPasswordTokenRepository.countByStatusAndCreatedAtBetween(Status.INACTIVE, startedAt, endsAt);
    }
}
