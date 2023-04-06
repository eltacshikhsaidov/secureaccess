package io.shikhsaidov.secureaccess.service.impl;

import io.shikhsaidov.secureaccess.dto.ForgotPasswordDTO;
import io.shikhsaidov.secureaccess.dto.LoginDTO;
import io.shikhsaidov.secureaccess.dto.RegisterDTO;
import io.shikhsaidov.secureaccess.dto.ResetPasswordDTO;
import io.shikhsaidov.secureaccess.entity.*;
import io.shikhsaidov.secureaccess.enums.*;
import io.shikhsaidov.secureaccess.exception.TokenNotFound;
import io.shikhsaidov.secureaccess.holder.HeaderHolder;
import io.shikhsaidov.secureaccess.repository.*;
import io.shikhsaidov.secureaccess.response.model.ForgotPasswordResponse;
import io.shikhsaidov.secureaccess.response.model.LoginResponse;
import io.shikhsaidov.secureaccess.response.model.RegisterResponse;
import io.shikhsaidov.secureaccess.response.Response;
import io.shikhsaidov.secureaccess.service.AuthenticationService;
import io.shikhsaidov.secureaccess.service.EmailService;
import io.shikhsaidov.secureaccess.service.JwtService;
import io.shikhsaidov.secureaccess.util.EmailUtil;
import io.shikhsaidov.secureaccess.util.LogDetail;
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
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static io.shikhsaidov.secureaccess.response.Response.*;
import static io.shikhsaidov.secureaccess.response.ResponseCodes.*;
import static io.shikhsaidov.secureaccess.util.Utility.isNull;
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
    private final HeaderHolder headerHolder;

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
        Language language = Language.of(headerHolder.getLanguage());

        if (isNull(email, password, firstName, lastName)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: invalid request data",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(INVALID_REQUEST_DATA, "invalid request data");
        }

        if (emailValidator.validate(email)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email format is incorrect",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(EMAIL_FORMAT_IS_INCORRECT, "email format is incorrect", null);
        }

        // check if user is exists
        var checkUserInDB = userRepository.findByEmail(request.email());

        if (checkUserInDB.isPresent()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email is taken",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(EMAIL_IS_TAKEN, "email is taken", null);
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
                "success",
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
            return failed(INVALID_REQUEST_DATA, "invalid request data");
        }

        if (emailValidator.validate(email)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email format is incorrect",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(EMAIL_FORMAT_IS_INCORRECT, "email format is incorrect", null);
        }

        var checkUserInDB = userRepository.findByEmail(email);
        if (checkUserInDB.isEmpty()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: user is not registered",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(USER_IS_NOT_REGISTERED, "user is not registered");
        }

        if (!checkUserInDB.get().isEnabled()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email is not confirmed",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(EMAIL_IS_NOT_CONFIRMED, "email is not confirmed");
        }

        if (!checkUserInDB.get().isAccountNonLocked()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: user is locked by admin",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(USER_IS_LOCKED_BY_ADMIN, "user is locked by admin");
        }

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );
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
        return Response.success("success", LoginResponse.builder().token(jwtToken).build());
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
            return failed(EMAIL_IS_ALREADY_CONFIRMED, "email is already confirmed");
        }

        LocalDateTime expiresAt = confirmationToken.getExpiresAt();
        if (expiresAt.isBefore(LocalDateTime.now())) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: confirmation token expired",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(CONFIRMATION_TOKEN_EXPIRED, "confirmation token expired");
        }

        confirmationTokenRepository.updateConfirmedAt(token, LocalDateTime.now());
        userRepository.enableUser(confirmationToken.getUser().getEmail());

        log.info(
                "requestPath: '{}', clientIp: '{}', function response: success",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
        return success(
                "success",
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
            return failed(
                    INVALID_REQUEST_DATA,
                    "Provide an email for resetting your password"
            );
        }

        if (emailValidator.validate(email)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email format is incorrect",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return response(EMAIL_FORMAT_IS_INCORRECT, "email format is incorrect", null);
        }

        Optional<User> user = userRepository.findByEmail(email);

        if (user.isEmpty()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email will be sent if user exists",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(
                    EMAIL_SENT_WITH_PASSWORD_RESET,
                    "we will send reset link to your email if it is exist"
            );
        }

        if (!user.get().isEnabled()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: email is not confirmed",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(
                    EMAIL_IS_NOT_CONFIRMED,
                    "Email is not confirmed"
            );
        }

        if (!user.get().isAccountNonLocked()) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: user is locked by admin",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(
                    USER_IS_LOCKED_BY_ADMIN,
                    "User is locked by admin"
            );
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
                    "requestPath: '{}', clientIp: '{}', function response: daily email sending limit exceeded",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(
                    DAILY_EMAIL_LIMIT_EXCEEDED,
                    "Daily email sending limit exceeded for forgot email option"
            );
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
                "success",
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
            return failed(
                    INVALID_REQUEST_DATA,
                    "Invalid request data"
            );
        }

        if (!token.matches(RESET_PASSWORD_TOKEN_REGEX)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: invalid token",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(
                    INVALID_TOKEN,
                    "reset password token is invalid"
            );
        }

        ResetPasswordToken resetPasswordToken =
                resetPasswordTokenRepository.findResetPasswordTokenByToken(token).orElse(null);

        if (Objects.isNull(resetPasswordToken)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: token not found",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(
                    NOT_FOUND,
                    "Reset password token not found"
            );
        }

        LocalDateTime currentTime = LocalDateTime.now();
        if (currentTime.isAfter(resetPasswordToken.expiresAt)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: token expired",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(
                    TOKEN_EXPIRED,
                    "Reset password token is expired"
            );
        }

        if (resetPasswordToken.status.equals(Status.INACTIVE)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: token is used",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(
                    TOKEN_DISABLED,
                    "Reset password token is disabled"
            );
        }

        User user = resetPasswordTokenRepository.getUserByActiveToken(token).orElse(null);

        if (Objects.isNull(user)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: user not found",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(
                    NOT_FOUND,
                    "User is not found"
            );
        }

        if (!password.equals(confirmPassword)) {
            log.warn(
                    "requestPath: '{}', clientIp: '{}', function response: passwords did not match",
                    logDetail.getRequestPath(),
                    logDetail.getIp()
            );
            return failed(
                    PASSWORDS_DID_NOT_MATCH,
                    "Passwords did not match"
            );
        }

        try {
            log.info("Updating user data");
            userRepository.updatePasswordByUserId(user.getId(), passwordEncoder.encode(password));
            resetPasswordTokenRepository.updateAllByStatusAndUser(Status.INACTIVE, user);
        } catch (Exception e) {
            log.warn("Exception occurred while updating user, message: {}", e.getMessage());
            return failed(
                    EXCEPTION_OCCURRED,
                    "Exception occurred while updating user"
            );
        }


        log.info(
                "requestPath: '{}', clientIp: '{}', function response: success",
                logDetail.getRequestPath(),
                logDetail.getIp()
        );
        return success("success", null);
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
        LocalDateTime startedAt = localDateTime.withHour(0).withMinute(0).withSecond(0).withNano(0);
        LocalDateTime endsAt = localDateTime.withHour(23).withMinute(59).withSecond(59).withNano(9999999);
        return resetPasswordTokenRepository.countByStatusAndCreatedAtBetween(Status.INACTIVE, startedAt, endsAt);
    }
}
