package io.shikhsaidov.secureaccess.service.impl;

import io.shikhsaidov.secureaccess.dto.ForgotPasswordDTO;
import io.shikhsaidov.secureaccess.dto.LoginDTO;
import io.shikhsaidov.secureaccess.dto.RegisterDTO;
import io.shikhsaidov.secureaccess.dto.ResetPasswordDTO;
import io.shikhsaidov.secureaccess.entity.*;
import io.shikhsaidov.secureaccess.enums.*;
import io.shikhsaidov.secureaccess.exception.TokenNotFound;
import io.shikhsaidov.secureaccess.repository.*;
import io.shikhsaidov.secureaccess.response.model.ForgotPasswordResponse;
import io.shikhsaidov.secureaccess.response.model.LoginResponse;
import io.shikhsaidov.secureaccess.response.model.RegisterResponse;
import io.shikhsaidov.secureaccess.response.Response;
import io.shikhsaidov.secureaccess.service.AuthenticationService;
import io.shikhsaidov.secureaccess.service.EmailService;
import io.shikhsaidov.secureaccess.service.JwtService;
import io.shikhsaidov.secureaccess.util.EmailUtil;
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
    private final AuthenticationManager authenticationManager;
    private final EmailValidator emailValidator;
    private final EmailUtil emailUtil;
    private final EmailService emailService;
    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final EmailInfoRepository emailInfoRepository;
    private final ResetPasswordTokenRepository resetPasswordTokenRepository;

    @Value("${url}")
    public String url;

    @Value("${reset.password.token.regex.regexp}")
    public String RESET_PASSWORD_TOKEN_REGEX;

    @Override
    public Response<?> register(RegisterDTO request) {

        log.info("function calling with request");
        String email = request.email();
        String password = request.password();
        String firstName = request.firstName();
        String lastName = request.lastName();

        if (isNull(email, password, firstName, lastName)) {
            log.warn("Invalid request data");
            return failed(INVALID_REQUEST_DATA, "invalid request data");
        }

        if (emailValidator.validate(email)) {
            log.warn("Email format is incorrect");
            return response(EMAIL_FORMAT_IS_INCORRECT, "email format is incorrect", null);
        }

        // check if user is exists
        var checkUserInDB = userRepository.findByEmail(request.email());

        if (checkUserInDB.isPresent()) {
            log.warn("Email is already taken");
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

        // creating confirmation token
        String token = UUID.randomUUID().toString();

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
            emailService.sendEmail(emailInfo);

            emailInfo.setStatus(EmailStatus.SENT);
        } catch (Exception e) {
            log.warn("Sending email failed, but user registered successfully," +
                    " exception message: {}", e.getMessage());
            emailInfo.setStatus(EmailStatus.RETRY);
        }

        emailInfoRepository.save(emailInfo);

        log.info("user successfully registered!");
        return Response.success(
                "success",
                RegisterResponse.builder()
                        .message("confirmation link sent to your email address")
                        .build()
        );
    }

    @Override
    public Response<?> login(LoginDTO request) {

        log.info("function calling with request parameters");

        String email = request.email();
        String password = request.password();

        if (isNull(email, password)) {
            log.warn("invalid request data");
            return failed(INVALID_REQUEST_DATA, "invalid request data");
        }

        if (emailValidator.validate(email)) {
            log.warn("Email format is incorrect");
            return response(EMAIL_FORMAT_IS_INCORRECT, "email format is incorrect", null);
        }

        var checkUserInDB = userRepository.findByEmail(email);
        if (checkUserInDB.isEmpty()) {
            log.warn("User is not registered yet");
            return failed(USER_IS_NOT_REGISTERED, "user is not registered yet");
        }

        if (!checkUserInDB.get().isEnabled()) {
            log.warn("User did not confirmed email address");
            return failed(EMAIL_IS_NOT_CONFIRMED, "email is not confirmed");
        }

        if (!checkUserInDB.get().isAccountNonLocked()) {
            log.warn("User is locked by admin");
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

        log.info("user successfully logged in");
        return Response.success("success", LoginResponse.builder().token(jwtToken).build());
    }

    @Override
    public Response<?> confirmToken(String token) {
        ConfirmationToken confirmationToken = confirmationTokenRepository
                .findByToken(token)
                .orElseThrow(
                        () -> new TokenNotFound("token not found")
                );

        if (nonNull(confirmationToken.getConfirmedAt())) {
            log.warn("Email is already confirmed");
            return failed(EMAIL_IS_ALREADY_CONFIRMED, "email is already confirmed");
        }

        LocalDateTime expiresAt = confirmationToken.getExpiresAt();
        if (expiresAt.isBefore(LocalDateTime.now())) {
            log.warn("Confirmation token expired");
            return failed(CONFIRMATION_TOKEN_EXPIRED, "confirmation token expired");
        }

        confirmationTokenRepository.updateConfirmedAt(token, LocalDateTime.now());
        userRepository.enableUser(confirmationToken.getUser().getEmail());

        return success(
                "success",
                RegisterResponse.builder()
                        .message("token confirmed successfully")
                        .build()
        );
    }

    @Override
    public Response<?> forgotPassword(ForgotPasswordDTO forgotPasswordDTO) {
        String email = forgotPasswordDTO.email();

        if (isNull(email)) {
            log.warn("Please provide email for resetting your password");
            return failed(
                    INVALID_REQUEST_DATA,
                    "Provide an email for resetting your password"
            );
        }

        if (emailValidator.validate(email)) {
            log.warn("Email format is incorrect");
            return response(EMAIL_FORMAT_IS_INCORRECT, "email format is incorrect", null);
        }

        Optional<User> user = userRepository.findByEmail(email);

        if (user.isEmpty()) {
            log.warn("User with email: {} does not exist", email);
            return failed(
                    EMAIL_SENT_WITH_PASSWORD_RESET,
                    "we will send reset link to your email if it is exist"
            );
        }

        if (!user.get().isEnabled()) {
            log.warn("User did not confirmed an email yet");
            return failed(
                    EMAIL_IS_NOT_CONFIRMED,
                    "Email is not confirmed yet"
            );
        }

        if (!user.get().isAccountNonLocked()) {
            log.warn("This user is blocked by admin");
            return failed(
                    USER_IS_LOCKED_BY_ADMIN,
                    "User is locked by admin"
            );
        }

        String token = generateResetToken();

        var resetPasswordToken = ResetPasswordToken.builder()
                .token(token)
                .expiresAt(LocalDateTime.now().plusMinutes(1))
                .user(user.get())
                .status(Status.ACTIVE)
                .build();

        int countDisabledTokens = disableAllActiveResetTokens(user.get());

        if (countDisabledTokens >= 3) {
            log.warn("You exceeded the daily limit number of forgot email sending");
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

        return success(
                "success",
                ForgotPasswordResponse.builder()
                        .message("Reset instructions sent to your email address")
                        .build()
        );
    }

    @Override
    public Response<?> resetPassword(ResetPasswordDTO resetPasswordDTO) {
        log.info("Calling resetPassword function with parameters");

        String password = resetPasswordDTO.newPassword();
        String confirmPassword = resetPasswordDTO.confirmNewPassword();
        String token = resetPasswordDTO.token();

        if (isNull(password, confirmPassword, token)) {
            log.warn("Invalid request data");
            return failed(
                    INVALID_REQUEST_DATA,
                    "Invalid request data"
            );
        }

        if (!token.matches(RESET_PASSWORD_TOKEN_REGEX)) {
            log.warn("Reset password token is invalid");
            return failed(
                    INVALID_TOKEN,
                    "reset password token is invalid"
            );
        }

        ResetPasswordToken resetPasswordToken =
                resetPasswordTokenRepository.findResetPasswordTokenByToken(token).orElse(null);

        if (Objects.isNull(resetPasswordToken)) {
            log.warn("Reset password token not found");
            return failed(
                    NOT_FOUND,
                    "Reset password token not found"
            );
        }

        if (resetPasswordToken.status.equals(Status.INACTIVE)) {
            log.warn("Token is disabled");
            return failed(
                    TOKEN_DISABLED,
                    "Reset password token is disabled"
            );
        }

        LocalDateTime currentTime = LocalDateTime.now();
        if (currentTime.isAfter(resetPasswordToken.expiresAt)) {
            log.warn("Reset password token is expired");
            return failed(
                    TOKEN_EXPIRED,
                    "Reset password token is expired"
            );
        }

        User user = resetPasswordTokenRepository.getUserByActiveToken(token).orElse(null);

        if (Objects.isNull(user)) {
            log.warn("User is not found");
            return failed(
                    NOT_FOUND,
                    "User is not found"
            );
        }

        if (!password.equals(confirmPassword)) {
            log.warn("Passwords did not match");
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

    private String generateResetToken() {
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
