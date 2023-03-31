package io.shikhsaidov.secureaccess.service.impl;

import io.shikhsaidov.secureaccess.dto.LoginDTO;
import io.shikhsaidov.secureaccess.dto.RegisterDTO;
import io.shikhsaidov.secureaccess.entity.ConfirmationToken;
import io.shikhsaidov.secureaccess.entity.EmailInfo;
import io.shikhsaidov.secureaccess.entity.Token;
import io.shikhsaidov.secureaccess.entity.User;
import io.shikhsaidov.secureaccess.enums.EmailStatus;
import io.shikhsaidov.secureaccess.enums.EmailType;
import io.shikhsaidov.secureaccess.enums.Role;
import io.shikhsaidov.secureaccess.enums.TokenType;
import io.shikhsaidov.secureaccess.exception.TokenNotFound;
import io.shikhsaidov.secureaccess.repository.ConfirmationTokenRepository;
import io.shikhsaidov.secureaccess.repository.EmailInfoRepository;
import io.shikhsaidov.secureaccess.repository.TokenRepository;
import io.shikhsaidov.secureaccess.repository.UserRepository;
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

    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EmailValidator emailValidator;

    private final EmailUtil emailUtil;

    private final EmailService emailService;

    private final ConfirmationTokenRepository confirmationTokenRepository;

    private final EmailInfoRepository emailInfoRepository;

    @Value("${url}")
    public String url;

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
        var checkUserInDB = repository.findByEmail(request.email());

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

        var savedUser = repository.save(user);

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

        var checkUserInDB = repository.findByEmail(email);
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
        var user = repository.findByEmail(request.email())
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
        repository.enableUser(confirmationToken.getUser().getEmail());

        return success(
                "success",
                RegisterResponse.builder()
                        .message("token confirmed successfully")
                        .build()
        );
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
}
