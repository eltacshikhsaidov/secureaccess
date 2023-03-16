package io.shikhsaidov.secureaccess.service.impl;

import io.shikhsaidov.secureaccess.dto.LoginDTO;
import io.shikhsaidov.secureaccess.dto.RegisterDTO;
import io.shikhsaidov.secureaccess.entity.Token;
import io.shikhsaidov.secureaccess.entity.User;
import io.shikhsaidov.secureaccess.entity.role.Role;
import io.shikhsaidov.secureaccess.entity.tokentype.TokenType;
import io.shikhsaidov.secureaccess.repository.TokenRepository;
import io.shikhsaidov.secureaccess.repository.UserRepository;
import io.shikhsaidov.secureaccess.response.RegisterResponse;
import io.shikhsaidov.secureaccess.response.Response;
import io.shikhsaidov.secureaccess.service.AuthenticationService;
import io.shikhsaidov.secureaccess.service.JwtService;
import io.shikhsaidov.secureaccess.util.EmailUtil;
import io.shikhsaidov.secureaccess.util.validator.EmailValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static io.shikhsaidov.secureaccess.response.Response.failed;
import static io.shikhsaidov.secureaccess.response.Response.response;
import static io.shikhsaidov.secureaccess.response.ResponseCodes.*;
import static io.shikhsaidov.secureaccess.util.Utility.isNull;

@Log4j2
@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EmailValidator emailValidator;

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

        var user = User.builder()
                .firstname(request.firstName())
                .lastname(request.lastName())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.USER)
                .build();
        var savedUser = repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        saveUserToken(savedUser, jwtToken);

        log.info("user successfully registered!");
        return Response.success("success", RegisterResponse.builder().token(jwtToken).build());
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
        return Response.success("success", RegisterResponse.builder().token(jwtToken).build());
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
