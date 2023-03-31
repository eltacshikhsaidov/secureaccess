package io.shikhsaidov.secureaccess.service;

import io.shikhsaidov.secureaccess.dto.ForgotPasswordDTO;
import io.shikhsaidov.secureaccess.dto.LoginDTO;
import io.shikhsaidov.secureaccess.dto.RegisterDTO;
import io.shikhsaidov.secureaccess.dto.ResetPasswordDTO;
import io.shikhsaidov.secureaccess.response.Response;

public interface AuthenticationService {
    Response<?> register(RegisterDTO registerDTO);
    Response<?> login(LoginDTO loginDTO);
    Response<?> confirmToken(String token);

    Response<?> forgotPassword(ForgotPasswordDTO forgotPasswordDTO);
    Response<?> resetPassword(ResetPasswordDTO resetPasswordDTO);
}
