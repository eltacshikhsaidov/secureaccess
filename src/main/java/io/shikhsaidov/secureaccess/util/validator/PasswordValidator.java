package io.shikhsaidov.secureaccess.util.validator;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
@PropertySource("classpath:config-${application.environment}.properties")
public class PasswordValidator {

    @Value("${password.validation.regex.regexp}")
    public String PASSWORD_VALIDATOR_REGEX;

    public boolean validate(String password) {
        Pattern pattern = Pattern.compile(PASSWORD_VALIDATOR_REGEX);
        Matcher matcher = pattern.matcher(password);
        return !matcher.matches();
    }
}
