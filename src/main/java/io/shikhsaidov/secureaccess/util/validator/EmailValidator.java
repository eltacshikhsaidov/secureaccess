package io.shikhsaidov.secureaccess.util.validator;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

import java.util.regex.Matcher;
import java.util.regex.Pattern;


@Component
@PropertySource("classpath:email.properties")
public class EmailValidator {

    @Value("${regex.regexp}")
    public String EMAIL_REGEX;

    public boolean validate(String email) {
        Pattern pattern = Pattern.compile(EMAIL_REGEX);
        Matcher matcher = pattern.matcher(email);
        return !matcher.matches();
    }
}
