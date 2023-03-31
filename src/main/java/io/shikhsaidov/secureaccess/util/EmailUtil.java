package io.shikhsaidov.secureaccess.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.charset.Charset;


@Component
@PropertySource("classpath:email.properties")
public class EmailUtil {

    @Value("${confirmation.template.path}")
    public String CONFIRMATION_TEMPLATE_PATH;

    @Value("${reset.password.template.path}")
    public String RESET_PASSWORD_TEMPLATE_PATH;

    public String confirmationTemplate(String userName, String confirmationLink) {
        String templateString = null;

        try {

            templateString = StreamUtils.copyToString(
                    new ClassPathResource(CONFIRMATION_TEMPLATE_PATH).getInputStream(),
                            Charset.defaultCharset())
                    .replace("name_replace", StringUtils.capitalize(userName))
                    .replace("link_replace", confirmationLink);

        } catch (IOException e) {
            e.printStackTrace();
        }

        return templateString;
    }

    public String resetPasswordTemplate(String userName, String resetPasswordLink) {
        String templateString = null;

        try {

            templateString = StreamUtils.copyToString(
                            new ClassPathResource(RESET_PASSWORD_TEMPLATE_PATH).getInputStream(),
                            Charset.defaultCharset())
                    .replace("name_replace", StringUtils.capitalize(userName))
                    .replace("link_replace", resetPasswordLink);

        } catch (IOException e) {
            e.printStackTrace();
        }

        return templateString;
    }

}
