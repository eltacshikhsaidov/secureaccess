package io.shikhsaidov.secureaccess.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.charset.Charset;


@Component
@PropertySources({
        @PropertySource("classpath:email.properties"),
        @PropertySource("classpath:config-${application.environment}.properties")
})
public class EmailUtil {

    @Value("${confirmation.template.path}")
    public String CONFIRMATION_TEMPLATE_PATH;

    @Value("${reset.password.template.path}")
    public String RESET_PASSWORD_TEMPLATE_PATH;

    @Value("${inform.new.device.to.user.template.path}")
    public String INFORM_NEW_DEVICE_TO_USER_TEMPLATE_PATH;

    @Value("${google.map.api.key}")
    public String googleMapApiKey;

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

    public String informNewDeviceTemplate(String userName, double latitude, double longitude, String verifyLink) {
        String templateString = null;

        try {

            templateString = StreamUtils.copyToString(
                            new ClassPathResource(INFORM_NEW_DEVICE_TO_USER_TEMPLATE_PATH).getInputStream(),
                            Charset.defaultCharset())
                    .replace("name_replace", StringUtils.capitalize(userName))
                    .replace("api_key_replace", googleMapApiKey)
                    .replace("latitude_replace", String.valueOf(latitude))
                    .replace("longitude_replace", String.valueOf(longitude))
                    .replace("link_replace", verifyLink);

        } catch (IOException e) {
            e.printStackTrace();
        }

        return templateString;
    }

}
