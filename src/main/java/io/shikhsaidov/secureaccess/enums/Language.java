package io.shikhsaidov.secureaccess.enums;

public enum Language {
    AZ("AZ"), EN("EN"), RU("RU");

    private final String value;
    private static final Language DEFAULT_LANGUAGE = EN;

    Language(String value) {
        this.value = value;
    }

    public static Language of(String name) {
        for (Language language : values()) {
            if (language.value.equals(name)) {
                return language;
            }
        }
        return DEFAULT_LANGUAGE;
    }


    public String value() {
        return value;
    }
}
