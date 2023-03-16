package io.shikhsaidov.secureaccess.util;

public class Utility {
    public static boolean isNull(Object... objects) {
        for (Object o: objects) {
            if (java.util.Objects.isNull(o)){
                return true;
            }
        }

        return false;
    }
}
