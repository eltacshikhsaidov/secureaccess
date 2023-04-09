package io.shikhsaidov.secureaccess.util;

import io.shikhsaidov.secureaccess.enums.Language;

public class NumberUtil {

    public static String number2Text(int number, Language language) {
        String[] units;
        String[] teens;
        String[] tens;
        String hundred;
        String thousand;
        String million;
        String minus;
        String finalResponse;
        String zero;
        switch (language) {
            case EN -> {
                units = new String[]{"", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"};
                teens = new String[]{"eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"};
                tens = new String[]{"", "ten", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"};
                hundred = "hundred";
                thousand = "thousand";
                million = "million";
                minus = "minus";
                zero = "zero";
                finalResponse = "Number too large to convert to text";
            }
            case RU -> {
                units = new String[]{"", "один", "два", "три", "четыре", "пять", "шесть", "семь", "восемь", "девять"};
                teens = new String[]{"одиннадцать", "двенадцать", "тринадцать", "четырнадцать", "пятнадцать", "шестнадцать", "семнадцать", "восемнадцать", "девятнадцать"};
                tens = new String[]{"", "десять", "двадцать", "тридцать", "сорок", "пятьдесят", "шестьдесят", "семьдесят", "восемьдесят", "девяносто"};
                hundred = "сот";
                thousand = "тысяч";
                million = "миллион";
                minus = "минус";
                zero = "ноль";
                finalResponse = "Слишком большое число для преобразования в текст";
            }
            case AZ -> {
                units = new String[]{"", "bir", "iki", "üç", "dörd", "beş", "altı", "yeddi", "səkkiz", "doqquz"};
                teens = new String[]{"on bir", "on iki", "on üç", "on dörd", "on beş", "on altı", "on yeddi", "on səkkiz", "on doqquz"};
                tens = new String[]{"", "on", "iyirmi", "otuz", "qırx", "əlli", "altmış", "yetmiş", "səksən", "doxsan"};
                hundred = "yüz";
                thousand = "min";
                million = "milyon";
                minus = "mənfi";
                zero = "sıfır";
                finalResponse = "Ədəd sözə çevirmək üçün çox böyükdür";
            }
            default -> {
                return "Unsupported language";
            }
        }
        if (number == 0) return zero;
        if (number < 0) return minus + number2Text(Math.abs(number), language);
        if (number < 10) return units[number];
        if (number < 20) return teens[number - 11];
        if (number < 100) return tens[number / 10] + ((number % 10 != 0) ? " " : "") + units[number % 10];
        if (number < 1000) return units[number / 100] +
                " " + hundred + ((number % 100 != 0) ? " " : "") + number2Text(number % 100, language);
        if (number < 1000000) return number2Text(number / 1000, language) +
                " " + thousand + ((number % 1000 != 0) ? " " : "") + number2Text(number % 1000, language);
        if (number < 1000000000) return number2Text(number / 1000000, language) +
                " " + million + ((number % 1000000 != 0) ? " " : "") + number2Text(number % 1000000, language);
        return finalResponse;
    }


}
