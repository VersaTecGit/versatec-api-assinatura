package com.example.springboot.utils;

public class FormatterUtils {
    public static String formatCpfOrCnpj(String number) {
        if (number == null || number.isEmpty()) {
            return "";
        }

        number = number.replaceAll("\\D", "");

        if (number.length() == 11) {
            return number.replaceAll("(\\d{3})(\\d{3})(\\d{3})(\\d{2})", "$1.$2.$3-$4");
        } else if (number.length() == 14) {
            return number.replaceAll("(\\d{2})(\\d{4})(\\d{4})(\\d{2})(\\d{1})", "$1.$2.$3/$4-$5");
        } else {
            return "Invalid length";
        }
    }
}
