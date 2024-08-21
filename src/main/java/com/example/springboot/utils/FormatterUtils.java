package com.example.springboot.utils;

public class FormatterUtils {

    /**
     * Formata um número de CPF ou CNPJ.
     *
     * @param number Número de CPF ou CNPJ
     * @return Número de CPF ou CNPJ formatado
     */
    public static String formatCpfOrCnpj(String number) {
        if (number == null || number.isEmpty()) {
            return "";
        }

        number = number.replaceAll("\\D", "");

        if (number.length() == 11) {
            // CPF
            return number.replaceAll("(\\d{3})(\\d{3})(\\d{3})(\\d{2})", "$1.$2.$3-$4");
        } else if (number.length() == 14) {
            // CNPJ
            return number.replaceAll("(\\d{2})(\\d{3})(\\d{3})(\\d{4})(\\d{2})", "$1.$2.$3/$4-$5");
        } else {
            return "Invalid length";
        }
    }
}
