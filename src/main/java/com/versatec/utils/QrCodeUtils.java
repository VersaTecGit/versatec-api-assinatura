package com.versatec.utils;

import io.nayuki.qrcodegen.QrCode;

import java.awt.image.BufferedImage;
import java.util.Objects;

public class QrCodeUtils {

    /**
     * Gera uma imagem de código QR com base no texto fornecido.
     *
     * @param barcodeText O texto a ser codificado no código QR.
     *
     * @return Uma imagem {@link BufferedImage} representando o código QR gerado.
     */
    public static BufferedImage generateQrcode(String barcodeText) {
        QrCode qrCode = QrCode.encodeText(barcodeText, QrCode.Ecc.HIGH);
        return QrCodeUtils.toImage(qrCode, 4, 0, 0xFFFFFF, 0x000000);
    }

    /**
     * Converte um objeto {@link QrCode} para uma imagem {@link BufferedImage}.
     *
     * @param qr         O objeto {@link QrCode} a ser convertido.
     * @param scale      O fator de escala da imagem. O valor deve ser maior que zero.
     * @param border     A largura da borda da imagem em pixels. O valor deve ser maior ou igual a zero.
     * @param lightColor A cor da região de fundo da imagem em RGB.
     * @param darkColor  A cor da região escura da imagem em RGB.
     * @return Uma imagem {@link BufferedImage} representando o código QR gerado.
     * @throws IllegalArgumentException Se o valor de {@code scale} ou {@code border} for menor ou igual a zero.
     */
    private static BufferedImage toImage(QrCode qr, int scale, int border, int lightColor, int darkColor) {
        Objects.requireNonNull(qr);
        if (scale <= 0 || border < 0) {
            throw new IllegalArgumentException("Valor fora do intervalo");
        }
        if (border > Integer.MAX_VALUE / 2 || qr.size + border * 2L > Integer.MAX_VALUE / scale) {
            throw new IllegalArgumentException("Valor de Escala ou borda grandes, ou incompatíveis");
        }

        BufferedImage result = new BufferedImage(
                (qr.size + border * 2) * scale,
                (qr.size + border * 2) * scale,
                BufferedImage.TYPE_INT_RGB
        );

        for (int y = 0; y < result.getHeight(); y++) {
            for (int x = 0; x < result.getWidth(); x++) {
                boolean color = qr.getModule(x / scale - border, y / scale - border);
                result.setRGB(x, y, color ? darkColor : lightColor);
            }
        }

        return result;
    }
}
