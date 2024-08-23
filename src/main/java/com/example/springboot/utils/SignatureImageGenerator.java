package com.example.springboot.utils;


import com.example.springboot.config.AppProperties;
import com.example.springboot.customs.FileLocationEnum;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Date;

import static com.example.springboot.utils.FormatterUtils.formatCpfOrCnpj;
import static com.example.springboot.utils.FormatterUtils.formatDate;
import static com.example.springboot.utils.QrCodeUtils.generateQrcode;

@Component
public class SignatureImageGenerator {

    public final FileUtils fileUtils;
    public final AppProperties appConfig;

    public final int HEIGHT = 700;
    public final int QR_SIDE = 580;
    public final int WITH_QR_WIDTH = 1900;
    public final int WITHOUT_QR_WIDTH = 1300;
    public final int INFO_FONT_SIZE = (int) (HEIGHT * 0.059);
    public final int FONT_SIZE = (int) (HEIGHT * 0.07);
    public final float SPACING = (float) (HEIGHT * 0.025);
    public final String WITH_QR_BACKGROUND = "assinatura_bg.jpg";
    public final String WITHOUT_QR_BACKGROUND = "assinatura_bg_noQr.jpg";
    public final String DOC_DIGITAL_SIGNED_TEXT = "Documento assinado digitalmente";
    public final String VERIFICATION_CODE_TEXT = "CÓDIGO DE VERIFICAÇÃO";
    public final String FONT_TYPE = "Helvetica";

    public SignatureImageGenerator(FileUtils fileUtils, AppProperties appConfig) {
        this.fileUtils = fileUtils;
        this.appConfig = appConfig;
    }

    /**
     * Gera a assinatura padrão com o nome, CPF/CNPJ e data e inclui o qr code da url caso necessário
     *
     * @param name          nome da pessoa
     * @param identifier    CPF/CNPJ da pessoa
     * @param date          data da assinatura
     * @param url           url para a página de verificação
     * @param hasQrCode     se a imagem deve ter um qrcode
     *
     * @return imagem da assinatura em bytes
     * @throws Exception se houver um erro ao gerar a assinatura
     */
    public byte[] getDefaultSignature(String name, String identifier, Date date, String url, Boolean hasQrCode) throws Exception {
        //Configura a imagem e a margem para o texto central
        var imageName = WITHOUT_QR_BACKGROUND;
        var marginLeft = (float) (HEIGHT * 0.05);
        if(hasQrCode){
            imageName = WITH_QR_BACKGROUND;
            marginLeft = (float) (HEIGHT * 0.95);
        }

        //L  a imagem e cria o graphics2d para escrita
        var background = fileUtils.getFile(imageName, FileLocationEnum.ASSET);
        var image = ImageIO.read(background);
        var graphics2D = image.createGraphics();

        try {
            //Cor da fonte
            graphics2D.setColor(Color.BLACK);

            if(hasQrCode) {
                includeQrCode(graphics2D, url);
            }

            //Escreve texto, cpf e data
            graphics2D.setFont(new Font(FONT_TYPE, Font.PLAIN, FONT_SIZE));
            graphics2D.drawString(DOC_DIGITAL_SIGNED_TEXT, marginLeft, (float)(SPACING * 3.5));
            graphics2D.drawString(formatCpfOrCnpj(identifier), marginLeft, (SPACING * 27));
            graphics2D.drawString(formatDate(date), marginLeft, (float) (SPACING * 34.9));

            //Escreve as linhas do nome
            graphics2D.setFont(new Font(FONT_TYPE, Font.BOLD, FONT_SIZE));
            var lines = getLines(name, 33);
            var nextMarginTop = (SPACING*11);
            for (String line : lines) {
                graphics2D.drawString(line.trim(), marginLeft, nextMarginTop);
                nextMarginTop += FONT_SIZE;
            }
        } finally {
            graphics2D.dispose();
        }

        var byteArrayOutputStream = new ByteArrayOutputStream();
        ImageIO.write(image, "jpeg", byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    /**
     * Comandos necessários para inclusão do qr code na assinatura padrão
     *
     * @param graphics2D    graphics2d para escrita
     * @param url           url para a página de verificação
     *
     * @throws Exception se houver um erro ao incluir o qr code
     */
    private void includeQrCode(Graphics2D graphics2D, String url) throws Exception {
        var qr = generateQrcode(appConfig.getUrl() + "/api/v1/qr-code&url=" + url);
        graphics2D.drawImage(qr, (int) (SPACING * 1.5), (int) (SPACING * 1.5), QR_SIDE, QR_SIDE, null);
        graphics2D.setFont(new Font(FONT_TYPE, Font.BOLD, INFO_FONT_SIZE));
        graphics2D.drawString(VERIFICATION_CODE_TEXT, (float) (SPACING * 1.5), (float) (SPACING * 37.5));
    }

    /**
     * Divide um texto em linhas com base em um tamanho de linha desejado.
     *
     * @param text          texto a ser dividido
     * @param lineLength    tamanho da linha desejado
     *
     * @return lista de linhas do texto
     */
    private ArrayList<String> getLines(String text, int lineLength)
    {
        var words = text.split(" ");
        var lines = new ArrayList<String>();
        lines.add("");

        var indexLine = 0;
        for (String word : words) {
            if (lines.get(indexLine).length() + word.length() > lineLength) {
                indexLine++;
                lines.add("");
            }
            lines.set(indexLine, lines.get(indexLine) + " " + word);
        }

        return lines;
    }
}
