package com.example.springboot.factories;


import com.example.springboot.enums.FileLocationEnum;
import com.example.springboot.utils.FileUtils;
import com.example.springboot.utils.FormatterUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

@Component
public class SignatureImageFactory {

    @Autowired
    FileUtils fileUtils;

    public byte[] getDefaultSignature(String name, String identifier, String date) throws IOException {
        var background = fileUtils.getFile("selo_escuro.jpeg", FileLocationEnum.ASSET);
        var image = ImageIO.read(background);
        var g2d = image.createGraphics();

        try {
            g2d.setFont(new Font("Helvetica", Font.BOLD, 6));
            g2d.drawString(name, 50, 50);
            g2d.drawString(FormatterUtils.formatCpfOrCnpj(identifier), 50, 50);
            g2d.drawString(date, 50, 50);
        } finally {
            g2d.dispose();
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "jpeg", baos);
        return baos.toByteArray();
    }
}
