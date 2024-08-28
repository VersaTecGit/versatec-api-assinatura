package com.versatec.utils;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;

import java.awt.geom.AffineTransform;
import java.io.IOException;
import java.util.List;

public class PDFUtils {

    /**
     * Configura o acroForm no documento.
     * acroForm é um formulário interativo, utilizado para preencher informações diretamente no documento
     *
     * @param doc documento PDF
     *
     * @return o widget do campo de assinatura
     * @throws IOException se ocorrer um erro de I/O
     */
    public static PDAnnotationWidget setAcroForm(PDDocument doc) throws IOException
    {
        PDAcroForm acroForm = new PDAcroForm(doc);
        doc.getDocumentCatalog().setAcroForm(acroForm);

        PDSignatureField signatureField = new PDSignatureField(acroForm);
        List<PDField> acroFormFields = acroForm.getFields();
        acroFormFields.add(signatureField);

        acroForm.setSignaturesExist(true);
        acroForm.setAppendOnly(true);
        acroForm.getCOSObject().setDirect(true);

        return signatureField.getWidgets().get(0);
    }

    /**
     * Cria um formXObject para o documento.
     * Um formXObject é um objeto que pode ser adicionado a uma página de um documento PDF e pode
     * conter conteúdo gráfico, como imagens ou texto.
     *
     * @param doc           documento PDF
     * @param pageRotation  rotação da página
     *
     * @return o formXObject criado
     */
    public static PDFormXObject setFormXObject(PDDocument doc, int pageRotation)
    {
        PDStream stream = new PDStream(doc);
        PDFormXObject form = new PDFormXObject(stream);
        PDResources res = new PDResources();
        form.setResources(res);
        form.setFormType(1);

        switch (pageRotation) {
            case 90:
                form.setMatrix(AffineTransform.getQuadrantRotateInstance(1));
                break;
            case 180:
                form.setMatrix(AffineTransform.getQuadrantRotateInstance(2));
                break;
            case 270:
                form.setMatrix(AffineTransform.getQuadrantRotateInstance(3));
                break;
            default:
                break;
        }

        return form;
    }

    /**
     * Cria um dicionário de aparência para o widget.
     * A aparência de um widget é o aspecto visual do widget, como sua cor, forma, etc.
     * Este método cria um dicionário de aparência para o widget, adiciona um fluxo de entrada
     * como aparência normal e o seta como aparência do widget.
     *
     * @param form   o formXObject que contem o widget
     * @param widget o widget para o qual a aparência deve ser criada
     *
     * @return o fluxo de entrada criado como aparência normal
     */
    public static PDAppearanceStream createAppearanceDictionary(PDFormXObject form, PDAnnotationWidget widget)
    {
        PDAppearanceDictionary appearance = new PDAppearanceDictionary();
        appearance.getCOSObject().setDirect(true);
        PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
        appearance.setNormalAppearance(appearanceStream);
        widget.setAppearance(appearance);
        return appearanceStream;
    }

    /**
     * Retorna a matriz de transformação de escala e rotação para a página.
     * A escala é calculada com base na rotação da página e no tamanho do retângulo delimitador.
     * Se a rotação da página for 90 ou 270 graus, a escala é adaptada.
     *
     * @param boundingBox    o retângulo delimitador
     * @param pageRotation   rotação da página
     *
     * @return a matriz de transforma o de escala e rotação
     */
    public static Matrix getInitialScaleRotation(PDRectangle boundingBox, int pageRotation)
    {
        return switch (pageRotation) {
            case 90, 270 -> Matrix.getScaleInstance(
                boundingBox.getWidth() / boundingBox.getHeight(),
                boundingBox.getHeight() / boundingBox.getWidth());
            default -> null;
        };
    }
}
