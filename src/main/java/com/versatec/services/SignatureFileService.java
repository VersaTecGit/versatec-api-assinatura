package com.versatec.services;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.WriterProperties;
import com.versatec.customs.CustomCertificate;
import com.versatec.customs.FileLocationEnum;
import com.versatec.customs.VisualSignatureConfig;
import com.versatec.utils.FileUtils;
import com.versatec.utils.PDFUtils;
import com.versatec.utils.SignatureImageGenerator;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.springframework.stereotype.Service;

import java.awt.geom.Rectangle2D;
import java.io.*;
import java.nio.file.Path;
import java.util.Calendar;
import java.util.TimeZone;

@Service
public class SignatureFileService {

    private final SignatureImageGenerator signatureImageGenerator;
    private final FileUtils fileUtils;

    public SignatureFileService(SignatureImageGenerator signatureImageGenerator, FileUtils fileUtils) {
        this.signatureImageGenerator = signatureImageGenerator;
        this.fileUtils = fileUtils;
    }

    /**
     * Cria um novo PDF a partir de um documento assinado, adicionando a imagem da
     * assinatura em todas as páginas e, em seguida, a assinatura digital.
     *
     * @param filePath          o nome do arquivo original
     * @param signedDocument    o documento assinado
     * @param customCertificate especialização do certificado, contendo informações
     *                          necessárias
     * @param url               a URL do documento
     *
     * @return o novo PDF assinado
     * @throws IOException se houver um erro ao ler ou escrever o arquivo
     */
    public Path createPDF(
            Path filePath,
            byte[] signedDocument,
            CustomCertificate customCertificate,
            VisualSignatureConfig visualSignatureConfig,
            String url)
            throws Exception {
        var originalFile = filePath.toFile();
        var signedFileName = this.addSignatureName(originalFile.getName());
        var downloadPath = fileUtils.getFilePath(signedFileName, FileLocationEnum.DOWNLOAD);

        PDDocument documentToProcess = (visualSignatureConfig.allPages() != null && visualSignatureConfig.allPages())
                ? this.createStampedDocument(originalFile, customCertificate, visualSignatureConfig, url)
                : PDDocument.load(originalFile);

        byte[] processedDocumentBytes;
        try (PDDocument doc = documentToProcess) {
            var outputStream = new ByteArrayOutputStream();
            doc.save(outputStream);
            processedDocumentBytes = compressPDF(outputStream.toByteArray());
        }

        try (PDDocument finalDocument = PDDocument.load(new ByteArrayInputStream(processedDocumentBytes));
                FileOutputStream output = new FileOutputStream(downloadPath.toString())) {

            var signature = this.getPDSignature();
            var signatureOptions = this.getSignatureOptions(signedDocument.length);

            if (visualSignatureConfig.allPages() == null || !visualSignatureConfig.allPages()) {
                this.setVisualSignature(signature, signatureOptions, finalDocument, customCertificate, visualSignatureConfig, url);
            } else {
                int pageIndexForDigitalSignatureField = this.getPageIndex(visualSignatureConfig, finalDocument.getNumberOfPages());
                signatureOptions.setPage(pageIndexForDigitalSignatureField);
            }

            finalDocument.addSignature(signature, signatureOptions);
            var externalSigning = finalDocument.saveIncrementalForExternalSigning(output);
            externalSigning.setSignature(signedDocument);

            finalDocument.saveIncremental(output);
        }

        return downloadPath;
    }

    private byte[] compressPDF(byte[] pdfBytes) throws IOException {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(pdfBytes);
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

            PdfReader reader = new PdfReader(inputStream);
            PdfWriter writer = new PdfWriter(outputStream, new WriterProperties().setFullCompressionMode(true));

            // Ao reescrever o documento com um novo PdfWriter, o iText já
            // otimiza o conteúdo, incluindo a compressão dos streams.
            try (PdfDocument pdfDocument = new PdfDocument(reader, writer)) {
            }

            return outputStream.toByteArray();
        }
    }

    /**
     * Adiciona a imagem da assinatura visual em todas as páginas e retorna o
     * PDDocument modificado.
     *
     * @param originalFile          o arquivo PDF original
     * @param customCertificate     especialização do certificado
     * @param visualSignatureConfig as configurações da assinatura visual
     * @param url                   a URL do documento (para QR Code)
     * @return um PDDocument com a imagem da assinatura adicionada em todas as
     *         páginas.
     * @throws Exception se houver um erro
     */
    private PDDocument createStampedDocument(
            File originalFile,
            CustomCertificate customCertificate,
            VisualSignatureConfig visualSignatureConfig,
            String url) throws Exception {
        PDDocument stampedDocument = PDDocument.load(originalFile);

        var signatureContent = this.generateSignatureContent(customCertificate, this.getPDSignature(), url);
        var widthSignature = this.getSignatureWidth(url);
        var signatureHeight = (this.signatureImageGenerator.HEIGHT / 10);
        PDImageXObject signatureImage = PDImageXObject.createFromByteArray(stampedDocument, signatureContent,
                "signature_image.png");

        int totalPages = stampedDocument.getNumberOfPages();

        int pageIndexToStamp = -1;

        if (visualSignatureConfig.allPages() == null || !visualSignatureConfig.allPages()) {
            pageIndexToStamp = this.getPageIndex(visualSignatureConfig, totalPages);
        }

        for (int i = 0; i < totalPages; i++) {

            if (visualSignatureConfig.allPages() != null && visualSignatureConfig.allPages() || i == pageIndexToStamp) {
                PDPage page = stampedDocument.getPage(i);

                var humanRectangle = this.getSignatureHumanRectangle(visualSignatureConfig, page, widthSignature,
                        signatureHeight);

                try (PDPageContentStream contentStream = new PDPageContentStream(stampedDocument, page,
                        PDPageContentStream.AppendMode.APPEND, true, true)) {
                    float x = (float) humanRectangle.getX();
                    float y = (float) humanRectangle.getY();
                    float width = (float) humanRectangle.getWidth();
                    float height = (float) humanRectangle.getHeight();

                    contentStream.drawImage(signatureImage, x, y, width, height);
                }
            }
        }
        return stampedDocument;
    }

    /**
     * Retorna um objeto PDSignature com as informações básicas de uma assinatura.
     *
     * @return um objeto PDSignature pronto para ser adicionado ao documento
     */
    private PDSignature getPDSignature() {
        var signature = new PDSignature();
        signature.setSignDate(Calendar.getInstance(TimeZone.getTimeZone("America/Sao_Paulo")));
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);

        return signature;
    }

    /**
     * Retorna um objeto SignatureOptions com as opções de assinatura.
     *
     * @param signatureSize o tamanho da assinatura em bytes
     *
     * @return um objeto SignatureOptions pronto para ser adicionado ao documento
     */
    private SignatureOptions getSignatureOptions(int signatureSize) {
        var signatureOptions = new SignatureOptions();
        signatureOptions.setPreferredSignatureSize(signatureSize);

        return signatureOptions;
    }

    /**
     * Adiciona a configuração de assinatura visual na {@link SignatureOptions}.
     *
     * @param signature         a assinatura a ser adicionada ao documento
     * @param signatureOptions  as opções de assinatura a serem configuradas
     * @param originalDocument  o documento original
     * @param customCertificate especialização do certificado, contendo informações
     *                          necessárias
     * @param url               a URL do documento
     *
     * @throws IOException se houver um erro ao ler ou escrever o arquivo
     */
    private void setVisualSignature(
            PDSignature signature,
            SignatureOptions signatureOptions,
            PDDocument originalDocument,
            CustomCertificate customCertificate,
            VisualSignatureConfig visualSignatureConfig,
            String url) throws Exception {
        // Obtém a página do documento a ser assinada
        var pages = originalDocument.getDocumentCatalog().getPages();
        int pageIndex = this.getPageIndex(visualSignatureConfig, pages.getCount());
        var signaturePage = pages.get(pageIndex);

        // Gera a imagem da assinatura
        var signatureContent = this.generateSignatureContent(customCertificate, signature, url);
        var widthSignature = this.getSignatureWidth(url);

        // Configura a posição e tamanho da assinatura
        var humanRectangle = this.getSignatureHumanRectangle(
                visualSignatureConfig,
                signaturePage,
                widthSignature,
                (this.signatureImageGenerator.HEIGHT / 10));

        var inputStream = this.includeVisualSignature(
                signaturePage,
                humanRectangle,
                signatureContent);

        // Configura a página a ser assinada
        signatureOptions.setPage(pageIndex);
        signatureOptions.setVisualSignature(inputStream);
    }

    /**
     * Retorna a imagem correta de assinatura
     *
     * @param signature         a assinatura a ser adicionada ao documento
     * @param customCertificate especialização do certificado, contendo informações
     *                          necessárias
     * @param url               a URL do documento
     *
     * @throws IOException se houver um erro ao ler ou escrever o arquivo
     */
    private byte[] generateSignatureContent(CustomCertificate customCertificate, PDSignature signature, String url)
            throws Exception {
        var name = customCertificate.getCertificateName();
        var identifier = customCertificate.getIdentifier();
        var date = signature.getSignDate().getTime();

        if (url != null && !url.trim().isEmpty()) {
            return this.signatureImageGenerator.getDefaultSignature(name, identifier, date, url, true);
        }

        return this.signatureImageGenerator.getDefaultSignature(name, identifier, date, null, false);
    }

    /**
     * Retorna a largura correta da imagem
     *
     * @param url a URL do documento
     */
    private int getSignatureWidth(String url) {
        return (url != null && !url.trim().isEmpty())
                ? this.signatureImageGenerator.WITH_QR_WIDTH / 10
                : this.signatureImageGenerator.WITHOUT_QR_WIDTH / 10;
    }

    /**
     * Retorna o índice da página onde a assinatura visual será adicionada.
     * <p>
     * O índice é baseado em zero, ou seja, a primeira página possui índice 0.
     * Para automaticamente selecionar a ultíma página pode ser passado o
     * valor −1 na Configuração de assinatura
     * Se o índice for inválido ou for maior que o número de páginas, a última
     * página será usada.
     *
     * @param pageCount o número total de páginas no documento
     *
     * @return o índice da página onde a assinatura visual será adicionada
     */
    private int getPageIndex(VisualSignatureConfig visualSignatureConfig, int pageCount) {
        if (visualSignatureConfig.pageIndex() == null ||
                visualSignatureConfig.pageIndex() == -1 ||
                visualSignatureConfig.pageIndex() >= pageCount) {
            return pageCount - 1;
        }

        return visualSignatureConfig.pageIndex();
    }

    /**
     * Retorna um retângulo que representa a área onde ficará a assinatura
     * <p>
     * Se a Configuração de assinatura for nula, o retângulo será localizado no
     * centro da página, a 2cm do fim da página
     *
     * @param visualSignatureConfig as configurações da assinatura
     * @param page                  a página a ser assinada
     * @param signatureWidth        a largura da assinatura
     * @param signatureHeight       a altura da assinatura
     * @return um retângulo que representa a área onde ficará a assinatura humana
     */
    private Rectangle2D getSignatureHumanRectangle(
            VisualSignatureConfig visualSignatureConfig,
            PDPage page,
            int signatureWidth,
            int signatureHeight) {
        // Troca a largura caso a página esteja deitada
        var pageBox = page.getMediaBox();
        var pageWidth = pageBox.getWidth();
        if (page.getRotation() == 90 || page.getRotation() == 270) {
            pageWidth = pageBox.getHeight();
        }

        // Retorna os valores da configuração customizada
        if (visualSignatureConfig.x() != null &&
                visualSignatureConfig.y() != null) {
            return new Rectangle2D.Float(
                    visualSignatureConfig.x(),
                    visualSignatureConfig.y(),
                    signatureWidth,
                    signatureHeight);
        }

        // Retorna a posição padrão centralizada, e com margem ABNT
        return new Rectangle2D.Float(
                (pageWidth - signatureWidth) / 2,
                (float) (((16) * 72) / 25.4), // Margem de 16mm convertido para points (No mundo real 2cm)
                signatureWidth,
                signatureHeight);
    }

    /**
     * Adiciona "_assinado" ao nome do arquivo antes da extensão.
     * Exemplo: "documento.pdf" vira "documento_assinado.pdf"
     *
     * @param fileName o nome do arquivo a ser assinado
     *
     * @return o nome do arquivo com "_assinado" acrescentado
     */
    static String addSignatureName(String fileName) {
        var dotIndex = fileName.lastIndexOf('.');
        if (dotIndex != -1) {
            var name = fileName.substring(0, dotIndex);
            var extension = fileName.substring(dotIndex);

            return name + "_assinado" + extension;
        }
        return fileName;
    }

    /**
     * Cria um retângulo que representa a área onde a assinatura será desenhada.
     * A assinatura será desenhada na página com as mesmas coordenadas (x, y)
     * independentemente da rotação da página.
     * As coordenadas começam da parte inferior esquerda da página.
     *
     * @param page           a página a ser assinada
     * @param humanRectangle o retângulo em formato amigável que representa a área
     *                       onde a assinatura deve ser desenhada
     *
     * @return o retângulo que representa a área onde a assinatura será desenhada
     */
    private PDRectangle createSignatureRectangle(PDPage page, Rectangle2D humanRectangle) {
        var x = (float) humanRectangle.getX();
        var y = (float) humanRectangle.getY();
        var width = (float) humanRectangle.getWidth();
        var height = (float) humanRectangle.getHeight();
        var cropBox = page.getCropBox();
        var rectangle = new PDRectangle();

        switch (page.getRotation()) {
            case 90:
                rectangle.setLowerLeftX(cropBox.getWidth() - y - height);
                rectangle.setUpperRightX(cropBox.getWidth() - y);
                rectangle.setLowerLeftY(x);
                rectangle.setUpperRightY(x + width);
                break;
            case 180:
                rectangle.setLowerLeftX(cropBox.getWidth() - x - width);
                rectangle.setUpperRightX(cropBox.getWidth() - x);
                rectangle.setLowerLeftY(cropBox.getHeight() - y - height);
                rectangle.setUpperRightY(cropBox.getHeight() - y);
                break;
            case 270:
                rectangle.setLowerLeftX(y);
                rectangle.setUpperRightX(y + height);
                rectangle.setLowerLeftY(cropBox.getHeight() - x - width);
                rectangle.setUpperRightY(cropBox.getHeight() - x);
                break;
            case 0:
            default:
                rectangle.setLowerLeftX(x);
                rectangle.setUpperRightX(x + width);
                rectangle.setLowerLeftY(y);
                rectangle.setUpperRightY(y + height);
                break;
        }

        return rectangle;
    }

    /**
     * Incluir as configurações do pdf, a forma que a assinatura visual deve ser
     * posicionada
     *
     * @param originPage       a página de origem
     * @param humanRectangle   o posicionamento
     * @param signatureContent o conteúdo da assinatura
     *
     * @return um fluxo de entrada com o modelo de assinatura visual
     * @throws IOException se ocorrer um erro de I/O
     */
    private InputStream includeVisualSignature(
            PDPage originPage,
            Rectangle2D humanRectangle,
            byte[] signatureContent) throws IOException {
        try (PDDocument doc = new PDDocument()) {
            var rectanglePosition = this.createSignatureRectangle(originPage, humanRectangle);

            var newPage = new PDPage(originPage.getMediaBox());
            doc.addPage(newPage);

            var widget = PDFUtils.setAcroForm(doc);
            widget.setRectangle(rectanglePosition);

            var boundingBox = new PDRectangle(rectanglePosition.getWidth(), rectanglePosition.getHeight());
            var pageRotation = originPage.getRotation();
            var initialScale = PDFUtils.getInitialScaleRotation(boundingBox, pageRotation);
            var form = PDFUtils.setFormXObject(doc, pageRotation);
            form.setBBox(boundingBox);

            var appearanceStream = PDFUtils.createAppearanceDictionary(form, widget);

            try (var contentStream = new PDPageContentStream(doc, appearanceStream)) {
                if (initialScale != null) {
                    contentStream.transform(initialScale);
                }

                contentStream.saveGraphicsState();

                float imageWidth = boundingBox.getWidth();
                float imageHeight = boundingBox.getHeight();
                if (pageRotation == 90 || pageRotation == 270) {
                    imageWidth = boundingBox.getHeight();
                    imageHeight = boundingBox.getWidth();
                }

                var imageObject = PDImageXObject.createFromByteArray(doc, signatureContent, "signature.jpg");
                contentStream.drawImage(imageObject, 0, 0, imageWidth, imageHeight);
                contentStream.restoreGraphicsState();
            }

            var byteArrayOutputStream = new ByteArrayOutputStream();
            doc.save(byteArrayOutputStream);
            return new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        }
    }
}