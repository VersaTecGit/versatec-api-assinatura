package com.versatec.services;

import com.versatec.customs.CustomCertificate;
import com.versatec.customs.FileLocationEnum;
import com.versatec.customs.WrongCertificatePasswordException;
import com.versatec.utils.SignatureImageGenerator;
import com.versatec.customs.VisualSignatureConfig;
import com.versatec.utils.FileUtils;
import com.versatec.utils.PDFUtils;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESChecker;
import org.springframework.stereotype.Service;

import java.awt.geom.Rectangle2D;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
public class SignatureService {

    public final FileUtils fileUtils;
    public final SignatureImageGenerator signatureImageGenerator;

    public SignatureService(FileUtils fileUtils, SignatureImageGenerator signatureImageGenerator) {
        this.fileUtils = fileUtils;
        this.signatureImageGenerator = signatureImageGenerator;
    }

    /**
     * Assina um documento a partir de um arquivo e de um par de chaves.
     *
     * @param filePath          o nome do arquivo a ser assinado
     * @param customCertificate certificado contendo informações necessárias
     *
     * @return o documento assinado
     * @throws IOException                          se houver um erro ao ler o arquivo
     * @throws UnrecoverableKeyException            se a chave privada não puder ser recuperada
     * @throws KeyStoreException                    se houver um erro com o KeyStore
     * @throws NoSuchAlgorithmException             se o algoritmo de hash não é suportado
     * @throws WrongCertificatePasswordException    se a senha do certificado estiver incorreta
     */
    public byte[] signDocument(Path filePath, CustomCertificate customCertificate)
            throws IOException,
            UnrecoverableKeyException,
            KeyStoreException,
            NoSuchAlgorithmException,
            WrongCertificatePasswordException
    {
        var signer = this.getPKCS7Signer(customCertificate);
        byte[] content = Files.readAllBytes(filePath);
        return signer.doAttachedSign(content);
    }

    /**
     * Retorna um objeto PKCS7Signer a partir de um certificado.
     *
     * @param customCertificate especialização do certificado, contendo informações necessárias
     *
     * @return um objeto PKCS7Signer pronto para assinar um documento
     * @throws KeyStoreException         se o tipo de KeyStore não é suportado
     * @throws UnrecoverableKeyException se a chave privada não puder ser recuperada
     * @throws NoSuchAlgorithmException  se o algoritmo de hash não é suportado
     */
    private PKCS7Signer getPKCS7Signer(CustomCertificate customCertificate)
            throws KeyStoreException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException
    {
        var signer = PKCS7Factory.getInstance().factoryDefault();
        signer.setCertificates(customCertificate.certificateChain);
        signer.setPrivateKey((PrivateKey) customCertificate.keyStore.getKey(customCertificate.alias, customCertificate.password.toCharArray()));

        return signer;
    }

    /**
     * Cria um novo PDF a partir de um documento assinado e adiciona a assinatura
     * visual.
     *
     * @param filePath          o nome do arquivo original
     * @param signedDocument    o documento assinado
     * @param customCertificate especialização do certificado, contendo informações necessárias
     * @param url               a URL do documento
     *
     * @return o novo PDF assinado com a assinatura visual
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
        var originalDocument = PDDocument.load(originalFile);

        var signedFileName = this.addSignatureName(originalFile.getName());
        var downloadPath = fileUtils.getFilePath(signedFileName, FileLocationEnum.DOWNLOAD);
        var output = new FileOutputStream(downloadPath.toString());

        var signature = this.getPDSignature();

        var signatureOptions = this.getSignatureOptions(signedDocument.length);

        this.setVisualSignature(signature, signatureOptions, originalDocument, customCertificate, visualSignatureConfig, url);

        originalDocument.addSignature(signature, signatureOptions);

        var externalSigning = originalDocument.saveIncrementalForExternalSigning(output);
        externalSigning.setSignature(signedDocument);

        originalDocument.saveIncremental(output);
        originalDocument.close();
        IOUtils.closeQuietly(signatureOptions);

        return downloadPath;
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
     * @param customCertificate especialização do certificado, contendo informações necessárias
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
            String url
    ) throws Exception {
        // Obtém a página do documento a ser assinada
        var pages = originalDocument.getDocumentCatalog().getPages();
        int pageIndex = this.getPageIndex(visualSignatureConfig, pages.getCount());
        var signaturePage = pages.get(pageIndex);

        //Gera a imagem da assinatura
        var signatureContent = generateSignatureContent(customCertificate, signature, url);
        var widthSignature = getSignatureWidth(url);

        //Configura a posição e tamanho da assinatura
        var humanRectangle = getSignatureHumanRectangle(
                visualSignatureConfig,
                signaturePage,
                widthSignature,
                (this.signatureImageGenerator.HEIGHT/10)
        );

        var inputStream = includeVisualSignature(
                signaturePage,
                humanRectangle,
                signatureContent
        );

        // Configura a página a ser assinada
        signatureOptions.setPage(pageIndex);
        signatureOptions.setVisualSignature(inputStream);
    }

    /**
     * Retorna a imagem correta de assinatura
     *
     * @param signature         a assinatura a ser adicionada ao documento
     * @param customCertificate especialização do certificado, contendo informações necessárias
     * @param url               a URL do documento
     *
     * @throws IOException se houver um erro ao ler ou escrever o arquivo
     */
    private byte[] generateSignatureContent(CustomCertificate customCertificate, PDSignature signature, String url) throws Exception {
        var name = customCertificate.getCertificateName();
        var identifier = customCertificate.getIdentifier();
        var date = signature.getSignDate().getTime();
        if (url != null && !url.trim().isEmpty()) {
            return this.signatureImageGenerator.getDefaultSignature(name, identifier, date, url, true);
        } else {
            return this.signatureImageGenerator.getDefaultSignature(name, identifier, date, null, false);
        }
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
     * Se o índice for inválido ou for maior que o número de páginas, a última página será usada.
     *
     * @param pageCount o número total de páginas no documento
     *
     * @return o índice da página onde a assinatura visual será adicionada
     */
    private int getPageIndex(VisualSignatureConfig visualSignatureConfig, int pageCount) {
        if (
            visualSignatureConfig == null ||
            visualSignatureConfig.pageIndex() == -1 ||
            visualSignatureConfig.pageIndex() >= pageCount
        ) {
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
            int signatureHeight
    ) {
        //Troca a largura caso a página esteja deitada
        var pageBox = page.getMediaBox();
        var pageWidth = pageBox.getWidth();
        if(page.getRotation() == 90 || page.getRotation() == 270) {
            pageWidth = pageBox.getHeight();
        }

        //Retorna os valores da configuração customizada
        if (visualSignatureConfig != null) {
            return new Rectangle2D.Float(
                visualSignatureConfig.x(),
                visualSignatureConfig.y(),
                signatureWidth,
                signatureHeight
            );
        }

        //Retorna a posição padrão centralizada, e com margem ABNT
        return new Rectangle2D.Float(
            (pageWidth - signatureWidth) / 2,
            (float) (((16) * 72) / 25.4), //Margem de 16mm convertido para points (No mundo real 2cm)
            signatureWidth,
            signatureHeight
        );
    }

    /**
     * Adiciona "_assinado" ao nome do arquivo antes da extensão.
     * Exemplo: "documento.pdf" vira "documento_assinado.pdf"
     *
     * @param fileName o nome do arquivo a ser assinado
     *
     * @return o nome do arquivo com "_assinado" acrescentado
     */
    private String addSignatureName(String fileName) {
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
     * A assinatura será desenhada na página com as mesmas coordenadas (x, y) independentemente da rotação da página.
     * As coordenadas começam da parte inferior esquerda da página.
     *
     * @param page           a página a ser assinada
     * @param humanRectangle o retângulo em formato amigável que representa a área onde a assinatura deve ser desenhada
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
     * Incluir as configurações do pdf, a forma que a assinatura visual deve ser posicionada
     *
     * @param oldPage           a página de origem
     * @param humanRectangle    o posicionamento
     * @param signatureContent  o conteúdo da assinatura
     *
     * @return um fluxo de entrada com o modelo de assinatura visual
     * @throws IOException se ocorrer um erro de I/O
     */
    private InputStream includeVisualSignature(
            PDPage oldPage,
            Rectangle2D humanRectangle,
            byte[] signatureContent
    ) throws IOException {
        try (PDDocument doc = new PDDocument()) {
            var rectanglePosition = createSignatureRectangle(oldPage, humanRectangle);

            var newPage = new PDPage(oldPage.getMediaBox());
            doc.addPage(newPage);

            var widget = PDFUtils.setAcroForm(doc);
            widget.setRectangle(rectanglePosition);

            var boundingBox = new PDRectangle(rectanglePosition.getWidth(), rectanglePosition.getHeight());
            var pageRotation = oldPage.getRotation();
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

    /**
     * Valida todas as assinaturas digitais em um documento PDF.
     *
     * @param filePath o caminho para o arquivo PDF a ser validado
     *
     * @return uma lista de informações sobre as assinaturas encontradas e o resultado da validação
     * @throws IOException          se ocorrer um erro de I/O
     * @throws ParseException       se ocorrer um erro ao analisar a data da assinatura
     * @throws CMSException         se ocorrer um erro relacionado ao CMS (Cryptographic Message Syntax)
     * @throws CertificateException se ocorrer um erro ao processar os certificados
     */
    public List<SignatureInformations> validateAllSignatures(Path filePath)
            throws IOException,
            ParseException,
            CMSException,
            CertificateException
    {
        var results = new ArrayList<SignatureInformations>();
        var file = filePath.toFile();

        try (PDDocument document = PDDocument.load(file)) {
            for (var signature : document.getSignatureDictionaries()) {
                var cosDictionary = signature.getCOSObject();
                var documentSignature = getDocumentSignature(cosDictionary);

                var signingTime = extractDateOfDictM(cosDictionary.getDictionaryObject(COSName.M));
                var checker = new CAdESChecker();

                try {
                    processSignature(documentSignature, checker, signingTime, results);
                } catch (Exception e) {
                    processInvalidSignature(documentSignature, e, signingTime, results);
                }

                checkIncrementalModification(signature, filePath);
            }
        }

        return results;
    }

    /**
     * Extrai e analisa a data a partir do objeto COSBase que representa a data da assinatura.
     *
     * @param cosNameM o objeto COSBase que contém a data da assinatura no formato COSString
     *
     * @return a data extraída e analisada como um objeto {@link Date}
     * @throws ParseException se ocorrer um erro ao analisar a data do formato string para o formato {@link Date}
     */
    private Date extractDateOfDictM(COSBase cosNameM) throws ParseException {
        var dateString = cosNameM.toString();
        dateString = dateString.replaceAll("^COSString\\{D:|\\}$", "");
        var gmt = "-" + dateString.split("-")[1].split("'")[0] + "00";
        dateString = dateString.replaceFirst("-\\d{2}'\\d{2}'", gmt);
        var formatter = new SimpleDateFormat("yyyyMMddHHmmssZ");
        return formatter.parse(dateString);
    }

    /**
     * Obtém o conteúdo da assinatura a partir do dicionário de assinatura.
     *
     * @param cosDictionary o dicionário da assinatura
     *
     * @return o conteúdo da assinatura como um array de bytes
     */
    private byte[] getDocumentSignature(COSDictionary cosDictionary) {
        var contents = (COSString) cosDictionary.getDictionaryObject(COSName.CONTENTS);
        return contents.getBytes();
    }

    /**
     * Processa uma assinatura e adiciona suas informações à lista de resultados.
     *
     * @param documentSignature o conteúdo da assinatura
     * @param checker           o objeto para validação da assinatura
     * @param signingTime       a data da assinatura
     * @param results           a lista onde as informações da assinatura serão adicionadas
     */
    private void processSignature(
            byte[] documentSignature,
            CAdESChecker checker,
            Date signingTime,
            List<SignatureInformations> results
    ) {
        var result = checker.checkAttachedSignature(documentSignature);
        if (result != null && !result.isEmpty()) {
            checker.getSignaturesInfo().get(0).setSignDate(signingTime);
            results.addAll(checker.getSignaturesInfo());
        } else {
            System.err.println("Signature validation failed: no result.");
        }
    }

    /**
     * Processa uma assinatura inválida e registra as informações do erro.
     *
     * @param documentSignature o conteúdo da assinatura
     * @param e                 a exceção lançada durante a validação
     * @param signingTime       a data da assinatura
     * @param results           a lista onde as informações da assinatura inválida serão adicionadas
     *
     * @throws CertificateException se ocorrer um erro ao processar os certificados
     * @throws IOException          se ocorrer um erro de I/O ao gerar certificados
     */
    private void processInvalidSignature(
            byte[] documentSignature,
            Exception e,
            Date signingTime,
            List<SignatureInformations> results
    )
            throws CertificateException,
            IOException,
            CMSException
    {
        var cmsSignedData = new CMSSignedData(documentSignature);
        var signerInfo = cmsSignedData.getSignerInfos().getSigners().iterator().next();
        Collection<X509CertificateHolder> certificateChain = cmsSignedData.getCertificates().getMatches(signerInfo.getSID());

        var certificates = extractCertificates(certificateChain);

        var result = new SignatureInformations();
        var basicCertificate = new BasicCertificate(certificates.get(0));
        result.setIcpBrasilcertificate(basicCertificate);
        result.setValidatorErrors(new LinkedList<>(List.of(e.getMessage())));
        result.setInvalidSignature(true);
        result.setSignDate(signingTime);
        results.add(result);
    }

    /**
     * Extrai certificados da cadeia de certificados obtida da assinatura.
     *
     * @param certificateChain a cadeia de certificados
     *
     * @return uma lista de certificados X509 extraídos
     * @throws CertificateException se ocorrer um erro ao processar os certificados
     * @throws IOException se ocorrer um erro de I/O ao gerar certificados
     */
    private List<X509Certificate> extractCertificates(Collection<X509CertificateHolder> certificateChain)
            throws CertificateException,
            IOException
    {
        var certFactory = CertificateFactory.getInstance("X.509");
        var certificates = new ArrayList<X509Certificate>();
        for (X509CertificateHolder certHolder : certificateChain) {
            var cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
            certificates.add(cert);
        }
        return certificates;
    }

    /**
     * Verifica se houve modificação incremental no arquivo PDF.
     *
     * @param signature a assinatura do documento
     * @param filePath o caminho para o arquivo PDF
     */
    private void checkIncrementalModification(PDSignature signature, Path filePath) {
        var byteRange = signature.getByteRange();
        var rangeMax = byteRange[byteRange.length - 2] + byteRange[byteRange.length - 1];
        var fileLen = (int) filePath.toFile().length();
        if (fileLen > rangeMax) {
            System.err.println("Error! Incremental modification detected.");
        }
    }
}