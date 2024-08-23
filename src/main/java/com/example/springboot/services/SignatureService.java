package com.example.springboot.services;

import com.example.springboot.customs.CustomCertificate;
import com.example.springboot.customs.FileLocationEnum;
import com.example.springboot.customs.WrongCertificatePasswordException;
import com.example.springboot.utils.SignatureImageGenerator;
import com.example.springboot.customs.VisualSignatureConfig;
import com.example.springboot.utils.FileUtils;
import com.example.springboot.utils.PDFUtils;
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
import org.bouncycastle.cms.SignerInformation;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.policy.impl.pades.pkcs7.impl.PAdESChecker;
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
     * @param customCertificate especialização do certificado, contendo informações necessárias
     *
     * @return o documento assinado
     * @throws IOException               se houver um erro ao ler o arquivo
     * @throws UnrecoverableKeyException se a chave privada não puder ser recuperada
     * @throws KeyStoreException         se houver um erro com o KeyStore
     * @throws NoSuchAlgorithmException  se o algoritmo de hash não é suportado
     */
    public byte[] signDocument(Path filePath, CustomCertificate customCertificate)
            throws IOException,
            UnrecoverableKeyException,
            KeyStoreException,
            NoSuchAlgorithmException,
            WrongCertificatePasswordException
    {
        var signer = getPKCS7Signer(customCertificate);
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
    private PKCS7Signer getPKCS7Signer(CustomCertificate customCertificate) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
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
        var fileIn = fileUtils.getFile(filePath);
        var originalDocument = PDDocument.load(fileIn);

        var downloadPath = fileUtils.getFilePath(addSignatureName(fileIn.getName()), FileLocationEnum.DOWNLOAD);
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
        byte[] signatureContent;
        var name = customCertificate.getCertificateName();
        var identifier = customCertificate.getIdentifier();
        var date = signature.getSignDate().getTime();
        var widthSignature = 0;
        if (url != null && !url.trim().isEmpty()) {
            signatureContent = this.signatureImageGenerator.getDefaultSignature(name, identifier, date, url, true);
            widthSignature = this.signatureImageGenerator.WITH_QR_WIDTH/10;
        } else {
            signatureContent = this.signatureImageGenerator.getDefaultSignature(name, identifier, date, null, false);
            widthSignature = this.signatureImageGenerator.WITHOUT_QR_WIDTH/10;
        }

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
            (pageWidth - (signatureWidth)) / 2,
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
            var initialScale = PDFUtils.getInitialScaleRotation(oldPage, boundingBox);
            var pageRotation = oldPage.getRotation();
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

    public List<SignatureInformations> validateAllSignatures(Path filePath) throws IOException, ParseException, CMSException, CertificateException {
        List<SignatureInformations> results = new ArrayList<>();
        List<X509Certificate> chains = new ArrayList<X509Certificate>();
        PDDocument document;

        document = PDDocument.load(new File(filePath.toString()));
        List<SignatureInformations> result = null;

        int rangeMax = 0;
        int fileLen = 0;
        for (PDSignature sig : document.getSignatureDictionaries()) {
            COSDictionary sigDict = sig.getCOSObject();
            COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);

            Date signingTime = this.extractDateOfDictM(sigDict.getDictionaryObject(COSName.M));

            byte[] buf = null;

            try (FileInputStream fis = new FileInputStream(filePath.toString())) {
                buf = sig.getSignedContent(fis);
            }

            ConfigurationRepo configlcr = ConfigurationRepo.getInstance();
            configlcr.setOnline(false);

            PAdESChecker checker = new PAdESChecker();
            byte[] documentSignature = contents.getBytes();

//            File fileP7S = this.createFileP7S(filePath, documentSignature);

            try {
                result = checker.checkDetachedSignature(buf, documentSignature);
                checker.getSignaturesInfo().get(0).setSignDate(signingTime);
                int[] byteRange = sig.getByteRange();
                rangeMax = (byteRange[byteRange.length - 2] + byteRange[byteRange.length - 1]);
                fileLen = (int) new File(filePath.toString()).length();

                if (result == null || result.isEmpty()) {
                    System.err.println("Erro ao validar");
                }
                results.addAll(checker.getSignaturesInfo());
            } catch (SignerException e) {
                CMSSignedData signature = new CMSSignedData(documentSignature);

                SignerInformation signerInfo = signature.getSignerInfos().getSigners().iterator().next();
                Collection<X509CertificateHolder> certificateChain = signature.getCertificates().getMatches(signerInfo.getSID());

                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                List<X509Certificate> certificates = new ArrayList<>();
                for (X509CertificateHolder certHolder : certificateChain) {
                    X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
                    certificates.add(cert);
                }

                SignatureInformations resul = new SignatureInformations();
                BasicCertificate icpBrasilcertificate = new BasicCertificate(certificates.get(0));
                resul.setIcpBrasilcertificate(icpBrasilcertificate);
                String err = e.getMessage();
                LinkedList<String> erro = new LinkedList<String>();
                erro.add(err);
                resul.setValidatorErrors(erro);
                resul.setInvalidSignature(true);
                resul.setSignDate(signingTime);
                results.add(resul);
                chains.add(certificates.get(0));
            }
        }

        document.close();

        if (fileLen > rangeMax) {
            System.err.println("Erro! Foi identificado uma modificação incremental");
        }

        return results;
    }

    private Date extractDateOfDictM(COSBase cosNameM) throws ParseException {
        String dateString = cosNameM.toString();
        dateString = dateString.replaceAll("^COSString\\{D:|\\}$", "");
        String gmt = "-" + dateString.split("-")[1].split("'")[0] + "00";
        dateString = dateString.replaceFirst("-\\d{2}'\\d{2}'", gmt);
        SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmssZ");
        Date date = formatter.parse(dateString);
        return date;
    }
}