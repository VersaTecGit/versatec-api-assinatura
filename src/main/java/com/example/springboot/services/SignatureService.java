package com.example.springboot.services;

import com.example.springboot.AppConfig;
import com.example.springboot.enums.FileLocationEnum;
import com.example.springboot.factories.SignatureImageFactory;
import com.example.springboot.records.VisualSignatureConfig;
import com.example.springboot.utils.FileUtils;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import io.nayuki.qrcodegen.QrCode;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.demoiselle.signer.policy.impl.pades.pkcs7.impl.PAdESChecker;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
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

import static com.example.springboot.utils.FormatterUtils.formatCpfOrCnpj;
import static com.example.springboot.utils.QrCodeUtils.generateQrcode;

@Service
public class SignatureService {

    @Autowired
    FileUtils fileUtils;

    @Autowired
    AppConfig appConfig;

    @Autowired
    SignatureImageFactory signatureImageFactory;

    public VisualSignatureConfig visualSignatureConfig;

    /**
     * Assina um documento a partir de um arquivo e de um par de chaves.
     *
     * @param filePath o nome do arquivo a ser assinado
     * @param ks       o KeyStore contendo as chaves
     * @param password a senha do KeyStore
     * @return o documento assinado
     * @throws IOException               se houver um erro ao ler o arquivo
     * @throws UnrecoverableKeyException se a chave privada não puder ser recuperada
     * @throws KeyStoreException         se houver um erro com o KeyStore
     * @throws NoSuchAlgorithmException  se o algoritmo de hash não é suportado
     */
    public byte[] signDocument(Path filePath, KeyStore ks, String password) throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        PKCS7Signer signer = getPKCS7Signer(ks, password);

        byte[] content = Files.readAllBytes(filePath);

        return signer.doAttachedSign(content);
    }

    /**
     * Retorna um objeto PKCS7Signer a partir de um KeyStore e uma senha.
     *
     * @param ks       o KeyStore contendo as chaves
     * @param password a senha do KeyStore
     * @return um objeto PKCS7Signer pronto para assinar um documento
     * @throws KeyStoreException         se o tipo de KeyStore não é suportado
     * @throws UnrecoverableKeyException se a chave privada não puder ser recuperada
     * @throws NoSuchAlgorithmException  se o algoritmo de hash não é suportado
     */
    private PKCS7Signer getPKCS7Signer(KeyStore ks, String password) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        String alias = ks.aliases().nextElement();

        PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
        signer.setCertificates(ks.getCertificateChain(alias));
        signer.setPrivateKey((PrivateKey) ks.getKey(alias, password.toCharArray()));
//        signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_3);
//        signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);

        return signer;
    }

    /**
     * Cria um novo PDF a partir de um documento assinado e adiciona a assinatura
     * visual.
     *
     * @param filePath       o nome do arquivo original
     * @param signedDocument o documento assinado
     * @param keyStore       o KeyStore contendo as chaves
     * @param url            a URL da assinatura visual
     * @return o novo PDF assinado com a assinatura visual
     * @throws IOException se houver um erro ao ler ou escrever o arquivo
     */
    public Path createPDF(Path filePath, byte[] signedDocument, KeyStore keyStore, String url) throws IOException, KeyStoreException {
        File fileIn = fileUtils.getFile(filePath);
        PDDocument originalDocument = PDDocument.load(fileIn);

        Path downloadPath = fileUtils.getFilePath(addSignatureName(fileIn.getName()), FileLocationEnum.DOWNLOAD);
        OutputStream output = new FileOutputStream(downloadPath.toString());

        PDSignature signature = this.getPDSignature();

        SignatureOptions signatureOptions = this.getSignatureOptions(signedDocument.length);

        this.setVisualSignature(signature, signatureOptions, originalDocument, keyStore, url);

        originalDocument.addSignature(signature, signatureOptions);

        ExternalSigningSupport externalSigning = originalDocument.saveIncrementalForExternalSigning(output);
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
        PDSignature signature = new PDSignature();
        signature.setSignDate(Calendar.getInstance(TimeZone.getTimeZone("America/Sao_Paulo")));
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
//        signature.setName(alias);
//        signature.setLocation("Caratinga, MG");
//        signature.setReason("Assinatura");

        return signature;
    }

    private SignatureOptions getSignatureOptions(int signatureSize) {
        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setPreferredSignatureSize(signatureSize);

        return signatureOptions;
    }

    /**
     * Adiciona a configuração de assinatura visual no {@link PDSignature}.
     *
     * @param signature        a assinatura a ser adicionada ao documento
     * @param signatureOptions as opções de assinatura
     * @param originalDocument o documento original
     * @param keyStore         o KeyStore contendo as chaves
     * @param url              a URL da assinatura visual
     * @throws IOException se houver um erro ao ler ou escrever o arquivo
     */
    private void setVisualSignature(PDSignature signature, SignatureOptions signatureOptions, PDDocument originalDocument, KeyStore keyStore, String url) throws IOException, KeyStoreException {
        // Obtém a última página do documento
        PDPageTree pages = originalDocument.getDocumentCatalog().getPages();
        PDPage lastPage = pages.get(pages.getCount() - 1);

        // Obtém o número da página onde a assinatura será adicionada
        int pageNum = this.getPageIndex(pages.getCount());
        signatureOptions.setPage(pageNum);
        Rectangle2D humanRectangle;
        Path signatureImageLocation;
        if (url != null && !url.trim().isEmpty()) {
            signatureImageLocation = this.fileUtils.getFilePath("assinatura_bg.jpg", FileLocationEnum.ASSET);
            humanRectangle = this.getSignatureHumanRectangle(lastPage.getMediaBox(), 190, 70);
        } else {
            signatureImageLocation = this.fileUtils.getFilePath("assinatura_bg_noQr.jpg", FileLocationEnum.ASSET);
            humanRectangle = this.getSignatureHumanRectangle(lastPage.getMediaBox(), 130, 70);
        }

        String alias = keyStore.aliases().nextElement();
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        BasicCertificate bc = new BasicCertificate(certificate);

        var signatureContent = this.signatureImageFactory.getDefaultSignature(bc.getName(), certificate.getSubjectX500Principal().getName().split(":")[1].split(",")[0], signature.getSignDate().getTime().toString());

        PDRectangle rect = createSignatureRectangle(originalDocument, humanRectangle);

        signatureOptions.setVisualSignature(createVisualSignatureTemplate(originalDocument, signature, pageNum, rect, signatureContent, keyStore, url));
    }

    /**
     * Retorna o índice da página onde a assinatura visual será adicionada.
     * <p>
     * O índice é baseado em zero, ou seja, a primeira página possui índice 0.
     * Para automaticamente selecionar a ultíma página pode ser passado o
     * valor -1 na Configuração de assinatura
     * Se o índice for inválido ou for maior que o número de páginas, a última página será usada.
     *
     * @param pageCount o número total de páginas no documento
     * @return o índice da página onde a assinatura visual será adicionada
     */
    private int getPageIndex(int pageCount) {
        if (this.visualSignatureConfig == null || this.visualSignatureConfig.pageIndex() == -1 || this.visualSignatureConfig.pageIndex() >= pageCount) {
            return pageCount - 1;
        }

        return this.visualSignatureConfig.pageIndex();
    }

    /**
     * Retorna um retângulo que representa a área onde ficará a assinatura
     * <p>
     * Se a Configuração de assinatura for nula, o retângulo será localizado no
     * centro da página, a 2cm do fim da página
     *
     * @param pageBox as dimensões da página
     * @return um retângulo que representa a área onde ficará a assinatura humana
     */
    private Rectangle2D getSignatureHumanRectangle(PDRectangle pageBox, int width, int height) {
        if (this.visualSignatureConfig != null) {
            return new Rectangle2D.Float(visualSignatureConfig.x(), visualSignatureConfig.y(), width, height);
        }

        return new Rectangle2D.Float((pageBox.getWidth() - (width)) / 2, (float) (((16) * 72) / 25.4), //Converte 16mm pra points
                width, height);
    }

    /**
     * Adiciona "_assinado" ao nome do arquivo antes da extensão.
     * Exemplo: "documento.pdf" vira "documento_assinado.pdf"
     *
     * @param fileName o nome do arquivo a ser assinado
     * @return o nome do arquivo com "_assinado" acrescentado
     */
    private String addSignatureName(String fileName) {
        int indicePonto = fileName.lastIndexOf('.');
        if (indicePonto != -1) {
            String name = fileName.substring(0, indicePonto);
            String extension = fileName.substring(indicePonto);

            return name + "_assinado" + extension;
        }
        return fileName;
    }

    /**
     * Cria um retângulo que representa a área onde a assinatura será desenhada.
     * A assinatura será desenhada na página com as mesmas coordenadas (x, y) independentemente da rotação da página.
     * As coordenadas começam da parte inferior esquerda da página.
     *
     * @param doc            o documento que contém a página a ser assinada
     * @param humanRectangle o retângulo que representa a área onde a assinatura humana deve ser desenhada
     * @return o retângulo que representa a área onde a assinatura será desenhada
     */
    private PDRectangle createSignatureRectangle(PDDocument doc, Rectangle2D humanRectangle) {
        float x = (float) humanRectangle.getX();
        float y = (float) humanRectangle.getY();
        float width = (float) humanRectangle.getWidth();
        float height = (float) humanRectangle.getHeight();
        PDPage page = doc.getPage(0);
        PDRectangle pageRect = page.getCropBox();
        PDRectangle rect = new PDRectangle();

        // Signature image should be at the same position regardless of page rotation.
        // Coordinates start from bottom left.
        switch (page.getRotation()) {
            case 90:
                rect.setLowerLeftX(pageRect.getWidth() - y - height);
                rect.setUpperRightX(pageRect.getWidth() - y);
                rect.setLowerLeftY(x);
                rect.setUpperRightY(x + width);
                break;
            case 180:
                rect.setLowerLeftX(pageRect.getWidth() - x - width);
                rect.setUpperRightX(pageRect.getWidth() - x);
                rect.setLowerLeftY(pageRect.getHeight() - y - height);
                rect.setUpperRightY(pageRect.getHeight() - y);
                break;
            case 270:
                rect.setLowerLeftX(y);
                rect.setUpperRightX(y + height);
                rect.setLowerLeftY(pageRect.getHeight() - x - width);
                rect.setUpperRightY(pageRect.getHeight() - x);
                break;
            case 0:
            default:
                rect.setLowerLeftX(x);
                rect.setUpperRightX(x + width);
                rect.setLowerLeftY(y);
                rect.setUpperRightY(y + height);
                break;
        }

        return rect;
    }

    /**
     * Cria um template de assinatura visual para os parâmetros dados.
     *
     * @param srcDoc           o documento de origem
     * @param signature        o objeto de assinatura
     * @param pageNum          o número da página
     * @param rect             o retângulo
     * @param signatureContent o conteúdo da assinatura
     * @param keyStore         o repositório de chaves
     * @param url              a URL
     * @return um fluxo de entrada com o template de assinatura visual
     * @throws IOException se ocorrer um erro de I/O
     */
    private InputStream createVisualSignatureTemplate(PDDocument srcDoc, PDSignature signature, int pageNum, PDRectangle rect, byte[] signatureContent, KeyStore keyStore, String url) throws IOException {
        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage(srcDoc.getPage(pageNum).getMediaBox());
            doc.addPage(page);
            PDAcroForm acroForm = new PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(acroForm);
            PDSignatureField signatureField = new PDSignatureField(acroForm);
            PDAnnotationWidget widget = signatureField.getWidgets().get(0);
            List<PDField> acroFormFields = acroForm.getFields();
            acroForm.setSignaturesExist(true);
            acroForm.setAppendOnly(true);
            acroForm.getCOSObject().setDirect(true);
            acroFormFields.add(signatureField);

            widget.setRectangle(rect);

            // from PDVisualSigBuilder.createHolderForm()
            PDStream stream = new PDStream(doc);
            PDFormXObject form = new PDFormXObject(stream);
            PDResources res = new PDResources();
            form.setResources(res);
            form.setFormType(1);
            PDRectangle bbox = new PDRectangle(rect.getWidth(), rect.getHeight());
            Matrix initialScale = null;
            int pageRotation = srcDoc.getPage(0).getRotation();
            switch (pageRotation) {
                case 90:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(1));
                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
                    break;
                case 180:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(2));
                    break;
                case 270:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(3));
                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
                    break;
                default:
                    break;
            }
            form.setBBox(bbox);

            // From PDVisualSigBuilder.createAppearanceDictionary()
            PDAppearanceDictionary appearance = new PDAppearanceDictionary();
            appearance.getCOSObject().setDirect(true);
            PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
            appearance.setNormalAppearance(appearanceStream);
            widget.setAppearance(appearance);

            try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream)) {
                if (initialScale != null) {
                    cs.transform(initialScale);
                }

                if (signatureContent != null) {
//                    byte[] image = Base64.getDecoder().decode(imageInBase64);
                    cs.saveGraphicsState();

                    float imageWidth = bbox.getWidth();
                    float imageHeight = bbox.getHeight();
                    if (pageRotation == 90 || pageRotation == 270) {
                        imageWidth = bbox.getHeight();
                        imageHeight = bbox.getWidth();
                    }

                    PDImageXObject img = PDImageXObject.createFromByteArray(doc, signatureContent, "signature.jpg");

                    cs.drawImage(img, 0, 0, imageWidth, imageHeight);

                    var infoFontSize = (float) (imageHeight * 0.06);
                    var fontSize = (float) (imageHeight * 0.085);
                    var spacing = (float) (imageHeight * 0.025);
                    var marginLeft = (float) ((imageHeight * 0.05));

                    if (url != null && !url.trim().isEmpty()) {
                        var qr = generateQrcode(appConfig.getUrl() + "/api/v1/qr-code&url=" + url);
                        PDImageXObject imgQr = PDImageXObject.createFromByteArray(doc, qr, "qrCode.jpg");
                        cs.drawImage(imgQr, (float) (imageHeight * 0.025), (float) (imageHeight * 0.125), (float) (imageHeight * 0.85), (float) (imageHeight * 0.85));
                        cs.restoreGraphicsState();

                        cs.setFont(PDType1Font.HELVETICA_BOLD, infoFontSize);
                        cs.beginText();
                        cs.newLineAtOffset((float) (imageHeight * 0.023), (float) (spacing * 1.5));
                        cs.showText("CÓDIGO PARA VERIFICAÇÃO");
                        cs.endText();
                        marginLeft = (float) ((imageHeight * 0.95));
                    }

                    String alias = keyStore.aliases().nextElement();
                    X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
                    BasicCertificate bc = new BasicCertificate(certificate);

                    var identifier = certificate.getSubjectX500Principal().getName().split(":")[1].split(",")[0];

                    cs.setFont(PDType1Font.HELVETICA, fontSize);
                    cs.beginText();
                    if (url != null && !url.trim().isEmpty()) {
                        cs.newLineAtOffset(marginLeft, (spacing * 5));
                    } else {
                        cs.newLineAtOffset(marginLeft, (spacing * 3));
                    }
                    var sdf = new SimpleDateFormat("dd/MM/yyyy   HH:mm:ss   'UTC'XXX");
                    var date = signature.getSignDate().getTime();
                    cs.showText(sdf.format(date));
                    cs.newLineAtOffset(0, (spacing * 10));
                    cs.showText(formatCpfOrCnpj(identifier));
                    cs.newLineAtOffset(0, (float) (spacing * 21.5));
                    cs.showText("Documento assinado digitalmente");
                    cs.endText();

                    cs.setFont(PDType1Font.HELVETICA_BOLD, fontSize);
                    cs.beginText();
                    var words = bc.getName().split(" ");
                    var lines = new ArrayList<String>();
                    lines.add("");

                    var indexLine = 0;
                    for (String word : words) {
                        if (lines.get(indexLine).length() + word.length() > 30) {
                            indexLine++;
                            lines.add("");
                        }
                        lines.set(indexLine, lines.get(indexLine) + " " + word);
                    }

                    cs.newLineAtOffset(marginLeft, (float) (spacing * (27 - (lines.size() * 1.5))));
                    for (int i = lines.size() - 1; i >= 0; i--) {
                        cs.showText(lines.get(i).trim());
                        cs.newLineAtOffset(0, fontSize);
                    }

                    cs.endText();
                    cs.restoreGraphicsState();
                }

            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            return new ByteArrayInputStream(baos.toByteArray());
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

    public void setVisualSignatureConfig(VisualSignatureConfig vsc) {

    }
}