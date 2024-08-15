package com.example.springboot.services;

import com.example.springboot.AppConfig;
import com.example.springboot.FileStorageProperties;
import com.example.springboot.records.VisualSignatureConfig;
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
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

@Service
public class SignerService {

    @Autowired
    AppConfig appConfig;

    private final Path fileAssetLocation;
    private final Path fileUploadLocation;
    private final Path fileDownloadLocation;
    private VisualSignatureConfig visualSignatureConfig;

    public SignerService(FileStorageProperties fileStorageLocation) {
        this.fileAssetLocation = Paths.get(fileStorageLocation.getAssetDir()).toAbsolutePath().normalize();
        this.fileUploadLocation = Paths.get(fileStorageLocation.getUploadDir()).toAbsolutePath().normalize();
        this.fileDownloadLocation = Paths.get(fileStorageLocation.getDownloadDir()).toAbsolutePath().normalize();
    }
    
    /**
     * Define a configuração da assinatura visual.
     *
     * @param value a instância da configuração da assinatura visual
     */
    public void setVisualSignatureConfig(VisualSignatureConfig value)
    {
        this.visualSignatureConfig = value;
    }

    /**
     * Faz o upload de um arquivo e de um certificado.
     *
     * @param file o arquivo a ser assinado
     * @param fileHash o hash do arquivo
     * @param certificateFile o arquivo do certificado
     * @param certificateHash o hash do certificado
     * @throws IOException se houver um erro ao fazer o upload
     */
    public void uploadFile(MultipartFile file, String fileHash, MultipartFile certificateFile, String certificateHash) throws IOException {
        //TODO Add hash in name
        if (file != null) {
            String fileName = StringUtils.cleanPath(Objects.requireNonNull(fileHash));
            Path fileLocation = this.fileUploadLocation.resolve(fileName).normalize();
            file.transferTo(fileLocation);
        }

        if (certificateFile != null) {
            byte[] bytes = certificateFile.getBytes();
            String certificateFileName = StringUtils.cleanPath(Objects.requireNonNull(certificateHash));
            Path certificateFileLocation = this.fileUploadLocation.resolve(certificateFileName).normalize();
            FileOutputStream fos = new FileOutputStream(certificateFileLocation.toString());
            fos.write(bytes);
            fos.close();
        }
    }

    /**
     * Remove todos os arquivos referentes ao hash do arquivo e ao hash do
     * certificado.
     *
     * @param fileHash o hash do arquivo
     * @param certificateHash o hash do certificado
     * @throws IOException se houver um erro ao deletar os arquivos
     */
    public void removeAllFiles(String fileHash, String certificateHash) throws IOException {
        if (fileHash != null) {
            Path filePath = this.fileUploadLocation.resolve(fileHash).normalize();
            Files.deleteIfExists(filePath);
            Path signedFilePath = this.fileDownloadLocation.resolve(this.addSignatureName(fileHash)).normalize();
            Files.deleteIfExists(signedFilePath);
        }

        if (certificateHash != null) {
            Path certificatePath = this.fileUploadLocation.resolve(certificateHash).normalize();
            Files.deleteIfExists(certificatePath);
        }
    }


    /**
     * Retorna um objeto KeyStore a partir de um arquivo de certificado e uma senha.
     *
     * @param certificateFile o nome do arquivo do certificado
     * @param password a senha do arquivo de certificado
     * @return um objeto KeyStore contendo o certificado
     * @throws KeyStoreException se o tipo de KeyStore não é suportado
     * @throws IOException se houver um erro ao ler o arquivo de certificado
     * @throws CertificateException se houver um erro ao carregar o certificado
     * @throws NoSuchAlgorithmException se o algoritmo de hash não é suportado
     */
    public KeyStore getKeyStore(String certificateFile, String password) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        Path certificateFilePath = this.fileUploadLocation.resolve(certificateFile).normalize();
        FileInputStream fileInputStream = new FileInputStream(certificateFilePath.toString());

        try {
            keyStore.load(fileInputStream, password.toCharArray());
            fileInputStream.close();

            return keyStore;
        } catch (Exception e) {
            fileInputStream.close();
            throw e;
        }
    }

    /**
     * Assina um documento a partir de um arquivo e de um par de chaves.
     *
     * @param fileName o nome do arquivo a ser assinado
     * @param ks o KeyStore contendo as chaves
     * @param password a senha do KeyStore
     * @return o documento assinado
     * @throws IOException se houver um erro ao ler o arquivo
     * @throws UnrecoverableKeyException se a chave privada não puder ser recuperada
     * @throws KeyStoreException se houver um erro com o KeyStore
     * @throws NoSuchAlgorithmException se o algoritmo de hash não é suportado
     */
    public byte[] signDocument(String fileName, KeyStore ks, String password) throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        PKCS7Signer signer = getPKCS7Signer(ks, password);

        Path filePath = this.fileUploadLocation.resolve(fileName).normalize();
        byte[] content = Files.readAllBytes(filePath);

        return signer.doAttachedSign(content);
    }

    /**
     * Cria um novo PDF a partir de um documento assinado e adiciona a assinatura
     * visual.
     *
     * @param fileName o nome do arquivo original
     * @param signedDocument o documento assinado
     * @param keyStore o KeyStore contendo as chaves
     * @param url a URL da assinatura visual
     * @return o novo PDF assinado com a assinatura visual
     * @throws IOException se houver um erro ao ler ou escrever o arquivo
     */
    public byte[] createPDF(String fileName, byte[] signedDocument, KeyStore keyStore, String url) throws IOException {
        Path filePath = this.fileUploadLocation.resolve(fileName).normalize();
        File fileIn = new File(filePath.toString());
        PDDocument originalDocument = PDDocument.load(fileIn);

        Path downloadPath = this.fileDownloadLocation.resolve(this.addSignatureName(fileName)).normalize();
        OutputStream output = new FileOutputStream(downloadPath.toString());

        PDSignature signature = this.getPDSignature();

        SignatureOptions signatureOptions = this.getSignatureOptions(signedDocument.length);

        this.setVisualSignatureTemplate(signature, signatureOptions, originalDocument, keyStore, url);

        originalDocument.addSignature(signature, signatureOptions);

        ExternalSigningSupport externalSigning = originalDocument.saveIncrementalForExternalSigning(output);
        externalSigning.setSignature(signedDocument);

        originalDocument.saveIncremental(output);
        originalDocument.close();
        IOUtils.closeQuietly(signatureOptions);

        return Files.readAllBytes(downloadPath);
    }

    public Path getFilePath(String fileName) {
        return this.fileUploadLocation.resolve(fileName).normalize();
    }

    /**
     * Retorna um objeto PKCS7Signer a partir de um KeyStore e uma senha.
     *
     * @param ks o KeyStore contendo as chaves
     * @param password a senha do KeyStore
     * @return um objeto PKCS7Signer pronto para assinar um documento
     * @throws KeyStoreException se o tipo de KeyStore não é suportado
     * @throws UnrecoverableKeyException se a chave privada não puder ser recuperada
     * @throws NoSuchAlgorithmException se o algoritmo de hash não é suportado
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
     * @param signature a assinatura a ser adicionada ao documento
     * @param signatureOptions as opções de assinatura
     * @param originalDocument o documento original
     * @param keyStore o KeyStore contendo as chaves
     * @param url a URL da assinatura visual
     * @throws IOException se houver um erro ao ler ou escrever o arquivo
     */
    private void setVisualSignatureTemplate(
            PDSignature signature,
            SignatureOptions signatureOptions,
            PDDocument originalDocument,
            KeyStore keyStore,
            String url
    ) throws IOException {
        // Obtém a última página do documento
        PDPageTree pages = originalDocument.getDocumentCatalog().getPages();
        PDPage lastPage = pages.get(pages.getCount() - 1);

        // Obtém o número da página onde a assinatura será adicionada
        int pageNum = this.getPageIndex(pages.getCount());
        signatureOptions.setPage(pageNum);
        var humanRectangle = this.getSignatureHumanRectangle(lastPage.getMediaBox().getWidth());

        Path signatureImageLocation = this.fileAssetLocation.resolve("assinatura_bg.jpg").normalize();
        File signatureImage = new File(signatureImageLocation.toString());
        byte[] signatureContent = Files.readAllBytes(signatureImage.toPath());

        PDRectangle rect = createSignatureRectangle(originalDocument, humanRectangle);

        signatureOptions.setVisualSignature(createVisualSignatureTemplate(
                originalDocument,
                signature,
                pageNum,
                rect,
                signatureContent,
                keyStore,
                url
        ));
    }

    /**
     * Retorna o índice da página onde a assinatura visual será adicionada.
     *
     * O índice é baseado em zero, ou seja, a primeira página possui índice 0.
     * Para automaticamente selecionar a ultima página pode ser passado o
     * valor -1 na Configuração de assinatura
     * Se o índice for inválido ou for maior que o número de páginas, a última página será usada.
     *
     * @param pageCount o número total de páginas no documento
     * @return o índice da página onde a assinatura visual será adicionada
     */
    private int getPageIndex(int pageCount)
    {
        if (
            this.visualSignatureConfig == null ||
            this.visualSignatureConfig.pageIndex() == -1 ||
            this.visualSignatureConfig.pageIndex() >= pageCount
        ) {
            return pageCount - 1;
        }

        return this.visualSignatureConfig.pageIndex();
    }

    /**
     * Retorna um retângulo que representa a área onde ficará a assinatura.
     *
     * Se a Configuração de assinatura for nula, o retângulo será localizado no
     * centro da página, a pixels do fim da página
     * Tamanho fixo de 190 pixels de largura e 70 pixels de altura.
     *
     * @param pageWidth a largura da página em pixels
     * @return um retângulo que representa a área onde ficará a assinatura humana
     */
    private Rectangle2D getSignatureHumanRectangle(float pageWidth)
    {
        if(this.visualSignatureConfig != null) {
            return new Rectangle2D.Float(
                visualSignatureConfig.x(),
                visualSignatureConfig.y(),
                190,
                70
            );
        }

        return new Rectangle2D.Float(
            (pageWidth - (190)) / 2,
            10,
            190,
            70
        );
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
     * @param doc o documento que contém a página a ser assinada
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
     * @param srcDoc          o documento de origem
     * @param signature       o objeto de assinatura
     * @param pageNum         o n mero da p gina
     * @param rect            o ret ngulo
     * @param signatureContent o conte do da assinatura
     * @param keyStore        o reposit rio de chaves
     * @param url             a URL
     * @return um fluxo de entrada com o template de assinatura visual
     * @throws IOException se ocorrer um erro de I/O
     */
    private InputStream createVisualSignatureTemplate(
            PDDocument srcDoc,
            PDSignature signature,
            int pageNum,
            PDRectangle rect,
            byte[] signatureContent,
            KeyStore keyStore,
            String url
    ) throws IOException {
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

                    cs.drawImage(
                        img,
                        0,
                        0,
                        imageWidth,
                        imageHeight
                    );

                    var qr = generateQrcode(appConfig.getUrl() + "/api/v1/qr-code&url=" + url);
                    var baos = new ByteArrayOutputStream();
                    ImageIO.write(qr, "jpeg", baos);
                    PDImageXObject imgQr = PDImageXObject.createFromByteArray(doc, baos.toByteArray(), "qrCode.jpg");
                    cs.drawImage(
                            imgQr,
                            (float) (imageHeight*0.025),
                            (float) (imageHeight*0.125),
                            (float) (imageHeight*0.85),
                            (float) (imageHeight*0.85)
                    );
                    cs.restoreGraphicsState();

                    String alias = keyStore.aliases().nextElement();
                    X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
                    BasicCertificate bc = new BasicCertificate(certificate);

                    var identifier = certificate
                            .getSubjectX500Principal()
                            .getName()
                            .split(":")[1]
                            .split(",")[0];

                    var infoFontSize = (float)(imageHeight*0.06);
                    var fontSize = (float)(imageHeight*0.085);
                    var spacing = (float)(imageHeight*0.025);

                    cs.setFont(PDType1Font.HELVETICA_BOLD, infoFontSize);
                    cs.beginText();
                    cs.newLineAtOffset((float) (imageHeight*0.023), (float)(spacing*1.5));
                    cs.showText("CÓDIGO PARA VERIFICAÇÃO");
                    cs.endText();

                    cs.setFont(PDType1Font.HELVETICA, fontSize);
                    cs.beginText();
                    var marginLeft = (float) ((imageHeight*0.95));
                    cs.newLineAtOffset(marginLeft, (spacing*5) );
                    var sdf = new SimpleDateFormat("dd/MM/yyyy   HH:mm:ss   'UTC'XXX");
                    var date = signature.getSignDate().getTime();
                    cs.showText(sdf.format(date));
                    cs.newLineAtOffset(0, (spacing*10));
                    cs.showText(formatCpfOrCnpj(identifier));
                    cs.newLineAtOffset(0, (float)(spacing*21.5));
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

                    cs.newLineAtOffset(marginLeft, (float) (spacing*(27-(lines.size()*1.5))));
                    for (int i = lines.size()-1; i >= 0; i--) {
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

    /**
     * Gera um hash aleat rio.
     *
     * @return Um hash aleat rio
     */
    public String getRandomHash() {
        UUID uuid = UUID.randomUUID();
        return uuid.toString();
    }

    /**
     * Gera uma imagem de c digo QR com base no texto fornecido.
     *
     * @param barcodeText O texto a ser codificado no c digo QR.
     * @return Uma imagem {@link BufferedImage} representando o c digo QR gerado.
     * @throws Exception Caso ocorra um erro ao gerar o c digo QR.
     */
    public static BufferedImage generateQrcode(String barcodeText) throws Exception {
        QrCode qrCode = QrCode.encodeText(barcodeText, QrCode.Ecc.HIGH);
        BufferedImage img = toImage(qrCode, 4, 0, 0xFFFFFF, 0x000000);
        return img;
    }

    /**
     * Converte um objeto {@link QrCode} para uma imagem {@link BufferedImage}.
     *
     * @param qr         O objeto {@link QrCode} a ser convertido.
     * @param scale      O fator de escala da imagem. O valor deve ser maior que zero.
     * @param border     A largura da borda da imagem em pixels. O valor deve ser maior ou igual a zero.
     * @param lightColor A cor da regi o de fundo da imagem em RGB.
     * @param darkColor  A cor da regi o escura da imagem em RGB.
     * @return Uma imagem {@link BufferedImage} representando o c digo QR gerado.
     * @throws IllegalArgumentException Se o valor de {@code scale} ou {@code border} for menor ou igual a zero.
     */
    public static BufferedImage toImage(QrCode qr, int scale, int border, int lightColor, int darkColor) {
        Objects.requireNonNull(qr);
        if (scale <= 0 || border < 0) {
            throw new IllegalArgumentException("Valor fora do intervalo");
        }
        if (border > Integer.MAX_VALUE / 2 || qr.size + border * 2L > Integer.MAX_VALUE / scale) {
            throw new IllegalArgumentException("Escala ou borda demasiado grande");
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