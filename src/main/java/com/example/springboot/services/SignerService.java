package com.example.springboot.services;

import com.example.springboot.FileStorageProperties;
import com.example.springboot.records.VisualSignatureConfig;
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
import org.demoiselle.signer.core.extension.CertificateExtra;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.List;

@Service
public class SignerService {

    private final Path fileAssetLocation;
    private final Path fileUploadLocation;
    private final Path fileDownloadLocation;
    private VisualSignatureConfig visualSignatureConfig;

    public SignerService(FileStorageProperties fileStorageLocation) {
        this.fileAssetLocation = Paths.get(fileStorageLocation.getAssetDir()).toAbsolutePath().normalize();
        this.fileUploadLocation = Paths.get(fileStorageLocation.getUploadDir()).toAbsolutePath().normalize();
        this.fileDownloadLocation = Paths.get(fileStorageLocation.getDownloadDir()).toAbsolutePath().normalize();
        this.visualSignatureConfig = new VisualSignatureConfig(-1, 247, 10);

    }

    public void setVisualSignatureConfig(VisualSignatureConfig value)
    {
        this.visualSignatureConfig = value;
    }

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

    public Path getCertificatePath(String certificate) {
        //TODO Change default location
        String location = "C:\\Projetos\\springboot\\" + certificate;

        return Paths.get(location);
    }

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

    public byte[] signDocument(String fileName, KeyStore ks, String password) throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        PKCS7Signer signer = getPKCS7Signer(ks, password);

        Path filePath = this.fileUploadLocation.resolve(fileName).normalize();
        byte[] content = Files.readAllBytes(filePath);

        return signer.doAttachedSign(content);
    }

    public byte[] createPDF(String fileName, byte[] signedDocument, KeyStore keyStore) throws IOException {
        Path filePath = this.fileUploadLocation.resolve(fileName).normalize();
        File fileIn = new File(filePath.toString());
        PDDocument originalDocument = PDDocument.load(fileIn);

        Path downloadPath = this.fileDownloadLocation.resolve(this.addSignatureName(fileName)).normalize();
        OutputStream output = new FileOutputStream(downloadPath.toString());

        PDSignature signature = this.getPDSignature();

        SignatureOptions signatureOptions = this.getSignatureOptions(signedDocument.length);

        this.setVisualSignatureTemplate(signature, signatureOptions, originalDocument, keyStore);

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

    private PKCS7Signer getPKCS7Signer(KeyStore ks, String password) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        String alias = ks.aliases().nextElement();

        PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
        signer.setCertificates(ks.getCertificateChain(alias));
        signer.setPrivateKey((PrivateKey) ks.getKey(alias, password.toCharArray()));
//        signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_3);
//        signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);

        return signer;
    }

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

    private void setVisualSignatureTemplate(
            PDSignature signature,
            SignatureOptions signatureOptions,
            PDDocument originalDocument,
            KeyStore keyStore
    ) throws IOException {
        PDPageTree pages = originalDocument.getDocumentCatalog().getPages();

        int pageNum;
        if (
            this.visualSignatureConfig.pageIndex() == -1 ||
            this.visualSignatureConfig.pageIndex() >= pages.getCount()
        ) {
            pageNum = pages.getCount() - 1;
        }
        else {
            pageNum = this.visualSignatureConfig.pageIndex();
        }

        signatureOptions.setPage(pageNum);
        Rectangle2D humanRect = new Rectangle2D.Float(
                visualSignatureConfig.x(),
                visualSignatureConfig.y(),
                100,
                100
        );

        Path signatureImageLocation = this.fileAssetLocation.resolve("selo_escuro.jpeg").normalize();
        File signatureImage = new File(signatureImageLocation.toString());
        byte[] signatureContent = Files.readAllBytes(signatureImage.toPath());

        PDRectangle rect = createSignatureRectangle(originalDocument, humanRect);

        signatureOptions.setVisualSignature(createVisualSignatureTemplate(
                originalDocument,
                signature,
                pageNum,
                rect,
                signatureContent,
                keyStore
        ));
    }

    private String addSignatureName(String fileName) {
        int indicePonto = fileName.lastIndexOf('.');
        if (indicePonto != -1) {
            String name = fileName.substring(0, indicePonto);
            String extension = fileName.substring(indicePonto);

            return name + "_assinado" + extension;
        }
        return fileName;
    }

    private PDRectangle createSignatureRectangle(PDDocument doc, Rectangle2D humanRect) {
        float x = (float) humanRect.getX();
        float y = (float) humanRect.getY();
        float width = (float) humanRect.getWidth();
        float height = (float) humanRect.getHeight();
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

    private InputStream createVisualSignatureTemplate(
            PDDocument srcDoc,
            PDSignature signature,
            int pageNum,
            PDRectangle rect,
            byte[] signatureContent,
            KeyStore keyStore
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
                    PDImageXObject img = PDImageXObject.createFromByteArray(doc, signatureContent, "signature.png");

                    float imageWidth = bbox.getWidth();
                    float imageHeight = bbox.getHeight();
                    if (pageRotation == 90 || pageRotation == 270) {
                        imageWidth = bbox.getHeight();
                        imageHeight = bbox.getWidth();
                    }
                    cs.drawImage(img, 0, 0, imageWidth, imageHeight);

                    String alias = keyStore.aliases().nextElement();
                    X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
                    BasicCertificate bc = new BasicCertificate(certificate);

                    var identifier = certificate
                            .getSubjectX500Principal()
                            .getName()
                            .split(":")[1]
                            .split(",")[0];

                    cs.setFont(PDType1Font.HELVETICA_BOLD, 6);
                    cs.beginText();
                    cs.newLineAtOffset(0,36);
                    cs.showText(signature.getSignDate().getTime().toString());
                    cs.newLineAtOffset(0,12);
                    cs.showText(formatCpfOrCnpj(identifier));
                    cs.newLineAtOffset(0,12);
                    cs.showText(bc.getName());
                    cs.endText();

                    cs.restoreGraphicsState();
                }

            } catch (KeyStoreException e) {
                throw new RuntimeException(e);
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            return new ByteArrayInputStream(baos.toByteArray());
        }
    }

    public static String formatCpfOrCnpj(String number) {
        if (number == null || number.isEmpty()) {
            return "";
        }

        // Remove all non-digit characters
        number = number.replaceAll("\\D", "");

        if (number.length() == 11) {
            // Format CPF
            return number.replaceAll("(\\d{3})(\\d{3})(\\d{3})(\\d{2})", "$1.$2.$3-$4");
        } else if (number.length() == 14) {
            // Format CNPJ
            return number.replaceAll("(\\d{2})(\\d{4})(\\d{4})(\\d{2})(\\d{1})", "$1.$2.$3/$4-$5");
        } else {
            // Invalid length
            return "Invalid length";
        }
    }

    public String getRandomHash() {
        UUID uuid = UUID.randomUUID();
        return uuid.toString();
    }
}
