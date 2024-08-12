package com.example.springboot.services;

import com.example.springboot.enums.FileLocationEnum;
import com.example.springboot.factories.SignatureImageFactory;
import com.example.springboot.records.VisualSignatureConfig;
import com.example.springboot.utils.FileUtils;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
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
import org.demoiselle.signer.policy.impl.pades.pkcs7.impl.PAdESChecker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.awt.geom.AffineTransform;
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

    @Autowired
    FileUtils fileUtils;

    @Autowired
    SignatureImageFactory signatureImageFactory;

    public VisualSignatureConfig visualSignatureConfig;

    public byte[] signDocument(Path filePath, KeyStore ks, String password) throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        PKCS7Signer signer = getPKCS7Signer(ks, password);

        byte[] content = Files.readAllBytes(filePath);

        return signer.doAttachedSign(content);
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

    public Path createPDF(Path filePath, byte[] signedDocument, KeyStore keyStore) throws IOException, KeyStoreException {
        File fileIn = fileUtils.getFile(filePath);
        PDDocument originalDocument = PDDocument.load(fileIn);

        Path downloadPath = fileUtils.getFilePath(addSignatureName(fileIn.getName()), FileLocationEnum.DOWNLOAD);
        OutputStream output = new FileOutputStream(downloadPath.toString());

        PDSignature signature = this.getPDSignature();

        SignatureOptions signatureOptions = this.getSignatureOptions(signedDocument.length);

        this.setVisualSignature(signature, signatureOptions, originalDocument, keyStore);

        originalDocument.addSignature(signature, signatureOptions);

        ExternalSigningSupport externalSigning = originalDocument.saveIncrementalForExternalSigning(output);
        externalSigning.setSignature(signedDocument);

        originalDocument.saveIncremental(output);
        originalDocument.close();
        IOUtils.closeQuietly(signatureOptions);

        return downloadPath;
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

    private void setVisualSignature(
            PDSignature signature,
            SignatureOptions signatureOptions,
            PDDocument originalDocument,
            KeyStore keyStore
    ) throws IOException, KeyStoreException {
        PDPageTree pages = originalDocument.getDocumentCatalog().getPages();
        PDPage lastPage = pages.get(pages.getCount() - 1);

        int pageNum = this.getPageIndex(pages.getCount());
        signatureOptions.setPage(pageNum);
        var humanRect = this.getSignatureHumanRect(lastPage.getMediaBox().getWidth());

        String alias = keyStore.aliases().nextElement();
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        BasicCertificate bc = new BasicCertificate(certificate);

        var signatureContent = this.signatureImageFactory.getDefaultSignature(
            bc.getName(),
            certificate.getSubjectX500Principal().getName().split(":")[1].split(",")[0],
            signature.getSignDate().getTime().toString()
        );

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

    private Rectangle2D getSignatureHumanRect(float pageWidth)
    {
        if(this.visualSignatureConfig != null) {
            return new Rectangle2D.Float(
                    visualSignatureConfig.x(),
                    visualSignatureConfig.y(),
                    100,
                    100
            );
        }

        return new Rectangle2D.Float(
                (pageWidth - 100) / 2,
                10,
                100,
                100
        );
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

                    cs.restoreGraphicsState();
                }

            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            return new ByteArrayInputStream(baos.toByteArray());
        }
    }

    public List<SignatureInformations> validateAllSignatures(Path filePath)
            throws IOException, ParseException, CMSException, CertificateException
    {
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
                Collection<X509CertificateHolder> certificateChain = signature.getCertificates()
                        .getMatches(signerInfo.getSID());

                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                List<X509Certificate> certificates = new ArrayList<>();
                for (X509CertificateHolder certHolder : certificateChain) {
                    X509Certificate cert = (X509Certificate) certFactory
                            .generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
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
