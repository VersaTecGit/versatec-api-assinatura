package com.versatec.utils;

import com.versatec.customs.CustomCertificate;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.List;

/**
 * Utility component that applies an enveloped XMLDSig {@code <ds:Signature>} to a specific
 * {@link Element} inside an existing DOM {@link Document}.
 *
 * <p>Uses the native Java {@code javax.xml.crypto.dsig} API so that the signature node is
 * inserted directly as a child of the target element, leaving any pre-existing signatures
 * elsewhere in the document completely intact.</p>
 *
 * <p>Algorithm choices follow the ICP-Brasil / XAdES BR recommendations:
 * <ul>
 *   <li>Signature: RSA-SHA256 ({@code http://www.w3.org/2001/04/xmldsig-more#rsa-sha256})</li>
 *   <li>Digest: SHA-256 ({@code http://www.w3.org/2001/04/xmlenc#sha256})</li>
 *   <li>Canonicalization: Canonical XML 1.0 ({@code http://www.w3.org/TR/2001/REC-xml-c14n-20010315})</li>
 *   <li>Transform: Enveloped Signature ({@code http://www.w3.org/2000/09/xmldsig#enveloped-signature})</li>
 * </ul>
 * </p>
 */
@Component
public class XmlNodeSigner {

    private static final String SIGNATURE_METHOD   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String DIGEST_METHOD       = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final String C14N_METHOD         = CanonicalizationMethod.INCLUSIVE;
    private static final String ENVELOPED_TRANSFORM = Transform.ENVELOPED;

    /**
     * Signs the given {@code targetElement} in place using an enveloped XMLDSig signature.
     * The {@code <ds:Signature>} node is appended as the last child of {@code targetElement}.
     *
     * <p>The {@code document} object is mutated directly; the caller is responsible for
     * serialising it afterwards.</p>
     *
     * @param document      the DOM document that owns {@code targetElement}
     * @param targetElement the element that will receive the enveloped signature as a child
     * @param certificate   the signing certificate and private key
     * @throws Exception if any cryptographic or XML processing error occurs
     */
    public void signElement(Document document, Element targetElement, CustomCertificate certificate)
            throws Exception {

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // --- Reference: covers the entire targetElement subtree -----------------------
        DigestMethod digestMethod = fac.newDigestMethod(DIGEST_METHOD, null);

        Transform envelopedTransform = fac.newTransform(ENVELOPED_TRANSFORM, (TransformParameterSpec) null);
        Transform c14nTransform      = fac.newTransform(C14N_METHOD, (TransformParameterSpec) null);

        // URI="" means the reference covers the document context node (targetElement in our DOMSignContext)
        Reference reference = fac.newReference(
                "",
                digestMethod,
                List.of(envelopedTransform, c14nTransform),
                null,
                null
        );

        // --- SignedInfo -----------------------------------------------------------
        CanonicalizationMethod c14n = fac.newCanonicalizationMethod(C14N_METHOD, (C14NMethodParameterSpec) null);
        SignatureMethod signatureMethod = fac.newSignatureMethod(SIGNATURE_METHOD, null);

        SignedInfo signedInfo = fac.newSignedInfo(c14n, signatureMethod, Collections.singletonList(reference));

        // --- KeyInfo (X.509 certificate chain) ------------------------------------
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509Data x509Data = kif.newX509Data(List.of((java.security.cert.X509Certificate) certificate.certificate));
        KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(x509Data));

        // --- Build and sign -------------------------------------------------------
        PrivateKey privateKey = (PrivateKey) certificate.keyStore.getKey(
                certificate.alias,
                certificate.password.toCharArray()
        );

        // DOMSignContext with the targetElement as parent: the <Signature> will be appended there
        DOMSignContext signContext = new DOMSignContext(privateKey, targetElement);
        signContext.setDefaultNamespacePrefix("ds");

        XMLSignature xmlSignature = fac.newXMLSignature(signedInfo, keyInfo);
        xmlSignature.sign(signContext);
    }
}
