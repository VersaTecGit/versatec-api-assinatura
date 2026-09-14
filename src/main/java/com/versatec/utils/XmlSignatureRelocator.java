package com.versatec.utils;

import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

@Component
public class XmlSignatureRelocator {

    private final XmlNodeLocator xmlNodeLocator;

    public XmlSignatureRelocator(XmlNodeLocator xmlNodeLocator) {
        this.xmlNodeLocator = xmlNodeLocator;
    }

    /** Package-private: usado apenas nos testes que não sobem o contexto Spring. */
    XmlSignatureRelocator() {
        this.xmlNodeLocator = new XmlNodeLocator();
    }

    /**
     * Move a última tag <ds:Signature> adicionada ao documento para o nó especificado pelo XPath.
     *
     * @param document O documento assinado
     * @param targetXPath O XPath do nó onde a assinatura deve residir
     * @throws Exception se o targetXPath não for encontrado ou inválido
     */
    public void relocate(Document document, String targetXPath) throws Exception {
        if (targetXPath == null || targetXPath.isBlank()) {
            return;
        }

        Element targetElement = xmlNodeLocator.locate(document, targetXPath);
        Element root = document.getDocumentElement();

        // Demoiselle appends the <ds:Signature> at the root element.
        // We locate it and move it to the targetXPath element.
        NodeList signatures = document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        if (signatures.getLength() > 0) {
            Node sigNode = signatures.item(signatures.getLength() - 1);

            if (!targetElement.isSameNode(root)) {
                root.removeChild(sigNode);
                targetElement.appendChild(sigNode);
            }
        }
    }
}
