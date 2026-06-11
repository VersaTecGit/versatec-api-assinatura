package com.versatec.utils;

import com.versatec.customs.XmlNodeNotFoundException;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

/**
 * Utility component responsible for locating a specific {@link Element} inside a DOM
 * {@link Document} using an XPath expression.
 *
 * <p>This class is intentionally kept narrow in scope so that DOM navigation logic
 * does not pollute the signing core in {@code SignatureService}.</p>
 */
@Component
public class XmlNodeLocator {

    /**
     * Evaluates the given XPath expression against the provided DOM document and returns
     * the matching {@link Element}.
     *
     * @param document the parsed DOM document to search within
     * @param xpath    the XPath expression identifying the target node
     *                 (e.g. {@code "/root/IES_Emissora"} or {@code "//diplomaDigital"})
     * @return the first {@link Element} matched by the XPath expression
     * @throws XPathExpressionException  if the XPath expression is syntactically invalid
     * @throws XmlNodeNotFoundException  if the XPath expression yields no result in the document
     */
    public Element locate(Document document, String xpath)
            throws XPathExpressionException, XmlNodeNotFoundException {

        // Se o xpath for apenas um nome de tag (ex: "A"), tenta buscar pelo nome da tag primeiro
        if (xpath != null && xpath.matches("^[a-zA-Z0-9_:-]+$")) {
            var elements = document.getElementsByTagName(xpath);
            if (elements.getLength() > 0) {
                return (Element) elements.item(0);
            }
        }

        // Caso contrário, avalia como uma expressão XPath real
        XPath xPath = XPathFactory.newInstance().newXPath();
        Element node = (Element) xPath.compile(xpath).evaluate(document, XPathConstants.NODE);

        if (node == null) {
            throw new XmlNodeNotFoundException(xpath);
        }

        return node;
    }
}
