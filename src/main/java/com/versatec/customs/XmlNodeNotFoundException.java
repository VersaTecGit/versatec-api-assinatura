package com.versatec.customs;

/**
 * Exception thrown when an XPath expression does not match any node in the XML
 * document.
 * Signals a client-side error (Bad Request) in the signing flow.
 */
public class XmlNodeNotFoundException extends Exception {

    private final String xpath;

    public XmlNodeNotFoundException(String xpath) {
        super("XML node not found for XPath expression: '" + xpath + "'");
        this.xpath = xpath;
    }

    public String getXpath() {
        return xpath;
    }
}
