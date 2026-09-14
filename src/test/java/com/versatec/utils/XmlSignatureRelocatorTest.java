package com.versatec.utils;

import com.versatec.customs.XmlNodeNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import static org.junit.jupiter.api.Assertions.*;

class XmlSignatureRelocatorTest {

    private XmlSignatureRelocator relocator;
    private DocumentBuilder builder;

    @BeforeEach
    void setUp() throws Exception {
        relocator = new XmlSignatureRelocator();
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        builder = factory.newDocumentBuilder();
    }

    @Test
    void testRelocateToNestedNode() throws Exception {
        Document doc = builder.newDocument();
        Element root = doc.createElement("Root");
        doc.appendChild(root);
        Element nested = doc.createElement("Nested");
        root.appendChild(nested);
        
        Element sig = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        root.appendChild(sig);

        relocator.relocate(doc, "Nested");

        // The signature should have been moved inside <Nested>
        assertEquals(0, root.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").getLength() - 1);
        assertEquals(1, nested.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").getLength());
        assertTrue(nested.isSameNode(sig.getParentNode()));
    }

    @Test
    void testRelocateNullXPathIsNoOp() throws Exception {
        Document doc = builder.newDocument();
        Element root = doc.createElement("Root");
        doc.appendChild(root);
        Element sig = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        root.appendChild(sig);

        relocator.relocate(doc, null);
        relocator.relocate(doc, " ");

        // Signature remains at the root
        assertTrue(root.isSameNode(sig.getParentNode()));
    }

    @Test
    void testRelocateToRootNode() throws Exception {
        Document doc = builder.newDocument();
        Element root = doc.createElement("Root");
        doc.appendChild(root);
        Element sig = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        root.appendChild(sig);

        relocator.relocate(doc, "Root");

        // Signature remains at the root (not moved)
        assertTrue(root.isSameNode(sig.getParentNode()));
    }

    @Test
    void testRelocateNonExistentNodeThrowsException() {
        Document doc = builder.newDocument();
        Element root = doc.createElement("Root");
        doc.appendChild(root);
        Element sig = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        root.appendChild(sig);

        assertThrows(XmlNodeNotFoundException.class, () -> {
            relocator.relocate(doc, "NonExistent");
        });
    }

    @Test
    void testRelocateWithPreexistingSignatures() throws Exception {
        Document doc = builder.newDocument();
        Element root = doc.createElement("Root");
        doc.appendChild(root);
        Element nested1 = doc.createElement("Nested1");
        root.appendChild(nested1);
        Element nested2 = doc.createElement("Nested2");
        root.appendChild(nested2);
        
        // Pre-existing signature already in nested1
        Element sig1 = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        nested1.appendChild(sig1);

        // New signature appended to root
        Element sig2 = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        root.appendChild(sig2);

        relocator.relocate(doc, "Nested2");

        // First signature remains in nested1
        assertTrue(nested1.isSameNode(sig1.getParentNode()));
        // Second signature is moved to nested2
        assertTrue(nested2.isSameNode(sig2.getParentNode()));
    }
}
