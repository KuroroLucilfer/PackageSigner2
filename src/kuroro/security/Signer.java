/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package kuroro.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.regex.Pattern;

import sun.misc.BASE64Encoder;
import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

/**
 * A command line tool to sign APKs and OTA update packages in a
 * way compatible with the mincrypt verifier, using SHA1 and RSA keys.
 */
@SuppressWarnings("restriction")
class Signer {
    
    private static final String PUBLIC_KEY = "/assets/keys/testkey.x509.pem";
    private static final String PRIVATE_KEY = "/assets/keys/testkey.pk8";
    
    private static final String CERT_SF_NAME = "META-INF/CERT.SF";
    private static final String CERT_RSA_NAME = "META-INF/CERT.RSA";
    private static final String OTACERT_NAME = "META-INF/com/android/otacert";
    
    // Files matching this pattern are not copied to the output.
    private static final Pattern PATTERN = Pattern.compile("^META-INF/(.*)[.](SF|RSA|DSA)$");
    
    private static final Pattern APK = Pattern.compile("\\.apk$");
    private static final Pattern ZIP = Pattern.compile("\\.zip$");
    
    
    /**
     * Read the key contents and get its data as byte array.
     * @param keyName The public or private key
     * @return The key data as byte array
     */
    private static byte[] readKeyContents(String keyName) throws IOException {
        InputStream input = Signer.class.getResourceAsStream(keyName);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while((length = input.read(buffer)) > 0) {
            output.write(buffer, 0, length);
        }
        return output.toByteArray();
    }
    
    
    /** Read an X509 public key. */
    private static X509Certificate readPublicKey()
            throws IOException, GeneralSecurityException {
        InputStream input = new ByteArrayInputStream(readKeyContents(PUBLIC_KEY));
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(input);
    }
    
    
    /** Read a PKCS 8 format private key. */
    private static PrivateKey readPrivateKey()
            throws IOException, GeneralSecurityException {
        KeySpec spec = new PKCS8EncodedKeySpec(readKeyContents(PRIVATE_KEY));
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (InvalidKeySpecException ex) {
            return KeyFactory.getInstance("DSA").generatePrivate(spec);
        }
    }
    
    
    /** Add the SHA1 of every file to the manifest, creating it if necessary. */
    private static Manifest messageDigests(JarFile jar)
            throws IOException, GeneralSecurityException {
        Manifest input = jar.getManifest();
        Manifest output = new Manifest();
        Attributes main = output.getMainAttributes();
        if (input != null) {
            main.putAll(input.getMainAttributes());
        } else {
            main.putValue("Manifest-Version", "1.0");
        }
        
        BASE64Encoder base64 = new BASE64Encoder();
        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] buffer = new byte[4096];
        int num;

        // We sort the input entries by name, and add them to the
        // output manifest in sorted order. We expect that the output
        // map will be deterministic.
        
        TreeMap<String, JarEntry> byName = new TreeMap<String, JarEntry>();
        
        for (Enumeration<JarEntry> e = jar.entries(); e.hasMoreElements();) {
            JarEntry entry = e.nextElement();
            byName.put(entry.getName(), entry);
        }
        
        System.out.print("\rGenerating message digest...");
        
        for (JarEntry entry : byName.values()) {
            String name = entry.getName();
            if (!entry.isDirectory() && !name.equals(JarFile.MANIFEST_NAME)
                    && !name.equals(CERT_SF_NAME) && !name.equals(CERT_RSA_NAME)
                    && !name.equals(OTACERT_NAME)
                    && (PATTERN == null || !PATTERN.matcher(name).matches())) {
                InputStream data = jar.getInputStream(entry);
                while ((num = data.read(buffer)) > 0) {
                    md.update(buffer, 0, num);
                }
                
                Attributes attr = null;
                if (input != null) attr = input.getAttributes(name);
                attr = attr != null ? new Attributes(attr) : new Attributes();
                attr.putValue("SHA1-Digest", base64.encode(md.digest()));
                output.getEntries().put(name, attr);
            }
        }
        
        return output;
    }
    
    
    /**
     * Add a copy of the public key to the archive; this should exactly match one
     * of the files in /system/etc/security/otacerts.zip on the device. (The same
     * cert can be extracted from the CERT.RSA file but this is much easier to get
     * at.)
     */
    private static void addOTACert(
            JarOutputStream outputJar,
            long timestamp,
            Manifest manifest)
            throws IOException, GeneralSecurityException {
        InputStream input = new ByteArrayInputStream(readKeyContents(PUBLIC_KEY));
        
        BASE64Encoder base64 = new BASE64Encoder();
        MessageDigest md = MessageDigest.getInstance("SHA1");
        
        JarEntry je = new JarEntry(OTACERT_NAME);
        je.setTime(timestamp);
        outputJar.putNextEntry(je);
        
        byte[] b = new byte[4096];
        int read;
        
        System.out.print("\rGenerating OTA certificate...");
        
        while ((read = input.read(b)) != -1) {
            outputJar.write(b, 0, read);
            md.update(b, 0, read);
        }
        input.close();
        
        Attributes attr = new Attributes();
        attr.putValue("SHA1-Digest", base64.encode(md.digest()));
        manifest.getEntries().put(OTACERT_NAME, attr);
    }
    
    /** Write a .SF file with a digest of the specified manifest. */
    private static void signatureFile(Manifest manifest, SignatureStream out)
            throws IOException, GeneralSecurityException {
        Manifest sf = new Manifest();
        Attributes main = sf.getMainAttributes();
        main.putValue("Signature-Version", "1.0");
        
        BASE64Encoder base64 = new BASE64Encoder();
        MessageDigest md = MessageDigest.getInstance("SHA1");
        PrintStream print = new PrintStream(
                new DigestOutputStream(new ByteArrayOutputStream(), md), true, "UTF-8");

        // Digest of the entire manifest
        manifest.write(print);
        print.flush();
        main.putValue("SHA1-Digest-Manifest", base64.encode(md.digest()));
        
        Map<String, Attributes> entries = manifest.getEntries();
        for (Map.Entry<String, Attributes> entry : entries.entrySet()) {
            // Digest of the manifest stanza for this entry.
            print.print("Name: " + entry.getKey() + "\r\n");
            for (Map.Entry<Object, Object> att : entry.getValue().entrySet()) {
                print.print(att.getKey() + ": " + att.getValue() + "\r\n");
            }
            print.print("\r\n");
            print.flush();
            Attributes sfAttr = new Attributes();
            sfAttr.putValue("SHA1-Digest", base64.encode(md.digest()));
            sf.getEntries().put(entry.getKey(), sfAttr);
        }
        
        System.out.print("\rGenerating signature file...");
        
        sf.write(out);

        // A bug in the java.util.jar implementation of Android platforms
        // up to version 1.6 will cause a spurious IOException to be thrown
        // if the length of the signature file is a multiple of 1024 bytes.
        // As a workaround, add an extra CRLF in this case.
        if ((out.size() % 1024) == 0) {
            out.write('\r');
            out.write('\n');
        }
    }
    
    
    /** Write a .RSA file with a digital signature. */
    private static void signatureBlock(
            Signature signature,
            X509Certificate publicKey,
            OutputStream out)
            throws IOException, GeneralSecurityException {
        SignerInfo signerInfo = new SignerInfo(
                new X500Name(publicKey.getIssuerX500Principal().getName()),
                publicKey.getSerialNumber(),
                AlgorithmId.get("SHA1"),
                AlgorithmId.get("RSA"),
                signature.sign());
        
        PKCS7 pkcs7 = new PKCS7(
                new AlgorithmId[] { AlgorithmId.get("SHA1") },
                new ContentInfo(ContentInfo.DATA_OID, null),
                new X509Certificate[] { publicKey },
                new SignerInfo[] { signerInfo });
        
        System.out.print("\rGenerating signature block...");
        
        pkcs7.encodeSignedData(out);
    }
    
    
    private static void wholePackage(
            byte[] zipData,
            OutputStream outputStream,
            X509Certificate publicKey,
            PrivateKey privateKey)
            throws IOException, GeneralSecurityException {

        // For a zip with no archive comment, the
        // end-of-central-directory record will be 22 bytes long, so
        // we expect to find the EOCD marker 22 bytes from the end.
        if (zipData[zipData.length - 22] != 0x50
                || zipData[zipData.length - 21] != 0x4b
                || zipData[zipData.length - 20] != 0x05
                || zipData[zipData.length - 19] != 0x06) {
            throw new IllegalArgumentException("zip data already has an archive comment");
        }
        
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(zipData, 0, zipData.length - 2);
        
        ByteArrayOutputStream temp = new ByteArrayOutputStream();

        // Put a readable message and a null char at the start of the
        // archive comment, so that tools that display the comment
        // (hopefully) show something sensible.
        // TODO: anything more useful we can put in this message?
        byte[] message = "signed by SignApk".getBytes("UTF-8");
        temp.write(message);
        temp.write(0);
        
        signatureBlock(signature, publicKey, temp);
        
        System.out.print("\rWriting signature comment...");
        
        int total_size = temp.size() + 6;
        if (total_size > 0xffff) {
            throw new IllegalArgumentException("Signature is too big for ZIP file comment");
        }
        // Signature starts this many bytes from the end of the file
        int signature_start = total_size - message.length - 1;
        temp.write(signature_start & 0xff);
        temp.write((signature_start >> 8) & 0xff);
        // Why the 0xff bytes? In a zip file with no archive comment,
        // bytes [-6:-2] of the file are the little-endian offset from
        // the start of the file to the central directory. So for the
        // two high bytes to be 0xff 0xff, the archive would have to
        // be nearly 4GB in side. So it's unlikely that a real
        // commentless archive would have 0xffs here, and lets us tell
        // an old signed archive from a new one.
        temp.write(0xff);
        temp.write(0xff);
        temp.write(total_size & 0xff);
        temp.write((total_size >> 8) & 0xff);
        temp.flush();

        // Signature verification checks that the EOCD header is the
        // last such sequence in the file (to avoid minzip finding a
        // fake EOCD appended after the signature in its scan). The
        // odds of producing this sequence by chance are very low, but
        // let's catch it here if it does.
        byte[] b = temp.toByteArray();
        for (int i = 0; i < b.length - 3; ++i) {
            if (b[i] == 0x50 && b[i + 1] == 0x4b && b[i + 2] == 0x05 && b[i + 3] == 0x06) {
                throw new IllegalArgumentException("Found spurious EOCD header at " + i);
            }
        }
        
        outputStream.write(zipData, 0, zipData.length - 2);
        outputStream.write(total_size & 0xff);
        outputStream.write((total_size >> 8) & 0xff);
        temp.writeTo(outputStream);
    }
    
    
    /**
     * Copy all the files in a manifest from input to output. We set the
     * modification times in the output to a fixed time, so as to reduce variation
     * in the output file and make incremental OTAs more efficient.
     */
    private static void packageContents(
            Manifest manifest,
            JarFile in,
            JarOutputStream out,
            long timestamp)
            throws IOException {
        
        byte[] buffer = new byte[4096];
        int num;
        
        Map<String, Attributes> entries = manifest.getEntries();
        List<String> names = new ArrayList<String>(entries.keySet());
        Collections.sort(names);
        
        System.out.print("\rCopying package contents...");
        
        for (String name : names) {
            JarEntry inEntry = in.getJarEntry(name);
            JarEntry outEntry = null;
            if (inEntry.getMethod() == JarEntry.STORED) {
                // Preserve the STORED method of the input entry.
                outEntry = new JarEntry(inEntry);
            } else {
                // Create a new entry so that the compressed len is recomputed.
                outEntry = new JarEntry(name);
            }
            outEntry.setTime(timestamp);
            out.putNextEntry(outEntry);
            
            InputStream data = in.getInputStream(inEntry);
            while ((num = data.read(buffer)) > 0) {
                out.write(buffer, 0, num);
            }
            out.flush();
        }
    }
    
    
    private static void sign(String pkgInput, String pkgOutput, boolean bool)
            throws IOException, GeneralSecurityException {
        
        boolean signWholePackage = bool;
        
        JarEntry je;
        JarFile inputJar = null;
        JarOutputStream outputJar = null;
        FileOutputStream outputFile = null;
        OutputStream outputStream = null;
        
        X509Certificate publicKey = readPublicKey();
        
        // Assume the certificate is valid for at least an hour.
        long timestamp = publicKey.getNotBefore().getTime() + 3600L * 1000;
        
        PrivateKey privateKey = readPrivateKey();
        inputJar = new JarFile(new File(pkgInput), false); // Don't verify.
        
        if (signWholePackage) {
            outputStream = new ByteArrayOutputStream();
        } else {
            outputStream = outputFile = new FileOutputStream(new File(pkgOutput));
        }
        outputJar = new JarOutputStream(outputStream);
        outputJar.setLevel(9);
        
        // Add message digest
        Manifest manifest = messageDigests(inputJar);
        
        // Copy package files
        packageContents(manifest, inputJar, outputJar, timestamp);
        
        // Add OTA Certificate
        if (signWholePackage) {
            addOTACert(outputJar, timestamp, manifest);
        }
        
        // MANIFEST.MF
        je = new JarEntry(JarFile.MANIFEST_NAME);
        je.setTime(timestamp);
        outputJar.putNextEntry(je);
        manifest.write(outputJar);

        // CERT.SF
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        je = new JarEntry(CERT_SF_NAME);
        je.setTime(timestamp);
        outputJar.putNextEntry(je);
        signatureFile(manifest, new SignatureStream(outputJar, signature));
        
        // CERT.RSA
        je = new JarEntry(CERT_RSA_NAME);
        je.setTime(timestamp);
        outputJar.putNextEntry(je);
        signatureBlock(signature, publicKey, outputJar);
        
        outputJar.close();
        outputJar = null;
        outputStream.flush();
        
        if (signWholePackage) {
            outputFile = new FileOutputStream(pkgOutput);
            wholePackage(
                    ((ByteArrayOutputStream) outputStream).toByteArray(),
                    outputFile,
                    publicKey,
                    privateKey);
        }
        
        if (inputJar != null) inputJar.close();
        if (outputFile != null) outputFile.close();
    }
    
    
    public static void main(String[] args) {
        
        if (args.length < 1 || args.length > 2) {
            System.out.print("Usage: java -jar signer.jar [-w] [package]\n\n");
            System.exit(0);
        }
        
        boolean signWhole = false;
        String signedPkg = null;
        String pkgName = null;
        
        for (String arg : args) {
            if (arg.toLowerCase().equals("-w")) signWhole = true;
            if (arg.toLowerCase().endsWith(".apk")) {
                signedPkg = APK.matcher(arg).replaceAll("") + "_signed.apk";
                pkgName = arg;
            } else if (arg.toLowerCase().endsWith(".zip")) {
                signedPkg = ZIP.matcher(arg).replaceAll("") + "_signed.zip";
                pkgName = arg;
            }
        }
        
        try {
            sign(pkgName, signedPkg, signWhole);
            System.out.print("\r"
                    + signedPkg
                    + " ("
                    + new File(signedPkg).length()
                    + " Bytes)"
                    + " √\n\n");
        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(0);
        }
    }
}
