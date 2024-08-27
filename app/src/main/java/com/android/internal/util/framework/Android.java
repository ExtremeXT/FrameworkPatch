package com.android.internal.util.framework;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Log;

import org.lsposed.lsparanoid.Obfuscate;
import org.spongycastle.asn1.ASN1Boolean;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Enumerated;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.openssl.PEMKeyPair;
import org.spongycastle.openssl.PEMParser;
import org.spongycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

@Obfuscate
public final class Android {
    private static final String TAG = "Play";
    private static final PEMKeyPair EC, RSA;
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");
    private static final List<Certificate> EC_CERTS = new ArrayList<>();
    private static final List<Certificate> RSA_CERTS = new ArrayList<>();
    private static final Map<String, String> map = new HashMap<>();
    private static final CertificateFactory certificateFactory;

    static {
        try {
            Class<Fingerprint> clazz = Fingerprint.class;
            for (Field field : clazz.getDeclaredFields()) {
                // MANUFACTURER == Fingerprint.MANUFACTURER
                // MODEL == Fingerprint.MODEL
                // and so on
                map.put(field.getName(), (String)field.get(null));
            }
        } catch (Throwable t) {
            Log.e(TAG, t.toString());
            throw new RuntimeException(t);
        }

        try {
            certificateFactory = CertificateFactory.getInstance("X.509");

            EC = parseKeyPair(Keybox.EC.PRIVATE_KEY);
            EC_CERTS.add(parseCert(Keybox.EC.CERTIFICATE_1));
            EC_CERTS.add(parseCert(Keybox.EC.CERTIFICATE_2));
            EC_CERTS.add(parseCert(Keybox.EC.CERTIFICATE_3));

            RSA = parseKeyPair(Keybox.RSA.PRIVATE_KEY);
            RSA_CERTS.add(parseCert(Keybox.RSA.CERTIFICATE_1));
            RSA_CERTS.add(parseCert(Keybox.RSA.CERTIFICATE_2));
            RSA_CERTS.add(parseCert(Keybox.RSA.CERTIFICATE_3));
        } catch (Throwable t) {
            Log.e(TAG, t.toString());
            throw new RuntimeException(t);
        }
    }

    private static PEMKeyPair parseKeyPair(String key) throws Throwable {
        try (PEMParser parser = new PEMParser(new StringReader(key))) {
            return (PEMKeyPair) parser.readObject();
        }
    }

    private static Certificate parseCert(String cert) throws Throwable {
        try (PemReader reader = new PemReader(new StringReader(cert))) {
            return certificateFactory.generateCertificate(new ByteArrayInputStream(reader.readPemObject().getContent()));
        }
    }

    private static Field getField(String fieldName) {
        Field field = null;
        try {
            field = Build.class.getDeclaredField(fieldName);
        } catch (Throwable ignored) {
            try {
                field = Build.VERSION.class.getDeclaredField(fieldName);
            } catch (Throwable t) {
                Log.e(TAG, "Couldn't find field " + fieldName);
            }
        }
        return field;
    }

    public static boolean hasSystemFeature(boolean ret, String name) {
        try {
            Class<?> systemPropertiesClass = Class.forName("android.os.SystemProperties");
            Method getBooleanMethod = systemPropertiesClass.getMethod("getBoolean", String.class, boolean.class);
            boolean noPlay = (Boolean) getBooleanMethod.invoke(null, "persist.sys.no_play", false);
            if (noPlay) return ret;
        } catch (Exception ignored) {}

        if (PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY.equals(name) || PackageManager.FEATURE_STRONGBOX_KEYSTORE.equals(name)) {
            return false;
        }

        return ret;
    }

    public static void newApplication(Context context) {
        if (context == null) return;

        try {
            Class<?> systemPropertiesClass = Class.forName("android.os.SystemProperties");
            Method getBooleanMethod = systemPropertiesClass.getMethod("getBoolean", String.class, boolean.class);
            boolean noPlay = (Boolean) getBooleanMethod.invoke(null, "persist.sys.no_play", false);
            if (noPlay) return;
        } catch (Exception ignored) {}

        String packageName = context.getPackageName();
        String processName = Application.getProcessName();

        if (TextUtils.isEmpty(packageName) || TextUtils.isEmpty(processName)) return;

        if (!"com.google.android.gms".equals(packageName)) return;

        if (!"com.google.android.gms.unstable".equals(processName)) return;

        map.forEach((fieldName, value) -> {
            Field field = getField(fieldName);
            if (field == null) return;
            field.setAccessible(true);
            try {
                field.set(null, value);
            } catch (Throwable t) {
                Log.e(TAG, t.toString());
            }
            field.setAccessible(false);
        });
    }

    public static Certificate[] engineGetCertificateChain(Certificate[] caList) {
        try {
            Class<?> systemPropertiesClass = Class.forName("android.os.SystemProperties");
            Method getBooleanMethod = systemPropertiesClass.getMethod("getBoolean", String.class, boolean.class);
            boolean noPlay = (Boolean) getBooleanMethod.invoke(null, "persist.sys.no_play", false);
            if (noPlay) return caList;

        } catch (Exception ignored) {}

        if (caList == null) throw new UnsupportedOperationException();

        try {
            // These have to be set to the security patch level date and version of your ROM
            int osVersionLevelVal = 140000;
            int osPatchLevelVal = 202408;

            X509Certificate leaf = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(caList[0].getEncoded()));
            if (leaf.getExtensionValue(OID.getId()) == null) return caList;

            X509CertificateHolder holder = new X509CertificateHolder(leaf.getEncoded());
            Extension ext = holder.getExtension(OID);
            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());
            ASN1Encodable[] encodables = sequence.toArray();
            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];
            ASN1EncodableVector vector = new ASN1EncodableVector();

            for (ASN1Encodable asn1Encodable : teeEnforced) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;
                var tag = taggedObject.getTagNo();
                /*
                * https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema
                * Values we replace:
                * 704: rootOfTrust
                * 705: osVersion
                * 706: osPatchlevel
                * 718: vendorPatchlevel
                * 719: bootPatchLevel
                */
                if (tag == 704 || tag == 705 || tag == 706 || tag == 718 || tag == 719) continue;
                vector.add(taggedObject);
            }

            LinkedList<Certificate> certificates;
            X509v3CertificateBuilder builder;
            ContentSigner signer;

            if (KeyProperties.KEY_ALGORITHM_EC.equals(leaf.getPublicKey().getAlgorithm())) {
                certificates = new LinkedList<>(EC_CERTS);
                builder = new X509v3CertificateBuilder(new X509CertificateHolder(EC_CERTS.get(0).getEncoded()).getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), EC.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder(leaf.getSigAlgName()).build(new JcaPEMKeyConverter().getPrivateKey(EC.getPrivateKeyInfo()));
            } else {
                certificates = new LinkedList<>(RSA_CERTS);
                builder = new X509v3CertificateBuilder(new X509CertificateHolder(RSA_CERTS.get(0).getEncoded()).getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), RSA.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder(leaf.getSigAlgName()).build(new JcaPEMKeyConverter().getPrivateKey(RSA.getPrivateKeyInfo()));
            }

            byte[] verifiedBootKey = new byte[32];
            byte[] verifiedBootHash = new byte[32];

            ThreadLocalRandom.current().nextBytes(verifiedBootKey);
            ThreadLocalRandom.current().nextBytes(verifiedBootHash);

            ASN1Encodable[] rootOfTrustEnc = {new DEROctetString(verifiedBootKey), ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(verifiedBootHash)};
            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEnc);
            ASN1TaggedObject rootOfTrustTagObj = new DERTaggedObject(704, rootOfTrustSeq);
            vector.add(rootOfTrustTagObj);

            // Spoof OS Version
            ASN1Encodable osVersionlevelEnc = new ASN1Integer(osVersionLevelVal);
            ASN1TaggedObject osVersionLevelObj = new DERTaggedObject(705, osVersionlevelEnc);
            vector.add(osVersionLevelObj);

            // Spoof OS Patch Level
            ASN1Encodable osPatchLevelEnc = new ASN1Integer(osPatchLevelVal);
            ASN1TaggedObject osPatchLevelObj = new DERTaggedObject(706, osPatchLevelEnc);
            vector.add(osPatchLevelObj);

            int value = Integer.parseInt(String.valueOf(osPatchLevelVal).concat("01"));

            // Spoof Vendor Patch Level
            ASN1Encodable vendorPatchLevelEnc = new ASN1Integer(value);
            ASN1TaggedObject vendorPatchLevelObj = new DERTaggedObject(718, vendorPatchLevelEnc);
            vector.add(vendorPatchLevelObj);

            // Spoof Boot Patch Level
            ASN1Encodable bootPatchLevelEnc = new ASN1Integer(value);
            ASN1TaggedObject bootPatchLevelObj = new DERTaggedObject(719, bootPatchLevelEnc);
            vector.add(bootPatchLevelObj);

            ASN1Sequence hackEnforced = new DERSequence(vector);
            encodables[7] = hackEnforced;
            ASN1Sequence hackedSeq = new DERSequence(encodables);
            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);
            Extension hackedExt = new Extension(OID, false, hackedSeqOctets);
            builder.addExtension(hackedExt);

            for (ASN1ObjectIdentifier extensionOID : holder.getExtensions().getExtensionOIDs()) {
                if (OID.getId().equals(extensionOID.getId())) continue;
                builder.addExtension(holder.getExtension(extensionOID));
            }

            certificates.addFirst(new JcaX509CertificateConverter().getCertificate(builder.build(signer)));

            return certificates.toArray(new Certificate[0]);

        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }
        return caList;
    }
}
