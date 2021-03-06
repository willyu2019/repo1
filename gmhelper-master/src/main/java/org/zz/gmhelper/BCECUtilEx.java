package org.zz.gmhelper;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class BCECUtilEx {
    private static final String ALGO_NAME_EC = "EC";
    private static final String PEM_STRING_PUBLIC = "PUBLIC KEY";
    private static final String PEM_STRING_ECPRIVATEKEY = "EC PRIVATE KEY";

    /**
     * ??????ECC?????????
     *
     * @return ECC?????????
     */
    public static AsymmetricCipherKeyPair generateKeyPair(ECDomainParameters domainParameters, SecureRandom random) {
        ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(domainParameters, random);
        ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
        keyGen.init(keyGenerationParams);
        return keyGen.generateKeyPair();
    }

    public static int getCurveLength(ECKeyParameters ecKey) {
        return getCurveLength(ecKey.getParameters());
    }

    public static int getCurveLength(ECDomainParameters domainParams) {
        return (domainParams.getCurve().getFieldSize() + 7) / 8;
    }
    
    
    public static BCECPrivateKey createECPrivateKey(String encodedPriKey, ECDomainParameters domainParameters) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    	return new BCECPrivateKey(ALGO_NAME_EC, new ECPrivateKeyParameters(new BigInteger(encodedPriKey), domainParameters), null, new ECParameterSpec(domainParameters.getCurve(), domainParameters.getG(), domainParameters.getN(), domainParameters.getH()), BouncyCastleProvider.CONFIGURATION);
    }
    
    public static BCECPrivateKey createECPrivateKey(byte[] encodedPriKey, ECDomainParameters domainParameters) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    	return createECPrivateKey(createECPrivateKeyParameters(new BigInteger(encodedPriKey), domainParameters));
    }
    
    public static BCECPrivateKey createECPrivateKey(ECPrivateKeyParameters priKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    	ECDomainParameters domainParams = priKey.getParameters();
        ECParameterSpec spec = new ECParameterSpec(domainParams.getCurve(), domainParams.getG(), domainParams.getN(), domainParams.getH());
    	return new BCECPrivateKey(ALGO_NAME_EC, priKey, null, spec, BouncyCastleProvider.CONFIGURATION);
    }
    
    public static ECPrivateKeyParameters createECPrivateKeyParameters(byte[] encodedPriKey, ECDomainParameters domainParameters) {
        return new ECPrivateKeyParameters(new BigInteger(encodedPriKey), domainParameters);
    }

    public static ECPrivateKeyParameters createECPrivateKeyParameters(BigInteger d, ECDomainParameters domainParameters) {
        return new ECPrivateKeyParameters(d, domainParameters);
    }
    
    public static BCECPublicKey createECPublicKey(String encodedKey, ECCurve curve, ECDomainParameters domainParameters) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    	return createECPublicKey(Hex.decode(encodedKey), curve, domainParameters);
    }

    public static BCECPublicKey createECPublicKey(byte[] encodedKey, ECCurve curve, ECDomainParameters domainParameters) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        return new BCECPublicKey(ALGO_NAME_EC, new ECPublicKeyParameters(curve.decodePoint(encodedKey), domainParameters), new ECParameterSpec(domainParameters.getCurve(), domainParameters.getG(), domainParameters.getN(), domainParameters.getH()), BouncyCastleProvider.CONFIGURATION);
    }
    
    public static ECPublicKeyParameters createECPublicKeyParameters(BigInteger x, BigInteger y, ECCurve curve, ECDomainParameters domainParameters) {
        byte[] xBytes = x.toByteArray();
        byte[] yBytes = y.toByteArray();
        return createECPublicKeyParameters(fixTo32Bytes(xBytes), fixTo32Bytes(yBytes), curve, domainParameters);
    }

    public static ECPublicKeyParameters createECPublicKeyParameters(String xHex, String yHex, ECCurve curve, ECDomainParameters domainParameters) {
        byte[] xBytes = ByteUtils.fromHexString(xHex);
        byte[] yBytes = ByteUtils.fromHexString(yHex);
        return createECPublicKeyParameters(fixTo32Bytes(xBytes), fixTo32Bytes(yBytes), curve, domainParameters);
    }

    public static ECPublicKeyParameters createECPublicKeyParameters(byte[] encodedPubKey, ECCurve curve, ECDomainParameters domainParameters) {
    	return new ECPublicKeyParameters(curve.decodePoint(encodedPubKey), domainParameters);
    }
    
    public static ECPublicKeyParameters createECPublicKeyParameters(byte[] xBytes, byte[] yBytes, ECCurve curve, ECDomainParameters domainParameters) {
        final byte uncompressedFlag = 0x04;
        byte[] encodedPubKey = new byte[1 + xBytes.length + yBytes.length];
        encodedPubKey[0] = uncompressedFlag;
        System.arraycopy(xBytes, 0, encodedPubKey, 1, xBytes.length);
        System.arraycopy(yBytes, 0, encodedPubKey, 1 + xBytes.length, yBytes.length);
        return new ECPublicKeyParameters(curve.decodePoint(encodedPubKey), domainParameters);
    }

    /**
     * ???ECC???????????????PKCS8??????????????????
     *
     * @param priKey
     * @param pubKey ??????????????????????????????????????????????????????OpenSSL??????????????????
     * @return
     */
    public static byte[] convertECPrivateKeyToPKCS8(ECPrivateKeyParameters priKey, ECPublicKeyParameters pubKey) {
        ECDomainParameters domainParams = priKey.getParameters();
        ECParameterSpec spec = new ECParameterSpec(domainParams.getCurve(), domainParams.getG(), domainParams.getN(), domainParams.getH());
        BCECPublicKey publicKey = null;
        if (pubKey != null) {
            publicKey = new BCECPublicKey(ALGO_NAME_EC, pubKey, spec, BouncyCastleProvider.CONFIGURATION);
        }
        BCECPrivateKey privateKey = new BCECPrivateKey(ALGO_NAME_EC, priKey, publicKey, spec, BouncyCastleProvider.CONFIGURATION);
        return privateKey.getEncoded();
    }

    /**
     * ???PKCS8?????????????????????????????????????????????
     *
     * @param pkcs8Key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     */
    public static BCECPrivateKey convertPKCS8ToECPrivateKey(byte[] pkcs8Key) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        PKCS8EncodedKeySpec peks = new PKCS8EncodedKeySpec(pkcs8Key);
        KeyFactory kf = KeyFactory.getInstance(ALGO_NAME_EC, BouncyCastleProvider.PROVIDER_NAME);
        
        return (BCECPrivateKey) kf.generatePrivate(peks);
    }

    /**
     * ???PKCS8?????????????????????????????????PEM
     *
     * @param encodedKey
     * @return
     * @throws IOException
     */
    public static String convertECPrivateKeyPKCS8ToPEM(byte[] encodedKey) throws IOException {
        return convertEncodedDataToPEM(PEM_STRING_ECPRIVATEKEY, encodedKey);
    }

    /**
     * ???PEM????????????????????????PKCS8???????????????
     *
     * @param pemString
     * @return
     * @throws IOException
     */
    public static byte[] convertECPrivateKeyPEMToPKCS8(String pemString) throws IOException {
        return convertPEMToEncodedData(pemString);
    }

    /**
     * ???ECC???????????????SEC1??????????????????
     * openssl d2i_ECPrivateKey???????????????DER?????????????????????SEC1????????????
     * ????????????????????????????????????????????????????????????openssl???????????????????????????ECC??????.
     * ??????RSA?????????PKCS1?????????ECC??????????????????SEC1
     *
     * @param priKey
     * @param pubKey
     * @return
     * @throws IOException
     */
    public static byte[] convertECPrivateKeyToSEC1(ECPrivateKeyParameters priKey, ECPublicKeyParameters pubKey) throws IOException {
        byte[] pkcs8Bytes = convertECPrivateKeyToPKCS8(priKey, pubKey);
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(pkcs8Bytes);
        ASN1Encodable encodable = pki.parsePrivateKey();
        ASN1Primitive primitive = encodable.toASN1Primitive();
        byte[] sec1Bytes = primitive.getEncoded();
        return sec1Bytes;
    }

    /**
     * ???SEC1?????????????????????????????????PKCS8??????????????????
     *
     * @param sec1Key
     * @return
     * @throws IOException
     */
    public static byte[] convertECPrivateKeySEC1ToPKCS8(byte[] sec1Key) throws IOException {
        /**
         * ??????org.bouncycastle.asn1.pkcs.PrivateKeyInfo??? org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey???????????????
         */
        X962Parameters params = getDomainParametersFromName(SM2Util.JDK_EC_SPEC, false);
        ASN1OctetString privKey = new DEROctetString(sec1Key);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(0)); //?????????
        v.add(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params)); //????????????
        v.add(privKey);
        DERSequence ds = new DERSequence(v);
        return ds.getEncoded(ASN1Encoding.DER);
    }

    /**
     * ???SEC1??????????????????????????????BCECPrivateKey??????
     *
     * @param sec1Key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     * @throws IOException
     */
    public static BCECPrivateKey convertSEC1ToBCECPrivateKey(byte[] sec1Key) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
        PKCS8EncodedKeySpec peks = new PKCS8EncodedKeySpec(convertECPrivateKeySEC1ToPKCS8(sec1Key));
        KeyFactory kf = KeyFactory.getInstance(ALGO_NAME_EC, BouncyCastleProvider.PROVIDER_NAME);
        return (BCECPrivateKey) kf.generatePrivate(peks);
    }

    /**
     * ???SEC1??????????????????????????????ECPrivateKeyParameters??????
     * openssl i2d_ECPrivateKey???????????????DER?????????ecc????????????SEC1??????????????????EC_GROUP?????????????????????
     * ????????????????????????????????????????????????Java????????????????????????openssl?????????ECC??????
     *
     * @param sec1Key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     */
    public static ECPrivateKeyParameters convertSEC1ToECPrivateKey(byte[] sec1Key)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
        BCECPrivateKey privateKey = convertSEC1ToBCECPrivateKey(sec1Key);
        return SM2UtilEx.convertPrivateKey(privateKey);
    }

    /**
     * ???ECC?????????????????????X509??????????????????
     *
     * @param pubKey
     * @return
     */
    public static byte[] convertECPublicKeyToX509(ECPublicKeyParameters pubKey) {
        ECDomainParameters domainParams = pubKey.getParameters();
        ECParameterSpec spec = new ECParameterSpec(domainParams.getCurve(), domainParams.getG(), domainParams.getN(), domainParams.getH());
        BCECPublicKey publicKey = new BCECPublicKey(ALGO_NAME_EC, pubKey, spec, BouncyCastleProvider.CONFIGURATION);
        return publicKey.getEncoded();
    }

    /**
     * ???X509??????????????????????????????????????????
     *
     * @param x509Bytes
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static BCECPublicKey convertX509ToECPublicKey(byte[] x509Bytes) throws NoSuchProviderException,
        NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec eks = new X509EncodedKeySpec(x509Bytes);
        KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return (BCECPublicKey) kf.generatePublic(eks);
    }

    /**
     * ???X509??????????????????????????????PEM
     *
     * @param encodedKey
     * @return
     * @throws IOException
     */
    public static String convertECPublicKeyX509ToPEM(byte[] encodedKey) throws IOException {
        return convertEncodedDataToPEM(PEM_STRING_PUBLIC, encodedKey);
    }

    /**
     * ???PEM?????????????????????X509??????????????????
     *
     * @param pemString
     * @return
     * @throws IOException
     */
    public static byte[] convertECPublicKeyPEMToX509(String pemString) throws IOException {
        return convertPEMToEncodedData(pemString);
    }

    /**
     * copy from BC
     *
     * @param genSpec
     * @return
     */
    public static X9ECParameters getDomainParametersFromGenSpec(ECGenParameterSpec genSpec) {
        return getDomainParametersFromName(genSpec.getName());
    }

    /**
     * copy from BC
     *
     * @param curveName
     * @return
     */
    public static X9ECParameters getDomainParametersFromName(String curveName) {
        X9ECParameters domainParameters;
        try {
            if (curveName.charAt(0) >= '0' && curveName.charAt(0) <= '2') {
                ASN1ObjectIdentifier oidID = new ASN1ObjectIdentifier(curveName);
                domainParameters = ECUtil.getNamedCurveByOid(oidID);
            } else {
                if (curveName.indexOf(' ') > 0) {
                    curveName = curveName.substring(curveName.indexOf(' ') + 1);
                    domainParameters = ECUtil.getNamedCurveByName(curveName);
                } else {
                    domainParameters = ECUtil.getNamedCurveByName(curveName);
                }
            }
        } catch (IllegalArgumentException ex) {
            domainParameters = ECUtil.getNamedCurveByName(curveName);
        }
        return domainParameters;
    }

    /**
     * copy from BC
     *
     * @param ecSpec
     * @param withCompression
     * @return
     */
    public static X962Parameters getDomainParametersFromName(java.security.spec.ECParameterSpec ecSpec,
        boolean withCompression) {
        X962Parameters params;

        if (ecSpec instanceof ECNamedCurveSpec) {
            ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveSpec) ecSpec).getName());
            if (curveOid == null) {
                curveOid = new ASN1ObjectIdentifier(((ECNamedCurveSpec) ecSpec).getName());
            }
            params = new X962Parameters(curveOid);
        } else if (ecSpec == null) {
            params = new X962Parameters(DERNull.INSTANCE);
        } else {
            ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

            X9ECParameters ecP = new X9ECParameters(
                curve,
                EC5Util.convertPoint(curve, ecSpec.getGenerator(), withCompression),
                ecSpec.getOrder(),
                BigInteger.valueOf(ecSpec.getCofactor()),
                ecSpec.getCurve().getSeed());

            params = new X962Parameters(ecP);
        }

        return params;
    }

    private static String convertEncodedDataToPEM(String type, byte[] encodedData) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PemWriter pWrt = new PemWriter(new OutputStreamWriter(bOut));
        try {
            PemObject pemObj = new PemObject(type, encodedData);
            pWrt.writeObject(pemObj);
        } finally {
            pWrt.close();
        }
        return new String(bOut.toByteArray());
    }

    private static byte[] convertPEMToEncodedData(String pemString) throws IOException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(pemString.getBytes());
        PemReader pRdr = new PemReader(new InputStreamReader(bIn));
        try {
            PemObject pemObject = pRdr.readPemObject();
            return pemObject.getContent();
        } finally {
            pRdr.close();
        }
    }
    private static byte[] fixTo32Bytes(byte[] src) {
        final int fixLen = 32;
        if (src.length == fixLen) {
            return src;
        }

        byte[] result = new byte[fixLen];
        if (src.length > fixLen) {
            System.arraycopy(src, src.length - result.length, result, 0, result.length);
        } else {
            System.arraycopy(src, result.length - src.length, result, 0, src.length);
        }
        return result;
    }
}
