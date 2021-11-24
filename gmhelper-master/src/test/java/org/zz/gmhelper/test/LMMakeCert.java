//package org.zz.gmhelper.test;
//
//import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
//import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
//import org.bouncycastle.crypto.params.ECPublicKeyParameters;
//import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
//import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.util.encoders.Base64;
//import org.bouncycastle.util.encoders.Hex;
//import org.zz.gmhelper.BCECUtilEx;
//import org.zz.gmhelper.SM2Util;
//import org.zz.gmhelper.SM2UtilEx;
//import org.zz.gmhelper.cert.SM2CertUtil;
//import org.zz.gmhelper.cert.SM2PrivateKey;
//import org.zz.gmhelper.cert.SM2PublicKey;
//import sun.security.pkcs10.PKCS10;
//import sun.security.x509.X500Name;
//
//import java.io.File;
//import java.io.IOException;
//import java.math.BigInteger;
//import java.nio.ByteBuffer;
//import java.security.*;
//import java.security.cert.X509Certificate;
//import java.security.spec.InvalidKeySpecException;
//import java.util.Calendar;
//import java.util.Date;
//
//public class LMMakeCert {
//
//    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, IOException {
//
//        //GenECCKeyPair();
//
//        String p10 =  "MIH7MIGgAgEAMD4xEjAQBgNVBAoMCWxvbmdtYWlfTzETMBEGA1UECwwKbG9uZ21haV9PVTETMBEGA1UEAwwKbG9uZ21haV9DTjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABJ6qfT2g0jWOpPczwWF";
//        Asn1RequesP10(p10);
//
//    }
//
//    public static void  Asn1RequesP10(String p10) throws NoSuchAlgorithmException, SignatureException, IOException {
//
//
//        PKCS10 pkcs10 = new PKCS10(Base64.decode(p10));
//        X500Name attr = pkcs10.getSubjectName();
//        String alg = pkcs10.getSigAlg();
//        System.err.println("alg = "+ alg);
//
//    }
//
//    //生成密钥对
//    public static SM2PrivateKey GenECCKeyPair()
//    {
//
//        //生成密钥对
//        AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
//        ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
//        ECPublicKeyParameters pubkey = (ECPublicKeyParameters) keyPair.getPublic();
//        System.err.println("Pirvate = "+ Hex.toHexString(priKey.getD().toByteArray()));
//        //ECPublicKeyParameters 转 sm2PubKey
//        ByteBuffer sm2PubKey = ByteBuffer.allocate(65);
//        sm2PubKey.put(Hex.decode("04"));
//
//        sm2PubKey.put(pubkey.getQ().getXCoord().getEncoded());
//        sm2PubKey.put(pubkey.getQ().getYCoord().getEncoded());
//
//        System.err.println("X = "+Hex.toHexString(pubkey.getQ().getXCoord().getEncoded()));
//        System.err.println("Y = "+Hex.toHexString(pubkey.getQ().getYCoord().getEncoded()));
//        try {
//
//
//            BCECPublicKey bcecPublicKey =  BCECUtilEx.createECPublicKey(sm2PubKey.array(),SM2Util.CURVE,SM2Util.DOMAIN_PARAMS);
//            SM2PublicKey sm2SubPub = new SM2PublicKey("EC",
//                    bcecPublicKey);
//            System.err.println("SM2 X ="+sm2SubPub.getQ().getXCoord());
//            System.err.println("SM2 Y ="+sm2SubPub.getQ().getYCoord());
//            byte[] priKeyBCEC = SM2Util.fixToCurveLengthBytes(priKey.getD().toByteArray());
//            BCECPrivateKey bcecPrivateKey = BCECUtilEx.createECPrivateKey(priKeyBCEC,SM2Util.DOMAIN_PARAMS);
//            System.err.println("SM2 priKey = "+Hex.toHexString(bcecPrivateKey.getD().toByteArray()));
//            SM2PrivateKey sm2SubPri = new SM2PrivateKey(bcecPrivateKey,bcecPublicKey);
//
//            return sm2SubPri;
//
//        } catch (NoSuchProviderException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (InvalidKeySpecException e) {
//            e.printStackTrace();
//        }
//
//    }
//
//}
