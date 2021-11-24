
package org.zz.gmhelper.test;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.BCECUtilEx;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.cert.CommonUtil;
import org.zz.gmhelper.cert.SM2PrivateKey;
import org.zz.gmhelper.cert.SM2PublicKey;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * 生成证书请求文件（PCSK10）
 *
 * <a ref="https://tools.ietf.org/html/rfc2986">rfc2986</a>
 *
 * @author 权观宇
 * @since 2019-11-26 16:25:03
 */
public class P10List {

    /**
     * @return 证书请求识别名称 （也就是证书的Subject）
     */
    public static X500Name dn() {
        return new X500NameBuilder()
                // 国家代码
                .addRDN(BCStyle.C, "CN")
                // 组织
                .addRDN(BCStyle.O, "HZNU")
                // 省份
                .addRDN(BCStyle.ST, "Zhejiang")
                // 地区
                .addRDN(BCStyle.L, "Hangzhou")
                // 通用名称
                .addRDN(BCStyle.CN, "Cluster Node Certificate")
                .build();
    }

    /**
     * 生成SM2密钥对的证书请求（pkcs10格式）
     * <p>
     * 参考资自 {@link //org.bouncycastle.cert.test.PKCS10Test#generationTest}
     *
     * <a ref="https://github.com/bcgit/bc-java/blob/master/pkix/src/test/java/org/bouncycastle/cert/test/BcPKCS10Test.java">BcPKCS10Test.java</a>
     *
     * @param kp      SM2密钥对
     * @param subject 证书使用者
     * @return 证书请求
     * @throws OperatorCreationException
     */
    public static PKCS10CertificationRequest generate(KeyPair kp, X500Name subject) throws OperatorCreationException {
        // 构造请求信息，主要是由“实体”的DN和公钥构成
        PKCS10CertificationRequestBuilder requestBuilder =
                new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
        // 使用“实体”私钥对请求的信息进行签名,然后组装成ASN.1对象
        return requestBuilder.build(
                new JcaContentSignerBuilder("SM3withSM2")
                        .setProvider("BC")
                        .build(kp.getPrivate()));

    }


    /**
     * 验证PKCS10
     *
     * @param p10Base64 Base64 编码PKCS10 DER
     * @return true - 通过验证；false - 签名值不对
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws OperatorCreationException
     * @throws PKCSException
     */
    public static boolean verifyP10(String p10Base64) throws IOException, NoSuchAlgorithmException, InvalidKeyException, OperatorCreationException, PKCSException {
        // 解码
        byte[] p10Der = Base64.decode(p10Base64);
        JcaPKCS10CertificationRequest req = new JcaPKCS10CertificationRequest(p10Der).setProvider("BC");
        // 取出证书请求中的公钥
        PublicKey publicKey = req.getPublicKey();
        // 签名验证
        return req.isSignatureValid(
                new JcaContentVerifierProviderBuilder()
                        .setProvider("BC")
                        .build(publicKey));
    }

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        boolean result = verifyP10("MIICfzCCAWkCAQAwPjESMBAGA1UECgwJbG9uZ21haV9PMRMwEQYDVQQLDApsb25nbWFpX09VMRMwEQYDVQQDDApsb25nbWFpX0NOMIIBIDALBgkqhkiG9w0BAQEDggEPADCCAQoCggEBAMq6eBk54edfECRDrtNCEOrNn63b/I+6LFLv5/eOTYX1PxYivbE65yQRB0Oy6MNbA9lPRDF/K7xCtRQbp6ze9lLxnzNoWJqnvGjQQU/OPYumPWBQJ0H7sf8Tdbe3NsuenzDUEd4KCf1g5kBaNy9sX6Ka70m+XSgvAjomCDXa/TSChiJWBI6BkB8n8fK5tMr+cK6YuL2lD5AbpoLMn0k4DeSpq4NLgP39jT5pCv5T/Nhb0Co60s6hyylicZOpfLL1e7YvArhKISHEXxvcb9aBLwz87Q+U2FtEH4STSmIjuLzGhc4IvqyqAZvGP+1n3CjzSRGoa2NcfLeIu0PnRud1ekUCAwEAAaAAMAsGCSqGSIb3DQEBBQOCAQEASp/g3s6Av5A3ZcgWhaNPLQm09jVLxipK1KVO4pLznijVDT3SCWB3U67eENP3NfanHU/N15zUOeZ8n0WnK/j80Y1pSJjJFgv5VbFSbzl18uZPnM9z7h8OU74MUOkwbR6DCtbNk/yG5Bu90K6KpsDbdMg/C/uxgQ1qN5ftg9gWMHPWyxG3Q+kSK1EsmVpTqXkzS9drmX9XA4YWft1WC/4m72jvyK4QjbneNn5liQGWBlVnqruTyH92uOxfU3AAXtDQdO+PyWypQ7qW30MTDC6RAUCEnCLBBQJUqLVFCPDRIcMsFAlFpBBek99TKJwbRQublCpESCT8fvDUqzSPJOPpSQ==");
        System.out.println("p10 result ="+result);

        // 1. 生成SM2密钥对
//        byte[] inPubkey =    LMUSBKey.exportKeyPublic(1);
//        byte[] xHex = new byte[32];
//        byte[] yHex = new byte[32];
//        System.arraycopy(inPubkey,0,xHex,0,32);
//        System.arraycopy(inPubkey,32,yHex,0,32);
//        ECPublicKeyParameters srcpubKey = BCECUtil.createECPublicKeyParameters(xHex, yHex, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);
        AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();

        ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();
        SM2PublicKey pubKeysm2 = ECPublicKeyParametersToSM2PublicKey(pubKey);
       SM2PrivateKey priKeysm2 =  ECPrivateKeyParametersToSM2PrivateKey(priKey,ECPublicKeyParametersToSM2PublicKey(pubKey));
       // KeyPair kp1 = SM2Util.generateKeyPair();
        // 2. 构造使用者DN
        X500Name subject = dn();
        // 3. 生成证书请求（P10），然后进行Base64编码
        PKCS10CertificationRequest  req = CommonUtil.createCSR(subject,pubKeysm2,priKeysm2,"SM3WITHSM2");
        //PKCS10CertificationRequest req = generate(kp1, subject);
        String base64 = Base64.toBase64String(req.getEncoded());
        System.out.printf("证书请求P10：\n\t%s\n", base64);

        boolean pass = verifyP10(base64);
        System.out.println("PKCS10 验证：" + pass);
    }
    public static SM2PublicKey ECPublicKeyParametersToSM2PublicKey(ECPublicKeyParameters pubkey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        ByteBuffer sm2PubKey = ByteBuffer.allocate(65);
        sm2PubKey.put(Hex.decode("04"));
        sm2PubKey.put(pubkey.getQ().getXCoord().getEncoded());

        sm2PubKey.put(pubkey.getQ().getYCoord().getEncoded());
        System.err.println("x = "+Hex.toHexString(pubkey.getQ().getXCoord().getEncoded()));
        System.err.println("Y = "+Hex.toHexString(pubkey.getQ().getYCoord().getEncoded()));
        BCECPublicKey bcecPublicKey =  BCECUtilEx.createECPublicKey(sm2PubKey.array(),SM2Util.CURVE,SM2Util.DOMAIN_PARAMS);
        SM2PublicKey sm2SubPub = new SM2PublicKey("EC",
                bcecPublicKey);
        return sm2SubPub;

    }
    public static SM2PrivateKey ECPrivateKeyParametersToSM2PrivateKey(ECPrivateKeyParameters priKey,SM2PublicKey pubKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

            byte[] priKeyBCEC = SM2Util.fixToCurveLengthBytes(priKey.getD().toByteArray());
            BCECPrivateKey bcecPrivateKey = BCECUtilEx.createECPrivateKey(priKeyBCEC,SM2Util.DOMAIN_PARAMS);
            System.err.println("SM2 priKey = "+Hex.toHexString(bcecPrivateKey.getD().toByteArray()));
            SM2PrivateKey sm2SubPri = new SM2PrivateKey(bcecPrivateKey,pubKey);
            return sm2SubPri;

    }


}