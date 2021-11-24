package org.zz.gmhelper.test;

import com.longmai.asn1.ASN1EncodableVector;
import com.longmai.asn1.ASN1Integer;
import com.longmai.asn1.ASN1ObjectIdentifier;
import com.longmai.asn1.DERSequence;
import com.longmai.asn1.x500.X500Name;
import com.longmai.asn1.x509.AlgorithmIdentifier;
import com.longmai.mtoken.GM3000Jna;
import com.longmai.mtoken.GM3000Lib;
import com.longmai.operator.ContentSigner;
import com.longmai.pkcs.PKCS10CertificationRequest;
import com.longmai.pkcs.sm2.SM2PKCS10CertificationRequestBuilder;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Cipher;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.SM4Util;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.naming.OperationNotSupportedException;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.rmi.ServerError;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Struct;
import java.util.Arrays;
import java.util.Collections;
import java.util.Random;

import com.longmai.pkcs.*;
import org.zz.gmhelper.cert.CertSNAllocator;
import org.zz.gmhelper.cert.FileSNAllocator;
import org.zz.gmhelper.cert.SM2X509CertMaker;
import org.zz.gmhelper.cert.exception.InvalidX500NameException;
import org.zz.gmhelper.test.util.FileUtil;

public class LM_ImportCertInfo {
    private static GM3000Lib skf = GM3000Jna.getInstance();
    public static void main(String[] args) throws Exception {

                byte[] pub = LMUSBKey.exportKeyPublic(1); //导出Key的公钥
              String str=   requestPKCS10();

        SM2X509CertMaker certMaker = buildCertMaker();
        X509Certificate cert = certMaker.makeCertificate(false,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.dataEncipherment), Base64.decode(str));
        FileUtil.writeFile("ys1.cer", cert.getEncoded());

    }



    private static  byte[] pBlobPukey = new byte[132];
    private static int[] con = new int[1];

    private static  String requestPKCS10() throws IOException {

        int min=10;
        int max=100000;
        Random random = new Random(1000);
        int num = random.nextInt();
        int retn = skf.SKF_CreateContainer(LMUSBKey.getApp(),getNumSmallLetter(30),con);
        retn = skf.SKF_GenECCKeyPair(con[0],0x00020100,pBlobPukey);
        System.out.println("pBlob = " +Hex.toHexString(pBlobPukey));
        System.err.println("SKF_GenECCKeyPair = "+retn);


        PKCS10CertificationRequestBuilder pkcs10Builder = null;
        try {
            pkcs10Builder = new SM2PKCS10CertificationRequestBuilder(new X500Name("CN=Longmai CA,E=service@longmai.com.cm,OU=研发部,O=北京世纪龙脉科技有限公司,ST=北京市,L=北京市,C=CN"), pBlobPukey);
        } catch (IOException e) {
            e.printStackTrace();
        }
        PKCS10CertificationRequest request = pkcs10Builder.build(new ContentSigner() {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier(){
                return new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.156.10197.1.501"));
            }

            @Override
            public OutputStream getOutputStream() {
                return bos;
            }

            @Override
            public byte[] getSignature() {
                byte[] buff = bos.toByteArray();
                int[] phHash = new int[32];
               byte[] pucID = "1234567812345678".getBytes();
                int result = skf.SKF_DigestInit(LMUSBKey.getDev(),GM3000Lib.SGD_SM3,pBlobPukey,pucID,pucID.length,phHash);
                if (result!=0)
                {
                    System.err.println("SKF_DigestInit = "+result);
                    return null ;
                }
                byte[] pbHashData =new byte[32];
                int[] pulHashLen = new int[1];
                pulHashLen[0] = pbHashData.length;
                result = skf.SKF_Digest(phHash[0],buff,buff.length,pbHashData,pulHashLen);
                if (result!=0)
                {
                    System.err.println("SKF_Digest = "+result);
                    return null ;
                }
                System.out.println("pbHashData = " +Hex.toHexString(pbHashData));

                byte[] pSignature = new byte[128];
                result = skf.SKF_ECCSignData(con[0],pbHashData,pbHashData.length,pSignature);
                if (result!=0)
                {
                    System.err.println("SKF_ECCSignData = "+result);
                    return null ;
                }

                ByteBuffer b = ByteBuffer.wrap(pSignature,0,128);
                byte[] rr = new byte[64];
                b.get(rr);

                byte[] ss = new byte[64];
                b.get(ss);


                ASN1Integer r = new ASN1Integer(new BigInteger(rr));
                ASN1Integer s = new ASN1Integer(new BigInteger(ss));
                ASN1EncodableVector whole = new ASN1EncodableVector();
                whole.add(r);
                whole.add(s);
                DERSequence der = new DERSequence(whole);
                try {
                    return der.getEncoded();
                } catch (IOException e) {
                    e.printStackTrace();
                    return null;
                }
            }

        });
        System.out.println(Hex.toHexString(request.getEncoded()));
        System.out.println("PKCS10 = "+Base64.toBase64String(request.getEncoded()));
        return Base64.toBase64String(request.getEncoded());
    }

    public static String getNumSmallLetter(int size){
        StringBuffer buffer = new StringBuffer();
        Random random = new Random();
        for(int i=0; i<size;i++){
            if(random.nextInt(2) % 2 == 0){//字母
                buffer.append((char) (random.nextInt(27) + 'a'));
            }else{//数字
                buffer.append(random.nextInt(10));
            }
        }
        return buffer.toString();
    }

    private static byte[] intToByte(int val) {
        byte[] b = new byte[4];
        b[0] = (byte) (val & 0xff);
        b[1] = (byte) ((val >> 8) & 0xff);
        b[2] = (byte) ((val >> 16) & 0xff);
        b[3] = (byte) ((val >> 24) & 0xff);

        return b;
    }


    public static SM2X509CertMaker buildCertMaker() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidX500NameException {
        org.bouncycastle.asn1.x500.X500Name issuerName = buildRootCADN();
        KeyPair issKP = SM2Util.generateKeyPair();
        long certExpire = 20L * 365 * 24 * 60 * 60 * 1000; // 20年
        CertSNAllocator snAllocator = new FileSNAllocator(); // 实际应用中可能需要使用数据库来维护证书序列号
        return new SM2X509CertMaker(issKP, certExpire, issuerName, snAllocator);
    }

    public static org.bouncycastle.asn1.x500.X500Name buildRootCADN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, "LM Root CA");
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        return builder.build();
    }
}
