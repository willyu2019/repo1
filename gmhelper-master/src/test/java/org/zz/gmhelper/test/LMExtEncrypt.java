package org.zz.gmhelper.test;

import com.longmai.mtoken.GM3000Jna;
import com.longmai.mtoken.GM3000Lib;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Cipher;
import org.zz.gmhelper.SM2Util;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class LMExtEncrypt {

    private static GM3000Lib skf = GM3000Jna.getInstance();
    private static int rtn;
    private static int[] phDev = new int[1];
    private static byte[] pubKey = new byte[64];
    private static String szPIN = "12345678"; //upin
    private static int[] phContainer = new int[1];
    private static int[] phApplication = new int[1];


    public static void main(String[] args) {
        String szName = null;
        List<String> devList = new ArrayList<String>(); // dev Name 锟借备锟斤拷
        List<String> appList = new ArrayList<String>(); // Application Name 应锟斤拷锟斤拷
        List<String> conList = new ArrayList<String>(); // containerList Name
        int[] pulSize = new int[1];
        rtn = skf.SKF_EnumDev(1, devList, pulSize); // find token
        if (rtn != 0) {
            System.out.println("find token Error,errorCode =  " + rtn + "");
            return;
        }
        for (int i = 0; i < pulSize.length; i++) {
            szName = devList.get(i).toString(); // get token ID
            System.out.println("mtoken szName = " + szName);

            //
            rtn = skf.SKF_ConnectDev(szName, phDev); // connect token
            if (rtn != 0) {
                System.out.println("connect token Error,errorCode =  " + rtn
                        + "");
                return;
            }


            // 枚锟斤拷应锟斤拷
            rtn = skf.SKF_EnumApplication(phDev[0], appList, pulSize);
            if (rtn != 0) {
                System.out.println("SKF_EnumApplication Error,errorCode =  "
                        + rtn);
                return;
            }
            for (int j = 0; j < appList.size(); j++) {
                System.out.println("AppName = " + appList.get(j) + "");
            }

            rtn = skf.SKF_OpenApplication(phDev[0], appList.get(0),
                    phApplication);
            if (rtn != 0) {
                System.out.println("SKF_OpenApplication Error,errorCode =  "
                        + rtn);
                return;
            }
            // Login
            int ulPINType = 1; // 1 userpin ,2 so pin

            int[] pulRetryCount = new int[1];

            rtn = skf.SKF_VerifyPIN(phApplication[0], ulPINType, szPIN,
                    pulRetryCount);
            if (rtn != 0) {
                System.out.println("SKF_VerifyPIN Error,errorCode =  " + rtn);
                System.out.println("TryCount = " + pulRetryCount[0] + "");
                return;
            } else {
                System.out.println("user Login successfully");
            }


            rtn = skf.SKF_EnumContainer(phApplication[0], conList, pulSize);
            if (rtn != 0) {
                System.out.println("SKF_EnumContainer Error,errorCode =  "
                        + rtn);
                return;
            }
            for (int j = 0; j < conList.size(); j++) {
                //System.out.println("ConName = " + conList.get(j) + "");
            }

            rtn = skf.SKF_OpenContainer(phApplication[0], conList.get(0),
                    phContainer);
            if (rtn != 0) {
                System.out.println("SKF_OpenContainer Error,errorCode =  "
                        + rtn);
                return;
            }
            System.out.println("open Con  = " + conList.get(0));


            byte[] pbCert = new byte[4096];
            int[] pulCertLen = new int[1];
            pulCertLen[0] = 2048;
            byte[] pbBlob = new byte[4096];
            int[] publBlobLen = new int[1];
            publBlobLen[0] = 4096;
            rtn = skf.SKF_ExportPublicKey(phContainer[0], 0, pbBlob,
                    publBlobLen);
            if (rtn != 0) {
                System.out.println("SKF_ExportPublicKey Error,errorCode =  "
                        + rtn);
                return;
            }
            System.out.println(publBlobLen[0]);
//            System.out.println("publickey = "
//                    + Hex.toHexString(Arrays.copyOf(pbBlob, publBlobLen[0])));
            byte[] blob = new byte[publBlobLen[0]];
            System.arraycopy(pbBlob, 0, blob, 0, publBlobLen[0]);
            byte[] xPub = new byte[32];
            byte[] yPub = new byte[32];
            System.arraycopy(blob, 36, xPub, 0, 32);
            System.arraycopy(blob, 100, yPub, 0, 32);

            System.arraycopy(xPub, 0, pubKey, 0, 32);
            System.arraycopy(yPub, 0, pubKey, 32, 32);
            String xHex = Hex.toHexString(xPub);
            String yHex = Hex.toHexString(yPub);
//            System.err.println("XuKey :" + xHex);
//            System.err.println("YuKey :" + yHex);
            byte[] indata = SM2Encrypt(xHex,yHex);
            System.err.println("indata"+Hex.toHexString(indata));
            byte[] pboutData = new byte[2048];
            int[] pbDataLen1 = new int[1];
            pbDataLen1[0] = 4096;
            rtn = skf.SKF_ECCPrvKeyDecrypt(phContainer[0], indata, pboutData, pbDataLen1);
            if (rtn != 0) {
                System.err.println("SKF_ECCPrvKeyDecrypt" + rtn);
                return;
            }
            System.out.println("SKF_ECCPrvKeyDecrypt = " + new String(Arrays.copyOf(pboutData, pbDataLen1[0])));

        }
    }

        //sm4加密会话密钥
        public static byte[] SM2Encrypt(String xHex,String yHex)
        {
            ByteBuffer buff = ByteBuffer.allocate(196);
            byte[] sessionKey = "12345678123456781234567812345678".getBytes();

            ECPublicKeyParameters srcpubKey = BCECUtil.createECPublicKeyParameters(xHex, yHex, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);
            try {
                byte[] CipherBlob = SM2Util.encrypt(srcpubKey,sessionKey);
                SM2Cipher cip =  SM2Util.parseSM2Cipher(CipherBlob);
                byte[] c1 = cip.getC1();
                byte[] c2 = cip.getC2();
                byte[] c3 = cip.getC3();

                buff.put(new byte[32]);
                buff.put(Arrays.copyOfRange(c1,1,33));
                buff.put(new byte[32]);
                buff.put(Arrays.copyOfRange(c1, 33, 65));
                buff.put(SM2Util.fixToCurveLengthBytes(c3));
                buff.put(Hex.decode("20000000"));
                buff.put(c2);
                System.err.println("data = "+Hex.toHexString(buff.array()));

            } catch (InvalidCipherTextException e) {
                e.printStackTrace();
            }
            return  buff.array();
        }


    public static byte[] decodeValue(ByteBuffer bytes) {
        int len = bytes.limit() - bytes.position();
        byte[] bytes1 = new byte[len];
        bytes.get(bytes1);
        return bytes1;
    }

    }


