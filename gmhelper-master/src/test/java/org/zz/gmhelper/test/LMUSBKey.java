package org.zz.gmhelper.test;

import com.longmai.mtoken.GM3000Jna;
import com.longmai.mtoken.GM3000Lib;
import org.bouncycastle.util.encoders.Hex;

import java.util.ArrayList;
import java.util.List;

public class LMUSBKey {


    private static GM3000Lib skf = GM3000Jna.getInstance();
    private static int rtn;
    private static int[] phDev = new int[1];
    private static byte[] pubKey = new byte[64];
    private static  String szPIN = "12345678"; //upin
    private  static int[] phContainer = new int[1];
    private static   int[] phApplication = new int[1];

    public static byte[] exportKeyPublic(int flag) {
        String szName = null;
        List<String> devList = new ArrayList<String>(); // dev Name 锟借备锟斤拷
        List<String> appList = new ArrayList<String>(); // Application Name 应锟斤拷锟斤拷
        List<String> conList = new ArrayList<String>(); // containerList Name
        int[] pulSize = new int[1];


        rtn = skf.SKF_EnumDev(1, devList, pulSize); // find token
        if (rtn != 0) {
            System.out.println("find token Error,errorCode =  " + rtn + "");
            return null;
        }
        for (int i = 0; i < pulSize.length; i++) {
            szName = devList.get(i).toString(); // get token ID
            System.out.println("mtoken szName = " + szName);

            //
            rtn = skf.SKF_ConnectDev(szName, phDev); // connect token
            if (rtn != 0) {
                System.out.println("connect token Error,errorCode =  " + rtn
                        + "");
                return null;
            }


            // 枚锟斤拷应锟斤拷
            rtn = skf.SKF_EnumApplication(phDev[0], appList, pulSize);
            if (rtn != 0) {
                System.out.println("SKF_EnumApplication Error,errorCode =  "
                        + rtn);
                return null;
            }
            for (int j = 0; j < appList.size(); j++) {
                System.out.println("AppName = " + appList.get(j) + "");
            }

            rtn = skf.SKF_OpenApplication(phDev[0], appList.get(0),
                    phApplication);
            if (rtn != 0) {
                System.out.println("SKF_OpenApplication Error,errorCode =  "
                        + rtn);
                return null;
            }
            // Login
            int ulPINType = 1; // 1 userpin ,2 so pin

            int[] pulRetryCount = new int[1];

            rtn = skf.SKF_VerifyPIN(phApplication[0], ulPINType,szPIN ,
                    pulRetryCount);
            if (rtn != 0) {
                System.out.println("SKF_VerifyPIN Error,errorCode =  " + rtn);
                System.out.println("TryCount = " + pulRetryCount[0] + "");
                return null;
            } else {
                System.out.println("user Login successfully");
            }


            rtn = skf.SKF_EnumContainer(phApplication[0], conList, pulSize);
            if (rtn != 0) {
                System.out.println("SKF_EnumContainer Error,errorCode =  "
                        + rtn);
                return null;
            }
            for (int j = 0; j < conList.size(); j++) {
                //System.out.println("ConName = " + conList.get(j) + "");
            }

            rtn = skf.SKF_OpenContainer(phApplication[0], conList.get(0),
                    phContainer);
            if (rtn != 0) {
                System.out.println("SKF_OpenContainer Error,errorCode =  "
                        + rtn);
                return null;
            }
            System.out.println("open Con  = "+conList.get(0));

            byte[] pblob = new byte[132];
            int SGD_SM2_1 = 0x00020100;	//椭圆曲线签名算法
            rtn = skf.SKF_GenECCKeyPair(phContainer[0],SGD_SM2_1,pblob);
            if (rtn != 0) {
                System.out.println("SKF_GenECCKeyPair Error,errorCode =  "
                        + rtn);
                return null;
            }
            else
            {
                System.out.println("SKF_GenECCKeyPair success");
            }



            byte[] pbCert = new byte[4096];
            int[] pulCertLen = new int[1];
            pulCertLen[0] = 2048;
            byte[] pbBlob = new byte[4096];
            int[] publBlobLen = new int[1];
            publBlobLen[0] = 4096;

            flag = 1; // 1 锟斤拷签锟斤拷证锟斤拷 锟斤拷0锟角斤拷锟斤拷证锟斤拷

            rtn = skf.SKF_ExportPublicKey(phContainer[0], flag, pbBlob,
                    publBlobLen);
            if (rtn != 0) {
                System.out.println("SKF_ExportPublicKey Error,errorCode =  "
                        + rtn);
                return null;
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
        }
        return pubKey;
    }
    public static int getCon()
    {
        return  phContainer[0];

    }
    public static int getDev()
    {
        return  phDev[0];

    }

    public static int getApp()
    {
        return  phApplication[0];

    }
}
