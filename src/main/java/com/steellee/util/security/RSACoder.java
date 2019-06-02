package com.steellee.util.security;

import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @Description:
 * @author: Hyman
 * @date: 2019/06/02 18:08
 * @version： 1.0.0
 */
public class RSACoder {

    private final static String KEY_ALGORITHM = "RSA";
    private KeyPair keyPair;

    public RSACoder() throws Exception {
        this.keyPair = initKeyPair();
    }

    public byte[] encryptByPublicKey(byte[] plaintext, byte[] key) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext);
    }

    public byte[] encryptByPrivateKey(byte[] plaintext, byte[] key) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(plaintext);
    }

    public byte[] decryptByPublicKey(byte[] ciphertext, byte[] key) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(ciphertext);
    }

    public byte[] decryptByPrivateKey(byte[] ciphertext, byte[] key) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(ciphertext);
    }

    private KeyPair initKeyPair() throws Exception {
        // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        // 初始化密钥对生成器，密钥大小为1024位
        keyPairGen.initialize(1024);
        // 生成一个密钥对
        return keyPairGen.genKeyPair();
    }

    public static void main(String[] args) throws Exception {
        String msg = "Hello World!";
        RSACoder coder = new RSACoder();
        // 私钥加密，公钥解密
        byte[] ciphertext = coder.encryptByPrivateKey(msg.getBytes("UTF8"), coder.keyPair.getPrivate().getEncoded());
        byte[] plaintext = coder.decryptByPublicKey(ciphertext, coder.keyPair.getPublic().getEncoded());

        // 公钥加密，私钥解密
        byte[] ciphertext2 = coder.encryptByPublicKey(msg.getBytes(), coder.keyPair.getPublic().getEncoded());
        byte[] plaintext2 = coder.decryptByPrivateKey(ciphertext2, coder.keyPair.getPrivate().getEncoded());

        System.out.println("原文：" + msg);
        System.out.println("公钥：" + Base64.encodeBase64URLSafeString(coder.keyPair.getPublic().getEncoded()));
        System.out.println("私钥：" + Base64.encodeBase64URLSafeString(coder.keyPair.getPrivate().getEncoded()));

        System.out.println("============== 私钥加密，公钥解密 ==============");
        System.out.println("密文：" + Base64.encodeBase64URLSafeString(ciphertext));
        System.out.println("明文：" + new String(plaintext));

        System.out.println("============== 公钥加密，私钥解密 ==============");
        System.out.println("密文：" + Base64.encodeBase64URLSafeString(ciphertext2));
        System.out.println("明文：" + new String(plaintext2));
    }

}
