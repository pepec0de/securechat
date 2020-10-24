package com.pepe.apps.chatroom.room.encrypted;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
/**
 *
 * @author Pepe
 */
public class utils {
    
    private final String aesKey = "ËâÒÐÆÞÚÐÎÕÂáÌáÈ×ÌÔ××ÕËÞè×ÜÈÔÞèÚÐÂìåÑÔì×ßÂÞåÍÖÓ×ØÝÑÅåËÑËÔÑÔÇÝÂÝÖÉãèÓîÚÞÓÉßßÎãÖÐÊßÊÅÒåÂÒÈíàÎËáØÛÈÕÂæÚÎÓÜÈÌØÑØçäÏÚËÜÑÔØÛÌÙÎã";
    private final String obsKey = "fpioajeofnasjndajsduojeuojaseuthaypiawpwairepiowjgawegjamfdsajncnvnueurawjeruhejadjnajdsnfjneugnashgrjakfjaurgyahgasgde";
    private Base64.Encoder encoder;
    private Base64.Decoder decoder;
    
    public utils() {
        encoder = Base64.getEncoder();
        decoder = Base64.getDecoder();
        System.out.println(encryptMessageToSend("hola"));
        System.out.println(decryptMessageReceived("w5TDgcOXw5bCuMOPwpfDgcOUw4DCmsK0w5fCuMOKw5bCmsKjw4nDrMKnwqvCosKy"));
    }
    
    private String encryptMessageToSend(String message) {
        // 1. OBFUSCATE MESSAGE
        // 2. -> ENCRYPT BASE64
        // 3. -> ENCRYPT AES_B64 w/ aesKey        
        //return encryptAES(true, encryptBase64(obfuscate(message)));
        
        // 1. ENCRYPT AES_B64 w/ aesKey
        // 2. -> OBFUSCATE
        // 3. -> ENCRYPT BASE64
        return encryptBase64(obfuscate(encryptAES(true, message)));
    }

    private String decryptMessageReceived(String message) {
        // 1. DECRYPT AES_B64 w/ aesKey
        // 2. -> DECRYPT BASE64
        // 3. -> UNOBFUSCATE FINAL STR
        //return unobfuscate(decryptBase64(decryptAES(true, message)));
        
        // 1. DECRYPT BASE64
        // 2. -> UNOBFUSCATE
        // 3. -> DECRYPT AES_B64 w/ aesKey
        return decryptAES(true, unobfuscate(decryptBase64(message)));
    }
    // CRYPTO UTILS
    private String obfuscate(String s) {
        char[] result = new char[s.length()];
        for (int i = 0; i < s.length(); i++) {
            result[i] = (char) (s.charAt(i) + obsKey.charAt(i % obsKey.length()));
        }
        return new String(result);
    }

    private String unobfuscate(String s) {
        char[] result = new char[s.length()];
        for (int i = 0; i < s.length(); i++) {
            result[i] = (char) (s.charAt(i) - obsKey.charAt(i % obsKey.length()));
        }
        return new String(result);
    }
    
    // BASE 64
    
    // STR -> ENCRYPTED STR
    private String encryptBase64(String s) { 
        try {       
            return new String(encoder.encode(s.getBytes("UTF-8")));
        } catch(UnsupportedEncodingException ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    // ENCRYPTED STR -> DECRYPTED STR
    private String decryptBase64(String s) { 
        return new String(decoder.decode(s));        
    }
    
    // BYTE[] -> ENCRYPTED STR
    private String encryptBase64Bytes(byte[] binaryData) { 
        return new String(encoder.encode(binaryData));
    }
    
    // ENCRYPTED STR -> DECRYPTED BYTE[]
    private byte[] decryptBase64String(String s) { 
        return decoder.decode(s);
    }
    
    // AES
    
    private String encryptAES(boolean isBase64, String s) {
        try {
            // SET KEY mKey
            byte[] key = unobfuscate(aesKey).trim().getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            // ENCRYPT str
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");        
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            if (isBase64) {
                return encryptBase64Bytes(cipher.doFinal(s.getBytes("UTF-8")));                
            } else {
                return new String(cipher.doFinal(s.getBytes("UTF-8")));
            }
            
        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    private String decryptAES(boolean isBase64, String s) {
        try {
            // SET KEY mKey
            byte[] key = unobfuscate(aesKey).trim().getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16); // DEF : 16
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            // DECRYPT str
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            if(isBase64) {
                return new String(cipher.doFinal(decryptBase64String(s)));
            } else {
                return new String(cipher.doFinal(s.getBytes("UTF-8")));
            }
        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
        private String encryptAESTest(boolean isBase64, String s) {
        try {
            // SET KEY mKey
            byte[] key = unobfuscate(aesKey).trim().getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("AES");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            // ENCRYPT str
            Cipher cipher = Cipher.getInstance("AES");        
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            if (isBase64) {
                return encryptBase64Bytes(cipher.doFinal(s.getBytes("UTF-8")));                
            } else {
                return new String(cipher.doFinal(s.getBytes("UTF-8")));
            }
            
        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    private String decryptAESTest(boolean isBase64, String s) {
        try {
            // SET KEY mKey
            byte[] key = unobfuscate(aesKey).trim().getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16); // DEF : 16
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            // DECRYPT str
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            if(isBase64) {
                return new String(cipher.doFinal(decryptBase64String(s)));
            } else {
                return new String(cipher.doFinal(s.getBytes("UTF-8")));
            }
        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    public static void main(String[] args) {
        new utils();
    }
}
