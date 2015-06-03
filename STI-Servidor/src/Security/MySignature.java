/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Erbi
 */
public class MySignature{
    byte[] myPrivateKey;
    
    public MySignature(){   
    }   
    
    public byte[] generatePrivate(){
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(1024, random);
            KeyPair pair = keyGen.generateKeyPair();
            myPrivateKey = pair.getPrivate().getEncoded();
            return pair.getPublic().getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            System.out.println("[MySignatureClass]: " + ex);            
        }
        return null;
    }
    
    public void setPrivateKey(byte[] privatekey){
        myPrivateKey = privatekey;
    }
    
    public byte[] getPrivate(){
        return myPrivateKey;
    }
}
