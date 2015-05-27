/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Security;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Erbi
 */
public final class MD5 implements Serializable{
    BigInteger bi;
    
    public MD5(String message, int verbose){
        generateMD5(message, verbose);
    }
    
    public void generateMD5(String message, int verbose){
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(message.getBytes(), 0, message.length());
            bi = new BigInteger(1, md.digest());
            
            if(verbose != 1){
                System.out.println("[MD5 HASH CRIADA] = " + bi);
            }
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Erro ao criar MD5");
        }        
    }
    
    public BigInteger getMessageDigest(){
        return bi;
    }
}
