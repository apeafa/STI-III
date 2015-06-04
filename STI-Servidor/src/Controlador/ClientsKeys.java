/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Controlador;

import Threads.ServerSecurity;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Erbi
 */
public class ClientsKeys {
    HashMap<Integer, byte[]> keys;
    HashMap<Integer, byte[]> privateKeys;
    HashMap<Integer, byte[]> publicKeys;
    ServerSecurity server;
    
    public ClientsKeys() {
        server = new ServerSecurity();
        keys = new HashMap();
        privateKeys = new HashMap();
        publicKeys = new HashMap();
    }
    
    public byte[] getChaveFromID(int ID){
        try {
            byte [] encriptada = (byte[])keys.get(ID);
            System.out.println("Chave encriptada: " + encriptada);
            byte [] desencriptada = server.decrypt(encriptada);
            System.out.println("Chave desencriptada: " + desencriptada);
            return desencriptada;
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | IOException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger("Clients Keys: " + ex);
        }
        return null;
    } 
    
    public void clearAll(){
        keys.clear();
        privateKeys.clear();
        publicKeys.clear();
    }
    
    public void addKey(int ID, byte[] chave){
        byte[] encripted;
        try {
            encripted = server.encrypt(chave);
            keys.put(ID, encripted);
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger("Clients Keys: " + ex);
        }        
    }
    
    public void setPrivateKey(int ID, byte[] chave){
        byte[] encripted;
        try {
            encripted = server.encrypt(chave);
            privateKeys.put(ID, encripted);
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger("Clients Keys: " + ex);
        } 
    }
    
    public void setPublicKey(int ID, byte[] chave){
        byte[] encripted;
        try {
            encripted = server.encrypt(chave);
            publicKeys.put(ID, encripted);  
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger("Clients Keys: " + ex);
        }               
    }
    
    public byte[] getPrivateChaveFromID(int ID){
        try {
            byte [] encriptada = (byte[])privateKeys.get(ID);
            System.out.println("Chave Privada encriptada: " + encriptada);
            byte [] desencriptada = server.decrypt(encriptada);
            System.out.println("Chave Privada desencriptada: " + desencriptada);
            return desencriptada;
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | IOException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger("Clients Keys: " + ex);
        }
        return null;
    } 
    
    public byte[] getPublicChaveFromID(int ID){
        try {
            byte [] encriptada = (byte[])publicKeys.get(ID);
            System.out.println("Chave Publica encriptada: " + encriptada);
            byte [] desencriptada = server.decrypt(encriptada);
            System.out.println("Chave Publica desencriptada: " + desencriptada);
            return desencriptada;
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | IOException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger("Clients Keys: " + ex);
        }
        return null;
    } 
}
