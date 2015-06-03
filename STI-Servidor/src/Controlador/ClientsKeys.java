/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Controlador;

import java.util.HashMap;

/**
 *
 * @author Erbi
 */
public class ClientsKeys {
    HashMap<Integer, byte[]> keys;
    HashMap<Integer, byte[]> privateKeys;
    HashMap<Integer, byte[]> publicKeys;
    
    public ClientsKeys() {
        keys = new HashMap();
        privateKeys = new HashMap();
        publicKeys = new HashMap();
    }
    
    public byte[] getChaveFromID(int ID){
        return (byte[])keys.get(ID);
    } 
    
    public void clearAll(){
        keys.clear();
        privateKeys.clear();
        publicKeys.clear();
    }
    
    public void addKey(int ID, byte[] chave){
        keys.put(ID, chave);
    }
    
    public void setPrivateKey(int ID, byte[] chave){
        privateKeys.put(ID, chave);        
    }
    
    public void setPublicKey(int ID, byte[] chave){
        publicKeys.put(ID, chave);        
    }
    
    public byte[] getPrivateChaveFromID(int ID){
        return (byte[])privateKeys.get(ID);
    } 
    
    public byte[] getPublicChaveFromID(int ID){
        return (byte[])publicKeys.get(ID);
    } 
}
