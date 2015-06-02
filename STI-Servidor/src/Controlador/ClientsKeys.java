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

    public ClientsKeys() {
        keys = new HashMap();
    }
    
    public byte[] getChaveFromID(int ID){
        return (byte[])keys.get(ID);
    } 
    
    public void addKey(int ID, byte[] chave){
        keys.put(ID, chave);
    }
}
