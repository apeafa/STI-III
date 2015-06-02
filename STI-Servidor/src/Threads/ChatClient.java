package Threads;


import Controlador.Controlador;
import Controlador.Mensagem;
import java.net.*;
import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;


public class ChatClient implements Runnable
{  
    private Socket socket              = null;
    private Thread thread              = null;
    private DataInputStream  console   = null;
    private ObjectOutputStream streamOut = null;
    private ChatClientThread client    = null;
    private static Controlador controlador = null;

    
    
    public ChatClient(String serverName, int serverPort)
    {  
        System.out.println("Establishing connection to server...");
        
        try
        {
            // Establishes connection with server (name and port)
            socket = new Socket(serverName, serverPort);
            controlador = new Controlador();            
            System.out.println("Connected to server: " + socket);            
            start();
        }
        
        catch(UnknownHostException uhe)
        {  
            // Host unkwnown
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage()); 
        }
      
        catch(IOException ioexception)
        {  
            // Other error establishing connection
            System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage()); 
        } catch (Exception ex) {
            Logger.getLogger(ChatClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        
   }    
    
    
   public void run()
   {  
       while (thread != null)
       {  
           try
           {  
               streamOut.writeObject(controlador.enviarMensagem(console.readLine()));
               streamOut.flush();
           }
         
           catch(IOException ioexception)
           {  
               System.out.println("Error sending string to server: " + ioexception.getMessage());
               stop();
           }
       }
    }
   

    
    public void handle(Mensagem m)
    {  
        Mensagem recebida = controlador.receberMensagem(m);
        if(recebida == null)
            return;
        String msg = new String(recebida.getMensagem());
        // Receives message from server
        if (msg.equals(".quit"))
        {  
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();
        }
        else{
            // else, writes message received from server to console
            
            System.out.println(recebida.getID() + ": " + msg);
        }
    }
    
    // Inits new client thread
    public void start() throws IOException
    {  
        console   = new DataInputStream(System.in);
        streamOut = new ObjectOutputStream(socket.getOutputStream());
        
        if (thread == null)
        {  
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);                   
            thread.start();
        }
    }
    
    // Stops client thread
    public void stop()
    {  
        if (thread != null)
        {  
            thread.stop();  
            thread = null;
        }
        try
        {  
            if (console   != null)  console.close();
            if (streamOut != null)  streamOut.close();
            if (socket    != null)  socket.close();
        }
      
        catch(IOException ioe)
        {  
            System.out.println("Error closing thread..."); }
            client.close();  
            client.stop();
        }
    
       
    
    public static void main(String args[])
    {  
        ChatClient client = null;
       // if (args.length != 2)
            // Displays correct usage syntax on stdout
      //      System.out.println("Usage: java ChatClient host port");
      //  else
            // Calls new client
       //     client = new ChatClient(args[0], Integer.parseInt(args[1]));
        client = new ChatClient("localhost", 3000);
    }
    
    public void recebeChave(Mensagem m){
        controlador.setKey(m.getIv());
    }
    
}

class ChatClientThread extends Thread
{  
    private Socket           socket   = null;
    private ChatClient       client   = null;
    private ObjectInputStream  streamIn = null;

    public ChatClientThread(ChatClient _client, Socket _socket)
    {  
        client   = _client;
        socket   = _socket;
        open();  
        start();
    }
   
    public void open()
    {  
        try
        {  
            streamIn  = new ObjectInputStream(socket.getInputStream());
            
        }
        catch(IOException ioe)
        {  
            System.out.println("Error getting input stream: " + ioe);
            client.stop();
        }
        
    }
    
    public void close()
    {  
        try
        {  
            if (streamIn != null) streamIn.close();
        }
      
        catch(IOException ioe)
        {  
            System.out.println("Error closing input stream: " + ioe);
        }
    }
    
    public void run()
    {  
        try {
            client.recebeChave((Mensagem)streamIn.readObject());
        } catch (IOException ex) {
            Logger.getLogger(ChatClientThread.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ChatClientThread.class.getName()).log(Level.SEVERE, null, ex);
        }
        while (true)
        {   try
            {  
                client.handle((Mensagem)streamIn.readObject());
            }
            catch(IOException ioe)
            {  
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(ChatClientThread.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
}

