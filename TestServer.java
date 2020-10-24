package com.pepe.apps.chatroom.room.encrypted;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.*;
import java.util.Base64;

/**
 *
 * @author Pepe
 */
public class TestServer extends JFrame {

    private final String aesKey = "ËâÒÐÆÞÚÐÎÕÂ×ÒÔÚÉ";
    private final String obsKey = "fpioajeofnasjndajsduojeuojaseuthaypiawpwairepiowjgawegjamfdsajncnvnueurawjeruhejadjnajdsnfjneugnashgrjakfjaurgyahgasgde";
    private Base64.Encoder encoder;
    private Base64.Decoder decoder;
    
    private ArrayList clientOutputStreams;
    private ArrayList<String> users;    
    
    private int port = 5354;
    
    public TestServer() {
        this.encoder = Base64.getEncoder();
        this.decoder = Base64.getDecoder();
        initUI();
        setVisible(true);
        txtCmd.requestFocus();
    }
    
    private void initUI() {
        txtCmd = new JTextField();
        scrollArea = new JScrollPane();
        area = new JTextArea();

        setTitle("Server");
        setResizable(false);
        setLocationRelativeTo(null);
        getContentPane().setBackground(Color.BLACK);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setPreferredSize(new Dimension(500, 500));

        area.setColumns(20);
        area.setRows(5);
        area.setEditable(false);
        area.setBackground(Color.BLACK);
        area.setForeground(Color.GREEN);
        area.setCaretColor(Color.YELLOW);
                
        scrollArea.setViewportView(area);        
        
        txtCmd.setBackground(Color.BLACK);
        txtCmd.setForeground(Color.GREEN);       
        
        GroupLayout layout = new GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addComponent(txtCmd)
            .addComponent(scrollArea, GroupLayout.DEFAULT_SIZE, 500, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addComponent(scrollArea, GroupLayout.DEFAULT_SIZE, 469, Short.MAX_VALUE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(txtCmd, GroupLayout.PREFERRED_SIZE, 25, GroupLayout.PREFERRED_SIZE))
        );

        pack();
        
        txtCmd.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {}

            @Override
            public void keyPressed(KeyEvent e) {
                if(e.getKeyCode() == KeyEvent.VK_ENTER) {
                    String cmd = txtCmd.getText();
                    txtCmd.setText("");
                    if(cmd.startsWith("/")) {           
                        String c = cmd.replaceFirst("/", "");
                        area.append("$ " + c + "\n");
                        processCmd(c);
                    }
                }
            }

            @Override
            public void keyReleased(KeyEvent e) {}
        });
    }      
    
    private void processCmd(String cmd) {
        switch(cmd) {
            case "start":
                area.append("Starting Server...\n");
                new Thread(new ServerStart()).start();                
                break;
                
            case "stop":
                try {Thread.sleep(1000);} catch (InterruptedException ex) {Thread.currentThread().interrupt();}
                tellEveryone("Server:is stopping and all users will be disconnected.\n:Chat");
                area.append("Server stopping... \n");
                area.setText("");
                break;
                
            case "userlist":
                
                break;                        
            
            case "help":
                
                break;
            default:
                area.append("[ERROR] Command not found.\n");
        }
    }
    
    private String encryptMessageToSend(String message) {
        // 1. OBFUSCATE MESSAGE      
        // 2. -> ENCRYPT BASE64        
        // 3. -> ENCRYPT AES_B64 w/ aesKey        
        return encryptAES(true, encryptBase64(obfuscate(message)));        
    }
    
    private String decryptMessageReceived(String message) {
        // 1. DECRYPT AES_B64 w/ aesKey        
        // 2. -> DECRYPT BASE64        
        // 3. -> UNOBFUSCATE FINAL STR
        return unobfuscate(decryptBase64(decryptAES(true, message)));
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
            SecretKeySpec skeySpec = new SecretKeySpec(unobfuscate(aesKey).getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            byte[] encrypted = cipher.doFinal(s.getBytes("UTF-8"));
            if(isBase64) {
                return encryptBase64Bytes(encrypted);
            } else {
                return new String(encrypted);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private String decryptAES(boolean isBase64, String s) {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(unobfuscate(aesKey).getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            byte[] encrypted = cipher.doFinal(s.getBytes("UTF-8"));
            if(isBase64) {
                return decryptBase64(new String(encrypted));
            } else {
                return new String(encrypted);
            }                
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    // CHAT
    
    // CONNECTION THREADS
    public class ServerStart implements Runnable {

        @Override
        public void run() {
            clientOutputStreams = new ArrayList();
            users = new ArrayList();

            try {
                ServerSocket serverSock = new ServerSocket(port);
                area.append("[SUCCESS] Server started with port " + port + "\n");
                while (true) {
                    Socket clientSock = serverSock.accept();
                    PrintWriter writer = new PrintWriter(clientSock.getOutputStream());
                    clientOutputStreams.add(writer);                    
                    
                    new Thread(new ClientHandler(clientSock, writer)).start();
                    area.append("[DATA] Got a connection. \n");
                }
            } catch (Exception ex) {
                area.append("[ERROR] Error making a connection. \n");
            }
        }
    }
    
    public class ClientHandler implements Runnable {

        private BufferedReader reader;
        private Socket sock;
        private PrintWriter client;

        public ClientHandler(Socket clientSocket, PrintWriter user) {
            client = user;
            try {
                sock = clientSocket;
                reader = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            } catch (Exception ex) {
                area.append("Unexpected error... \n");
                area.append(ex.getMessage()+"\n");
            }

        }

        @Override
        public void run() {
            String stream, connect = "Connect", disconnect = "Disconnect", chat = "Chat";
            String[] data;

            try {
                while ((stream = reader.readLine()) != null) {
                    area.append(stream);
                    String message = decryptMessageReceived(stream);
                    area.append("Received: " + message + "\n");
                    data = message.split(":");

                    for (String token : data) {
                        area.append(token + "\n");
                    }

                    if (data[2].equals(connect)) {
                        tellEveryone((data[0] + ":" + data[1] + ":" + chat));
                        userAdd(data[0]);
                    } else if (data[2].equals(disconnect)) {
                        tellEveryone((data[0] + ":has disconnected." + ":" + chat));
                        userRemove(data[0]);
                    } else if (data[2].equals(chat)) {
                        tellEveryone(message);
                    } else {
                        area.append("No Conditions were met. \n");
                    }
                }
            } catch (Exception ex) {
                area.append("Lost a connection. \n");
                ex.printStackTrace();
                clientOutputStreams.remove(client);
            }
        }
    }
    
    // UTILS
    private void userAdd(String data) {
        String message, add = ": :Connect", done = "Server: :Done", name = data;
        area.append("Before " + name + " added. \n");
        users.add(name);
        area.append("After " + name + " added. \n");
        String[] tempList = new String[(users.size())];
        users.toArray(tempList);

        for (String token : tempList) {
            message = (token + add);
            tellEveryone(message);
        }
        tellEveryone(done);
    }

    private void userRemove(String data) {
        String message, add = ": :Connect", done = "Server: :Done", name = data;
        users.remove(name);
        String[] tempList = new String[(users.size())];
        users.toArray(tempList);

        for (String token : tempList) {
            message = (token + add);
            tellEveryone(message);
        }
        tellEveryone(done);
    }

    private void tellEveryone(String message) {
        Iterator it = clientOutputStreams.iterator();
        while (it.hasNext()) {
            try {
                PrintWriter writer = (PrintWriter) it.next();
                writer.println(encryptMessageToSend(message));
                area.append("Sending: " + message + "\n");
                writer.flush();
                area.setCaretPosition(area.getDocument().getLength());

            } catch (Exception ex) {                
                area.append("Error telling everyone. \n");
            }
        }
    }
    
    // JFRAME COMPONENTS
    private JTextField txtCmd;
    private JTextArea area;
    private JScrollPane scrollArea;

    public static void main(String[] args) {
        new TestServer();
    }
}