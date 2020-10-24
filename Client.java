package com.pepe.apps.chatroom.room.encrypted;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
/**
 *
 * @author Pepe
 */
public class Client extends JFrame {

    private final String aesKey = "ËâÒÐÆÞÚÐÎÕÂáÌáÈ×ÌÔ××ÕËÞè×ÜÈÔÞèÚÐÂìåÑÔì×ßÂÞåÍÖÓ×ØÝÑÅåËÑËÔÑÔÇÝÂÝÖÉãèÓîÚÞÓÉßßÎãÖÐÊßÊÅÒåÂÒÈíàÎËáØÛÈÕÂæÚÎÓÜÈÌØÑØçäÏÚËÜÑÔØÛÌÙÎã";
    private final String obsKey = "fpioajeofnasjndajsduojeuojaseuthaypiawpwairepiowjgawegjamfdsajncnvnueurawjeruhejadjnajdsnfjneugnashgrjakfjaurgyahgasgde";
    private Base64.Encoder encoder;
    private Base64.Decoder decoder;

    private Socket sock;
    private BufferedReader reader;
    private PrintWriter writer;
    private boolean isConnected;
    private String address = "192.168.1.244";
    private int port = 5354;
    private String user = "pc1";
    private String password;
    private ArrayList<String> users;

    public Client() {
        encoder = Base64.getEncoder();
        decoder = Base64.getDecoder();
        users = new ArrayList<>();
        initUI();
        setVisible(true);
    }

    private void initUI() {
        lblAddress = new JLabel("Address:");
        txtAddress = new JTextField();
        lblPort = new JLabel("Port:");
        txtPort = new JTextField();
        lblUsername = new JLabel("Username:");
        txtUsername = new JTextField();
        lblPassword = new JLabel("Password:");
        txtPassword = new JTextField();
        btnConnect = new JButton("Connect");
        btnDisconnect = new JButton("Disconnect");
        btnExit = new JButton("Disconnect and leave");
        scrollPane = new JScrollPane();
        areaChat = new JTextArea();
        txtMessage = new JTextField();
        btnSend = new JButton("Send");

        setTitle("Chat - Client's frame");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setResizable(false);      

        areaChat.setEditable(false);
        areaChat.setColumns(20);
        areaChat.setRows(5);
        scrollPane.setViewportView(areaChat);

        btnConnect.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                // CONNECT BUTTON
                connect();
            }
        });

        btnDisconnect.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                // DISCONNECT BUTTON
                disconnect();
            }
        });

        btnSend.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                // SEND BUTTON
                sendMessage();
            }
        });

        GroupLayout layout = new GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(txtMessage, GroupLayout.PREFERRED_SIZE, 352, GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(btnSend, GroupLayout.DEFAULT_SIZE, 126, Short.MAX_VALUE))
                                        .addComponent(scrollPane)
                                        .addGroup(layout.createSequentialGroup()
                                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING, false)
                                                        .addComponent(lblUsername, GroupLayout.DEFAULT_SIZE, 62, Short.MAX_VALUE)
                                                        .addComponent(lblAddress, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                                .addGap(18, 18, 18)
                                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                                                        .addComponent(txtAddress, GroupLayout.DEFAULT_SIZE, 89, Short.MAX_VALUE)
                                                        .addComponent(txtUsername))
                                                .addGap(18, 18, 18)
                                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                                                        .addComponent(lblPassword, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                        .addComponent(lblPort, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                                                        .addComponent(txtPassword)
                                                        .addComponent(txtPort, GroupLayout.DEFAULT_SIZE, 50, Short.MAX_VALUE))
                                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                                        .addGroup(layout.createSequentialGroup()
                                                                .addComponent(btnConnect)
                                                                .addGap(2, 2, 2)
                                                                .addComponent(btnDisconnect)
                                                                .addGap(0, 0, Short.MAX_VALUE))
                                                        .addComponent(btnExit, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
                                .addContainerGap()));
        layout.setVerticalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(lblAddress)
                                        .addComponent(txtAddress, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(lblPort)
                                        .addComponent(txtPort, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(btnExit))
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                                        .addComponent(txtUsername)
                                        .addComponent(txtPassword)
                                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                                .addComponent(lblUsername)
                                                .addComponent(lblPassword)
                                                .addComponent(btnConnect)
                                                .addComponent(btnDisconnect)))
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(scrollPane, GroupLayout.PREFERRED_SIZE, 310, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(txtMessage)
                                        .addComponent(btnSend, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addContainerGap())
        );

        pack();
    }

    private String encryptMessageToSend(String message) {
        // 1. OBFUSCATE MESSAGE
        // 2. -> ENCRYPT BASE64
        // 3. -> ENCRYPT AES_B64 w/ aesKey        
        //return encryptAES(true, encryptBase64(obfuscate(message)));
        
        // 1. ENCRYPT AES_B64 w/ aesKey
        // 2. -> OBFUSCATE
        // 3. -> ENCRYPT BASE64
        return encrypt(true, message);
    }

    private String decryptMessageReceived(String message) {
        // 1. DECRYPT AES_B64 w/ aesKey
        // 2. -> DECRYPT BASE64
        // 3. -> UNOBFUSCATE FINAL STR
        //return unobfuscate(decryptBase64(decryptAES(true, message)));
        
        // 1. DECRYPT BASE64
        // 2. -> UNOBFUSCATE
        // 3. -> DECRYPT AES_B64 w/ aesKey
        return decrypt(true, message);
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
    
    private String encrypt(boolean strongAes, String s) {
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
            if (strongAes) {
                return encryptBase64Bytes(cipher.doFinal(s.getBytes("UTF-8")));                
                //return encryptBase64(obfuscate(new String(cipher.doFinal(s.getBytes("UTF-8")))));
                
            } else {
                return new String(cipher.doFinal(s.getBytes("UTF-8")));
            }
            
        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    private String decrypt(boolean strongAes, String s) {
        try {
            // SET KEY mKey
            byte[] key = unobfuscate(aesKey).trim().getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            // DECRYPT str
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            if(strongAes) {
                return new String(cipher.doFinal(decryptBase64String(s)));
                //return new String(cipher.doFinal(unobfuscate(decryptBase64(s)).getBytes("UTF-8")));
            } else {
                return new String(cipher.doFinal(s.getBytes("UTF-8")));
            }
        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    Thread listener = new Thread(new Runnable() {
        @Override
        public void run() {
            String[] data;
            String stream;
            /*
                En esta funcion se interpreta los mensajes que nos llegan del servidor ya que el servidor nos va a
                dar un mensaje con la siguiente estructura -> [USUARIO]:[MENSAJE]:[ESTADO]
                Arriba tenemos las variables con los distintos estados de comunicacion que puede haber, la variable
                stream son las lineas que va leyendo nuestro BufferedReader
             */

            try {
                while ((stream = reader.readLine()) != null) {
                    String msg = decryptMessageReceived(stream);
                    data = msg.split(":");
                                        
                    switch (data[2]) {
                        case "Chat":
                            // EN CASO DE QUE EL ESTADO DEL MENSAJE QUIERA CHATEAR
                            areaChat.append(data[0] + ": " + data[1] + "\n");
                            break;

                        case "Connect":
                            // EN CASO DE QUE EL ESTADO DEL MENSAJE QUIERA DECIR QUE UN USUARIO SE HA CONECTADO
                            areaChat.removeAll();
                            userAdd(data[0]);
                            break;

                        case "Disconnect":
                            // EN CASO DE QUE EL ESTADO DEL MENSAJE QUIERA DECIR QUE UN USUARIO SE HA DESCONECTADO
                            userRemove(data[0]);
                            break;
                        
                        case "Done":
                            writeUsers();
                            users.clear();
                            break;
                            
                        default: // No se pudo resolver el estado
                    }
                }
            } catch (Exception ex) {
                areaChat.append("An errror ocurred!");
            }
        }
    });
    
    public class IncomingReader implements Runnable {

        @Override
        public void run() {
            String[] data;
            String stream;
            /*
                En esta funcion se interpreta los mensajes que nos llegan del servidor ya que el servidor nos va a
                dar un mensaje con la siguiente estructura -> [USUARIO]:[MENSAJE]:[ESTADO]
                Arriba tenemos las variables con los distintos estados de comunicacion que puede haber, la variable
                stream son las lineas que va leyendo nuestro BufferedReader
             */

            try {
                while ((stream = reader.readLine()) != null) {
                    String msg = decryptMessageReceived(stream);
                    data = msg.split(":");
                                        
                    switch (data[2]) {
                        case "Chat":
                            // EN CASO DE QUE EL ESTADO DEL MENSAJE QUIERA CHATEAR
                            areaChat.append(data[0] + ": " + data[1] + "\n");
                            break;

                        case "Connect":
                            // EN CASO DE QUE EL ESTADO DEL MENSAJE QUIERA DECIR QUE UN USUARIO SE HA CONECTADO
                            areaChat.removeAll();
                            userAdd(data[0]);
                            break;

                        case "Disconnect":
                            // EN CASO DE QUE EL ESTADO DEL MENSAJE QUIERA DECIR QUE UN USUARIO SE HA DESCONECTADO
                            userRemove(data[0]);
                            break;
                        
                        case "Done":
                            writeUsers();
                            users.clear();
                            break;
                            
                        default: // No se pudo resolver el estado
                    }
                }
            } catch (Exception ex) {
            }
        }
    }

    private void sendMessage() {
        if ((txtMessage.getText()).equals("")) {
            txtMessage.setText("");
            txtMessage.requestFocus();
        } else {
            try {
                String msg = user + ":" + txtMessage.getText() + ":" + "Chat";
                writer.println(encryptMessageToSend(msg));
                writer.flush(); // flushes the buffer
            } catch (Exception ex) {
                areaChat.append("Message was not sent. \n");
            }
            txtMessage.setText("");
            txtMessage.requestFocus();
        }

        txtMessage.setText("");
        txtMessage.requestFocus();
    }

    private void userAdd(String data) {
        users.add(data);
    }

    private void userRemove(String data) {
        areaChat.append(data + " is now offline.\n");
    }

    private void writeUsers() {
        String[] tempList = new String[(users.size())];
        users.toArray(tempList);
        for (String token : tempList) {
            //users.append(token + "\n");
        }
    }

    private void connect() {
        if (isConnected == false) { // Comprobamos que no esta conectado a ningun servidor
            txtUsername.setEditable(false);

            try {
                // INICIALIZAMOS LAS VARIABLES DE COMUNICACION
                sock = new Socket(address, port);
                reader = new BufferedReader(new InputStreamReader(sock.getInputStream()));
                writer = new PrintWriter(sock.getOutputStream());
                String msg = user + ":has connected.:Connect";
                writer.println(encryptMessageToSend(msg));
                writer.flush(); // LEVANTAMOS NUESTRO WRITER QUE VA A MANDAR LOS MENSAJES                        
                isConnected = true;
                // SE HA CONECTADO AL SERVER
            } catch (Exception ex) {
                areaChat.append("Cannot Connect! Try Again. \n");
                txtUsername.setEditable(true);
                ex.printStackTrace();
            }

            listener.start(); // LISTEN THREAD

        } else if (isConnected == true) {
            areaChat.append("You are already connected. \n");
        }
    }

    private void disconnect() {
        // FIRST SEND A BYE MESSAGE
        String bye = (user + ": :Disconnect");
        try {
            writer.println(encryptMessageToSend(bye));
            writer.flush();
        } catch (Exception e) {
            areaChat.append("[ERROR] Could not send Disconnect message.\n");
        }
        // THEN DISCONNECT
        try {
            areaChat.append("Disconnected.\n");
            sock.close();
        } catch (Exception ex) {
            areaChat.append("Failed to disconnect. \n");
        }
        isConnected = false;
        txtUsername.setEditable(true);
    }

    public static void main(String[] args) {
        new Client();
    }

    // JFRAME COMPONENTS
    private JButton btnExit;
    private JButton btnConnect;
    private JButton btnDisconnect;
    private JButton btnSend;
    private JScrollPane scrollPane;
    private JLabel lblAddress;
    private JLabel lblPassword;
    private JLabel lblPort;
    private JLabel lblUsername;
    private JTextArea areaChat;
    private JTextField txtAddress;
    private JTextField txtMessage;
    private JTextField txtPassword;
    private JTextField txtPort;
    private JTextField txtUsername;
}