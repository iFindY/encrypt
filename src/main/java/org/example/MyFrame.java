package org.example;

import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.ActionEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

import org.apache.commons.io.IOUtils;

class MyFrame extends JFrame {

    private JTextField path        = new JTextField();
    private JTextField pathEncrypt = new JTextField();

    private JTextField pathZip = new JTextField();
    private JTextField pathZipAndEncode = new JTextField();
    private JButton    exit        = new JButton("exit");

    private JButton decode = new JButton("decode");
    private JButton encode = new JButton("encode");

    private JButton zip = new JButton("zip");
    private JButton zipAndEncode = new JButton("zip&encode");
    private JLabel  lblA   = new JLabel("File Path: decode");

    private JLabel lblB = new JLabel("File Path encode:");

    private JLabel lblC = new JLabel("File Path zip:");
    private JLabel lblD = new JLabel("zip & encode:");

    public MyFrame() {
        setTitle("Decrypter");
        setSize(600, 300);
        setLocation(new Point(5000, 300));
        setLayout(null);
        setResizable(false);

        initComponent();
        initEvent();
    }

    private void initComponent() {
        exit.setBounds(500, 220, 80, 25);
        decode.setBounds(400, 220, 80, 25);
        encode.setBounds(300, 220, 80, 25);
        zip.setBounds(200, 220, 80, 25);
        zipAndEncode.setBounds(100, 220, 80, 25);

        lblA.setBounds(20, 50, 150, 20);
        lblB.setBounds(20, 100, 150, 20);
        lblC.setBounds(20, 150, 150, 20);
        lblD.setBounds(20, 180, 150, 20);

        path.setBounds(140, 50, 400, 25);
        pathEncrypt.setBounds(140, 100, 400, 25);
        pathZip.setBounds(140, 150, 400, 25);
        pathZipAndEncode.setBounds(140, 180, 400, 25);


        add(exit);
        add(encode);
        add(decode);
        add(zip);
        add(zipAndEncode);
        add(lblA);
        add(lblB);
        add(lblC);
        add(lblD);
        add(path);
        add(pathEncrypt);
        add(pathZip);
        add(pathZipAndEncode);
    }

    private void initEvent() {

        this.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(1);
            }
        });

        path.setDragEnabled(true);
        path.setDropTarget(new DropTarget() {

            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    List<File> droppedFiles = (List<File>) evt.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);

                    path.setText(droppedFiles.get(0).getAbsolutePath());
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });

        pathEncrypt.setDragEnabled(true);
        pathEncrypt.setDropTarget(new DropTarget() {

            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    List<File> droppedFiles = (List<File>) evt.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);

                    pathEncrypt.setText(droppedFiles.get(0).getAbsolutePath());
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });

        pathZip.setDragEnabled(true);
        pathZip.setDropTarget(new DropTarget() {

            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    List<File> droppedFiles = (List<File>) evt.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);

                    pathZip.setText(droppedFiles.get(0).getAbsolutePath());
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });
        pathZipAndEncode.setDropTarget(new DropTarget() {

            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    List<File> droppedFiles = (List<File>) evt.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);

                    pathZipAndEncode.setText(droppedFiles.get(0).getAbsolutePath());
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });

        exit.addActionListener(this::exit);
        decode.addActionListener(this::decode);
        encode.addActionListener(this::encode);
        zip.addActionListener(this::zip);
        zipAndEncode.addActionListener(this::zipAndEncode);
    }

    private void exit(ActionEvent evt) {
        System.exit(0);

    }

    private void decode(ActionEvent evt) {

        SecretKey secretKey = new SecretKeySpec("Arkadi0123456789".getBytes(), "AES");

        try (FileInputStream fileIn = new FileInputStream(path.getText())) {

            byte[] fileIv = new byte[16];
            fileIn.read(fileIv);

            var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(fileIv));

            try (CipherInputStream cipherIn = new CipherInputStream(fileIn, cipher);
                    FileOutputStream fo = new FileOutputStream(path.getText().replace("encoded", "decoded"))) {

                IOUtils.copy(cipherIn, fo);
            }

        } catch (InvalidKeyException | NoSuchPaddingException | IOException | NoSuchAlgorithmException |
                 InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }

    }

    private void encode(ActionEvent evt) {

        SecretKey secretKey = new SecretKeySpec("Arkadi0123456789".getBytes(), "AES");
        Cipher    cipher;
        byte[]    iv;

        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            iv = cipher.getIV();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        try (FileInputStream fileIn = new FileInputStream(pathEncrypt.getText());
                CipherInputStream cipherIn = new CipherInputStream(fileIn, cipher);
                FileOutputStream fileOut = new FileOutputStream(pathEncrypt.getText() + ".encoded")) {

            fileOut.write(iv);
            IOUtils.copy(cipherIn, fileOut);

        } catch (RuntimeException | IOException e) {
            throw new RuntimeException(e);
        }

    }

    private void zip(ActionEvent evt) {

        try (FileInputStream fileIn = new FileInputStream(pathZip.getText());
                FileOutputStream fileOut = new FileOutputStream(pathZip.getText() + ".zip");
                ZipOutputStream zip = new ZipOutputStream(fileOut)) {

            ZipEntry zipEntry = new ZipEntry("test.txt");
            zip.putNextEntry(zipEntry);

            IOUtils.copy(fileIn, zip);

        } catch (IOException ignored) {
            System.out.println(ignored);
        }
    }

    private void zipAndEncode(ActionEvent evt){
        SecretKey secretKey = new SecretKeySpec("Arkadi0123456789".getBytes(), "AES");
        Cipher    cipher;
        byte[]    iv;

        // ======================================
        // =              it cipher             =
        // ======================================
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            iv = cipher.getIV();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }


        // ======================================
        // =               zipping                =
        // ======================================
        try (FileInputStream fileIn = new FileInputStream(pathZipAndEncode.getText());
                FileOutputStream fileOut = new FileOutputStream(pathZipAndEncode.getText() + ".zip.encoded");
                CipherOutputStream cipherOut = new CipherOutputStream(fileOut, cipher);
                ZipOutputStream zipIn = new ZipOutputStream(cipherOut)) {

            fileOut.write(iv);
            ZipEntry zipEntry = new ZipEntry("test.txt");
            zipIn.putNextEntry(zipEntry);

            IOUtils.copy(fileIn, zipIn);

        } catch (IOException ignored) {
            System.out.println(ignored);
        }

    }
}

