package org.example;

import static java.awt.event.WindowEvent.WINDOW_CLOSING;
import static javax.swing.WindowConstants.EXIT_ON_CLOSE;

class Main {

    public static void main(String[] args) {

        MyFrame f = new MyFrame();
       f.setDefaultCloseOperation(EXIT_ON_CLOSE);
       f.setVisible(true);

    }

}

