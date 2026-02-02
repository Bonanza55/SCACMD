 Encrypt/Decrypt a binary or text file with a powerful command line utility.  

 The encrypted file has no specific header information so to 
 a file scanner it looks like a ordinry binary file. 

 Read from Stdin, write to Stdout OR -i <input> -o <output>

 Encrypt: java -jar scacmd.jar -e -i <plaintext> -o <ciphertext> [-p]<cipher key> [-h] [-v]
 Encrypt: cat [type] plaintext | java -jar scacmd.jar -e [-p]<cipher key> [-h] > ciphertext

 Decrypt: java -jar scacmd.jar -d -i <ciphertext> -o <plaintext> [-p]<cipher key> [-h] [-v]
 Decrypt: cat [type] ciphertext| java -jar scacmd.jar -d [-p]<cipher key> [-h] > plaintext

 Where -v = version
       -h = help
       -p = optional password

 If the environmental VAR is set then no <-p password> is requred.
 Windows:  set CIPHERKEY="f00Bar"
 UNIX/MAC: export CIPHERKEY=f00Bar
 To unset: unset CIPHERKEY
 $CIPHERKEY of 6 char or more required.

 1.0 Aug 27 2014 - initial release.
 1.1 Aug 29 2014 - add byte swap logic.
 1.2 Nov  3 2014 - add GetOpt logic.
 1.3 Nov  3 2014 - add four byte header.
 1.4 May 24 2015 - add -e -d options.
 1.5 May 31 2015 - add sha256.
 1.6 Oct 18 2015 - add cipherkey creep logic.
 1.7 Nov 29 2015 - add large arrays.
 1.8 Feb 22 2016 - add -i -o options.
 1.9 Mar 10 2016 - add block cipher.
 2.0 Oct 14 2016 - add enhanced block cipher (even/odd).
 2.1 Oct 14 2016 - add -v option.
 3.0 Sep 17 2020 - Removed SEED, added keyCksum to fix array index bug.
 3.1 Jun 26 2023 - Published on GitHub.
 4.3 Jan 28 2026 - IMPROVED SECURITY + PASSWORD RULES

 To compile:
 javac GetOpt.java 
 javac ScacmdArrays.java 
 javac SHA256Utils.java 
 javac RubiksCubeCipher54.java 
 javac Scacmd.java 

 To make Jar file:
 jar -cvfm Scacmd.jar manifest.txt ArrayH.class ArrayZ.class ArrayA.class ArrayS.class GetOpt.class SHA256Utils.class RubiksCubeCipher54.class Scacmd.class

 To test:
 cat Gettysburg.txt | java -jar scacmd.jar -e -p 1am2C00L! | java -jar scacmd.jar -d -p 1am2C00L! 

 To bitmap encode:
 cat peterbilt.jpg | java -jar scacmd.jar -e -p 1am2C00L! > pb.enc
 python3 b2p.py -e -i pb.enc -p pb.jpg -o pb.png                  
   Success: Saved to pb.png
 python3 b2p.py -d -i pb.png -o restored_pb.enc -p True
   Success: Decoded 160308 bytes to restored_pb.enc
 cat restored_pb.enc | java -jar scacmd.jar -d -p 1am2C00L! > pb.jpg
 cksum peterbilt.jpg
   770339206 160304 peterbilt.jpg
 cksum pb.jpg       
   770339206 160304 pb.jpg
