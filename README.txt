 Encrypt/Decrypt a binary or text file with a powerful command line utility.  

 The encrypted file has no specific header information so to 
 a file scanner it looks like a ordinry binary file. 

 Read from Stdin, write to Stdout OR -i <input> -o <output>

 Encrypt: java -jar scacmd3.jar -e -i <plaintext> -o <ciphertext> [-p]<cipher key> [-h] [-v]
 Encrypt: cat [type] plaintext | java -jar scacmd3.jar -e [-p]<cipher key> [-h] > ciphertext

 Decrypt: java -jar scacmd3.jar -d -i <ciphertext> -o <plaintext> [-p]<cipher key> [-h] [-v]
 Decrypt: cat [type] ciphertext| java -jar scacmd3.jar -d [-p]<cipher key> [-h] > plaintext

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

 To make Jar file:
 jar -cvfm scacmd3.jar manifest.txt ArrayH.class ArrayZ.class ArrayA.class ArrayS.class GetOpt.class scacmd3.class

