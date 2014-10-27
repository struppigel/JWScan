## JWScan

JWScan is a reverse engineering tool that tells you if your PE file was packed by a Jar-To-EXE wrapper tool.

Scans PE files for embedded Jar, Zip, or Java bytecode files, displays the location, and can dump the files. 
Scans for Jar-to-EXE wrapper signatures of Launch4j, Exe4j, JSmooth, Jar2Exe.
Scans for program independend indicators of Jar-to-EXE wrapper usage.

### Usage

General usage:

    java -jar jwscan.jar [-d <hexoffset>] <PEfile>

Example to get a report:

    java -jar jwscan.jar myfile.exe

Example to dump at offset 0x5c00:

    java -jar jwscan.jar -d 0x5c00 myfile.exe

Example output

    JWScan 0.2.1 -- by Katja Hahn
   
    scanning file ...
   
    file name: ../../portextestfiles/launch4jexe.exe
   
    Signatures found:
      * Jar manifest (strong indication for embedded jar)
      * Launch4j signature
      * PZIP Magic Number (weak indication for embedded zip)
      * Call to java.exe (strong indication for java wrapper)
      * Call to javaw.exe (strong indication for java wrapper)
   
    ZIP/Jar offsets: 0x5c00
  
### Build
  
Build this program via sbt
  
    sbt assembly
