IBM's libtpm ported to work with OpenTPM

Contact:
Corey Kallenberg (ckallenberg@mitre.org)

Instructions:

Dependencies - 
First make sure the opentpm driver is installed. Accomplish this by following
the instructions in the opentpm readme file.

You need MinGW/MSYS to build

You also need OpenSSL for win32: http://slproweb.com/products/Win32OpenSSL.html

Build - 
cd lib
make -f makefile.mak
cd ../utils
cp ../lib/libtpm.dll .
make -f makefile.mak

Enjoy.


             \                  /
    _________))                ((__________
   /.-------./\\    \    /    //\.--------.\
  //#######//##\\   ))  ((   //##\\########\\
 //#######//###((  ((    ))  ))###\\########\\
((#######((#####\\  \\  //  //#####))########))
 \##' `###\######\\  \)(/  //######/####' `##/
  )'    ``#)'  `##\`->oo<-'/##'  `(#''     `(
          (       ``\`..'/''       )
                     \""(
                      `- )
                      / /
                     ( /\  
                     /\| \
                    (  \
                        )
                       /
                      (
