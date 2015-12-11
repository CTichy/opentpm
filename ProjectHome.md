Home of the opensource TPM driver for Windows and a corresponding libtpm port!

If you are a developer, you probably want to check out the source code.

svn checkout http://opentpm.googlecode.com/svn/trunk/opentpm

svn checkout http://opentpm.googlecode.com/svn/trunk/libtpm

If you just want to play around with the TPM on your system, we have provided compiled binaries that will allow you to do so.

svn checkout http://opentpm.googlecode.com/svn/trunk/tpm_tools

Libtpm was originally developed by IBM and you can still get the original version here:
http://ibmswtpm.sourceforge.net/

The version I am providing here has been ported to work on Windows with the OpenTPM driver. Be warned that IBM clearly states that libtpm is for educational purposes only, and that the recommended way to interface with the TPM is with an API implementing the TSS specification. However, as a researcher I have found interfacing with the TPM directly, which is what libtpm does, to be much more straight forward. It is also the only option I am aware of for developers wishing to interact with the TPM as the kernel (or lower) level.

DISCLAIMER: This code is for research purposes only, there are probably some bugs in it.

