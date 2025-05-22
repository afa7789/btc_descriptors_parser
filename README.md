<pre>
                                                                                
     #                                "             m                        
  mmm#   mmm    mmm    mmm    m mm  mmm    mmmm   mm#mm   mmm    m mm   mmm  
 #" "#  #"  #  #   "  #"  "   #"  "   #    #" "#    #    #" "#   #"  " #   " 
 #   #  #""""   """m  #       #       #    #   #    #    #   #   #      """m 
 "#m##  "#mm"  "mmm"  "#mm"   #     mm#mm  ##m#"    "mm  "#m#"   #     "mmm" 
                                           #                                 
                                           "                              
</pre>
# Descriptors Derivation/Decoding

# Disclaimer

This was really hard, so I used LLM to finish it.
I don't think it's worth doing this in .c , probably better to do it in python and to use libs people already made to do it.
It was really hard to find how to derive and decode/encode things, not a quick trip to the mall, so better to stick to built tools in this case I guess.

# Pre-requisites

You need to install json-c and OpenSSL (for crypto functions).

## Installing on macOS

If you have Homebrew installed, you can run the following commands:

• Install OpenSSL:
  
```bash
    brew install openssl
    # either use exports
    export CPPFLAGS="-I$(brew --prefix openssl)/include"
    export LDFLAGS="-L$(brew --prefix openssl)/lib"
    # or create sys links to default locations where c looks for it's packages.
    sudo ln -s /opt/homebrew/opt/openssl/include/openssl /usr/local/include/openssl\n
    sudo ln -s /opt/homebrew/opt/openssl/lib/libssl.dylib /usr/local/lib/libssl.dylib\n
    sudo ln -s /opt/homebrew/opt/openssl/lib/libcrypto.dylib /usr/local/lib/libcrypto.dylib\n
```

• Install json-c:
   
   brew install json-c

You have to do something similar to json-c to find it when using c, the standard path for c compilers is in `/usr/local/include` and `/user/local/lib`

Note: After installing OpenSSL, you might need to set the proper paths when compiling your C projects. Homebrew will usually provide instructions on how to link the libraries.


## Running

To run it as a standalone program with the test main function:
Compile with: `gcc -o descriptors descriptors.c -ljson-c -lcrypto -lssl -DMAIN_INCLUDED`
Run with: `./descriptors`

`gcc -o a.out descriptors.c -ljson-c -lcrypto -lssl -DMAIN_INCLUDED && ./a.out`
