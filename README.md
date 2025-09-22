<p align="center">
  <img src="Screenshots/YoinkCity.gif" alt="Description of image">
</p>

# YoinkLighter

A tool to create spoof code signing certificates in order to sign binaries and DLL files to aid in the intention to evade EDR products and minimize SOC scrutiny. 
YoinkLighter can also be used with legitimate code signing certificates to sign files. 
YoinkLighter can use a fully qualified domain name such as `acme.com`.
Additionally, YoinkLighter allows supports the ability to yoink (take) embedded icons, file information, and certificates from an existing file.

YoinkLighter is a fork of the @Tylous LimeLighter GoLang project.
The intent was in addition to it's innate original functions utilize pure GoLang to perform additional Portable Executable (PE) manipulations. 

## Installation
Make sure that the following are installed on your OS 

```
openssl
osslsigncode
```

The first step as always is to clone the repo. Before you compile YoinkLighter you'll need to install the dependencies. To install them, run following commands:
```
go get github.com/savsanta/yoinkfuncs
go get github.com/fatih/color
go get github.com/charmbracelet/huh

```

Then build it

```
go build YoinkLighter.go
```




## Usage

```
./YoinkLighter -h       

_____.___.      .__        __   .____    .__       .__     __                
\__  |   | ____ |__| ____ |  | _|    |   |__| ____ |  |___/  |_  ___________ 
 /   |   |/  _ \|  |/    \|  |/ /    |   |  |/ ___\|  |  \   __\/ __ \_  __ \
 \____   (  <_> )  |   |  \    <|    |___|  / /_/  >   Y  \  | \  ___/|  | \/
 / ______|\____/|__|___|  /__|_ \_______ \__\___  /|___|  /__|  \___  >__|   
 \/                     \/     \/       \/ /_____/      \/          \/                                                               
                                            @Savsanta


[*] A Tool for Code Signing... Real or Fake
Usage of ./YoinkLighter:
  -C string
        Select a mode to apply the certificate. [STEAL, PFXSIGN, or NONE] (default "NONE")
  -Certmode string
        Select a mode to apply the certificate. [STEAL, PFXSIGN, or NONE] (default "NONE")
  -Domain string
        Domain to use when creating a fake code sign
  -I string
        Input filename to be signing.
  -Input string
        Input filename to be used for signing.
  -O string
        Output target to apply the signing to
  -Output string
        Output target to apply the signing to
  -Password string
        Password for real certificate
  -Real string
        Path to a valid .pfx certificate file
  -Verify string
        Verifies a file's code sign certificate
  -Y string
        Existing EXE/DLL file to yoink (take) ICON and file info from.
  -Yoink string
        Existing EXE/DLL file to yoink (take) ICON and file info from.
  -debug
        Print debug statements

```

### Signing a file using a generated cert
To sign a file you can use the command option `Domain` to generate a fake code signing certificate.

![Signing](Screenshots/Signing.png)

to sign a file with a valid code signing certificate use the `Real` and `Password` to sign a file with a valid code signing certificate.

### Verifying a signed file
To verify a signed file use the `verify` command.

![Verifying](Screenshots/Verifing.png)
![WindowsVerifying](Screenshots/WindowsVerifying.png)


### Yoinking an Icon and FileInfo Metadata Example Syntax
`./yoinklighter-linux-amd64 -Certmode STEAL -I mssetup.exe -Y mssetup.exe -O MyMalwareLoader.exe -Domain NotBenign.com`

`.\yoinklighter-windows-amd64.exe -Certmode STEAL -I mssetup.exe -Y mssetup.exe -O MyMalwareLoader.exe -Domain NotBenign.com`

##
