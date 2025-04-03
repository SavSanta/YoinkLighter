package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	crand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

type FlagOptions struct {
	outFile   string
	inputFile string
	domain    string
	password  string
	real      string
	verify    string
    take  string
	certmode string
}

var (
	debugging   bool
	debugWriter io.Writer
)

func printDebug(format string, v ...interface{}) {
	if debugging {
		output := fmt.Sprintf("[DEBUG] ")
		output += format
		fmt.Fprintf(debugWriter, output, v...)
	}
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
const __APPVERSION__ = "2025.04.03"

func VarNumberLength(min, max int) string {
	var r string
	crand.Seed(time.Now().UnixNano())
	num := crand.Intn(max-min) + min
	n := num
	r = RandStringBytes(n)
	return r
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[crand.Intn(len(letters))]

	}
	return string(b)
}

func GenerateCert(domain string, inputFile string) {
	var err error
	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	certs, err := GetCertificatesPEM(domain + ":443")
	if err != nil {
		os.Chdir("..")
		foldername := strings.Split(inputFile, ".")
		os.RemoveAll(foldername[0])
		log.Fatal("Error: The domain: " + domain + " does not exist or is not accessible from the host you are compiling on")
	}
	block, _ := pem.Decode([]byte(certs))
	cert, _ := x509.ParseCertificate(block.Bytes)

	keyToFile(domain+".key", rootKey)

	SubjectTemplate := x509.Certificate{
		SerialNumber: cert.SerialNumber,
		Subject: pkix.Name{
			CommonName: cert.Subject.CommonName,
		},
		NotBefore:             cert.NotBefore,
		NotAfter:              cert.NotAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	IssuerTemplate := x509.Certificate{
		SerialNumber: cert.SerialNumber,
		Subject: pkix.Name{
			CommonName: cert.Issuer.CommonName,
		},
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &SubjectTemplate, &IssuerTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	certToFile(domain+".pem", derBytes)

}

func keyToFile(filename string, key *rsa.PrivateKey) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to marshal RSA private key: %v", err)
		os.Exit(2)
	}
	if err := pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}); err != nil {
		panic(err)
	}
}

func certToFile(filename string, derBytes []byte) {
	certOut, err := os.Create(filename)
	if err != nil {
		log.Fatalf("[-] Failed to Open cert.pem for Writing: %s", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("[-] Failed to Write Data to cert.pem: %s", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("[-] Error Closing cert.pem: %s", err)
	}
}

func GetCertificatesPEM(address string) (string, error) {
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var b bytes.Buffer
	for _, cert := range conn.ConnectionState().PeerCertificates {
		err := pem.Encode(&b, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func GeneratePFK(password string, domain string) {
	cmd := exec.Command("openssl", "pkcs12", "-export", "-out", domain+".pfx", "-inkey", domain+".key", "-in", domain+".pem", "-passin", "pass:"+password+"", "-passout", "pass:"+password+"")
	err := cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
}

func SignExecutable(password string, pfx string, filein string, fileout string) {
	cmd := exec.Command("osslsigncode", "sign", "-pkcs12", pfx, "-in", ""+filein+"", "-out", ""+fileout+"", "-pass", ""+password+"")
	err := cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
}

func Check(check string) {

	cmd := exec.Command("osslsigncode", "verify", ""+check+"")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
}

func StealSignature(stealExe string, destExe string) string {

	File := filepath.Base(stealExe)
	sigFile := File + ".sig"
	//fmt.Println(sigFile)
	cmd := exec.Command("osslsigncode", "extract-signature", "-in", ""+stealExe+"", "-out", ""+sigFile+"")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	fmt.Println(color.GreenString("[*] ") + "Dumped signature from " + File + " to " + sigFile)
	if err != nil {
			log.Fatalf("cmd.Run() failed with %s\n", err)
	}

	destExeName := filepath.Base(destExe)
	sDestExe  := "s-" + destExeName
	att := exec.Command("osslsigncode", "attach-signature", "-sigin", ""+sigFile+"", "-in", ""+destExe+"", "-out", sDestExe, "-CAfile", "/dev/null")                                                                                                  
	//att.Stdout = os.Stdout
	//att.Stdout = os.Stderr
	//attErr := att.Run()
	att.Run()
	fmt.Println(color.GreenString("[*] ") + "Injected stolen signature into " + destExe)
	//if attErr != nil {
	//      log.Fatalf("att.Run() failed with %s\n", attErr)
	//}

	// Check the s-SignedFile.exe
	if _, err := os.Stat(sDestExe); errors.Is(err, os.ErrNotExist) {
		log.Fatalf("Could not create the %s with a stolen cert %s", sDestExe, err.Error())
	}

	return sDestExe
}

func ResourceTake(source string, destination string) {
    
    srcRes0 := yoinkfuncs.LoadAllResourcesFromPath(source)
	ico := yoinkfuncs.SearchForCommonICOGroups(srcRes0)
    
    rawfiRes := yoinkfuncs.GetSpecRawResTypeData(srcRes0, 0x10)
    vi := yoinkfuncs.GetRawVersionInfo(rawfiRes)
	jdata := yoinkfuncs.GetVersionInfoAsJSON(vi)
    ogfvi := yoinkfuncs.GetSrcFileVersionData(jdata)
	newfvi := yoinkfuncs.RequestNewFileInfoForm(ogfvi)
    yoinkfuncs.SetDstFileInfoData(vi, newfvi)
	
    srcRes0.SetIcon(yoinkfuncs.WINICON, ico)
	srcRes0.SetVersionInfo(*vi)
	yoinkfuncs.PerformResPatch(*srcRes0, destination)

}

func options() *FlagOptions {
	certmode := flag.String("Certmode", "NONE", "Select a mode to apply the certificate. [STEAL, PFXSIGN, or NONE]")
	outFile := flag.String("O", "", "Output filename")
	inputFile := flag.String("I", "", "Input filename to be signed/yoinked")
	take := flag.String("Yoink", "", "Existing EXE/DLL file to yoink (take) ICON and file info from.")
	domain := flag.String("Domain", "", "Domain to use when creating a fake code sign")
	password := flag.String("Password", "", "Password for real certificate")
    real := flag.String("Real", "", "Path to a valid .pfx certificate file")
	verify := flag.String("Verify", "", "Verifies a file's code sign certificate")
	debug := flag.Bool("debug", false, "Print debug statements")
	flag.Parse()
	debugging = *debug
	debugWriter = os.Stdout
	return &FlagOptions{outFile: *outFile, inputFile: *inputFile, take: *take, certmode: *certmode, domain: *domain, password: *password, real: *real, verify: *verify}
}

func main() {
	fmt.Printf(`
_____.___.      .__        __   .____    .__       .__     __
\__  |   | ____ |__| ____ |  | _|    |   |__| ____ |  |___/  |_  ___________
 /   |   |/  _ \|  |/    \|  |/ /    |   |  |/ ___\|  |  \   __\/ __ \_  __ \
 \____   (  <_> )  |   |  \    <|    |___|  / /_/  >   Y  \  | \  ___/|  | \/
 / ______|\____/|__|___|  /__|_ \_______ \__\___  /|___|  /__|  \___  >__|
 \/                     \/     \/       \/ /_____/      \/          \/
                                            @Savsanta		vers. %s

[*] A Tool for Code Signing... Real or Fake`, __APPVERSION__)
fmt.Println()
	opt := options()
	if opt.verify == "" && opt.inputFile == "" && opt.outFile == "" {
		log.Fatal("Error: Please provide a file to sign or a file check")
	}

	if opt.verify == "" && opt.inputFile == "" {
		log.Fatal("Error: Please provide a file to sign")
	}
	if opt.verify == "" && opt.outFile == "" {
		log.Fatal("Error: Please provide a name for the signed file")
	}
	if opt.real == "" && opt.domain == "" && opt.verify == "" {
		log.Fatal("Error: Please specify a valid path to a .pfx file or specify the domain to spoof")
	}

	if opt.verify != "" {
		fmt.Println("[*] Checking code signed on file: " + opt.verify)
		Check(opt.verify)
		os.Exit(3)
	}

	// TODO: Reflow this for finalized production after lib change. Or entirely change up their argparsing for readability.
	// Currently this is made to work with their flow and our flow.
	if opt.certmode == "STEAL" {
		fmt.Println(color.BlueString("[+] ") + "Certmode set to STEAL.")
		fmt.Println("[*] Stealing cert from " + opt.inputFile + " to " + opt.outFile)
		signedFile := StealSignature(opt.inputFile, opt.outFile)

		if opt.take != "" {
			fmt.Println("[*] Yoinking icon and file info from " + opt.take + " for target " + signedFile)
			ResourceTake(opt.take, signedFile)
		} 

	} else if opt.certmode == "PFXSIGN" {

		fmt.Println(color.BlueString("[+] ") + "Certmode set to PFXSIGN.")
		if opt.real != "" {
			// Using a valid code-signing cert/
			fmt.Println("[*] Signing " + opt.inputFile + " with a real valid code-signing cert " + opt.real)
			SignExecutable(opt.password, opt.real, opt.inputFile, opt.outFile)
		} else {
			// Generating a cert and signing
			password := VarNumberLength(8, 12)
			pfx := opt.domain + ".pfx"
			fmt.Println("[*] Signing " + opt.inputFile + " with a fake cert")
			GenerateCert(opt.domain, opt.inputFile)
			GeneratePFK(password, opt.domain)
			SignExecutable(password, pfx, opt.inputFile, opt.outFile)
		}

		fmt.Println("[*] Cleaning up....")
		printDebug("[!] Deleting " + opt.domain + ".pem\n")
		os.Remove(opt.domain + ".pem")
		printDebug("[!] Deleting " + opt.domain + ".key\n")
		os.Remove(opt.domain + ".key")
		printDebug("[!] Deleting " + opt.domain + ".pfx\n")
		os.Remove(opt.domain + ".pfx")
		fmt.Println(color.GreenString("[+] ") + "Signed file created.")

	}  else if opt.certmode == "NONE" {
		// Possibly they just ran an a YOINK or VERIFY. Though let's let them know
		fmt.Println(color.BlueString("[+] ") + "Certmode was set to NONE.")
		fmt.Println(color.GreenString("[+] ") + "YoinkLighter execution Finished.")
	}

}
