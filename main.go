package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

var logger = log.New(os.Stderr, "", log.LstdFlags)

type SPNEGOClient struct {
	Client *spnego.SPNEGO
	mu     sync.Mutex
}

func (c *SPNEGOClient) GetToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.Client.AcquireCred(); err != nil {
		return "", fmt.Errorf("could not acquire client credential: %v", err)
	}
	token, err := c.Client.InitSecContext()
	if err != nil {
		return "", fmt.Errorf("could not initialize context: %v", err)
	}
	b, err := token.Marshal()
	if err != nil {
		return "", fmt.Errorf("could not marshal SPNEGO token: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func readAuth(path string) map[string]string {
	auth := make(map[string]string)
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			text := scanner.Text()
			a := strings.Split(text, ":")
			if len(a) != 2 {
				log.Fatalf("bad auth line: %v", text)
			}
			auth[a[0]] = a[1]
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}
	return auth
}

func checkAuth(auth map[string]string, req *http.Request) (string, error) {
	user := ""
	if len(auth) > 0 {
		err := req.ParseForm()
		if err != nil {
			return user, fmt.Errorf("credentials not provided: %v", err)
		}
		user = req.Form.Get("u")
		pass := req.Form.Get("p")
		res := bcrypt.CompareHashAndPassword([]byte(auth[user]), []byte(pass))
		if res != nil {
			return user, fmt.Errorf("password mismatch: u=%v; p=%v; err=%v", user, pass, res)
		}
	}
	return user, nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "bind address")
	cfgFile := flag.String("config", "", "config file, e.g. /etc/krb5.conf")
	user := flag.String("user", "", "user name")
	realm := flag.String("realm", "", "realm")
	domain := flag.String("domain", "", "domain")
	ktPath := flag.String("keytab", "", "keytab file path")
	tlsKeyPath := flag.String("tls_key", "", "tls key file path")
	tlsCrtPath := flag.String("tls_crt", "", "tls cert file path")
	authPath := flag.String("auth", "", "auth file path")
	debug := flag.Bool("debug", false, "turn on debugging")
	flag.Parse()
	if *addr == "" || *cfgFile == "" || *user == "" || *realm == "" || *domain == "" || *ktPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	auth := readAuth(*authPath)

	kt, err := keytab.Load(*ktPath)
	if err != nil {
		logger.Panic(err)
	}

	spn := fmt.Sprintf("%s/%s", *user, *domain)
	if *debug {
		logger.Printf("spn: %v", spn)
	}
	cfg, err := config.Load(*cfgFile)
	if err != nil {
		logger.Panic(err)
	}
	opts := []func(*client.Settings){
		client.DisablePAFXFAST(true),
	}
	if *debug {
		opts = append(opts, client.Logger(logger))
	}
	cli := client.NewWithKeytab(*user, *realm, kt, cfg, opts...)
	spnegoCli := &SPNEGOClient{
		Client: spnego.SPNEGOClient(cli, spn),
	}

	ktoken := func(w http.ResponseWriter, req *http.Request) {
		user, err := checkAuth(auth, req)
		if err != nil {
			logger.Print(err)
			w.WriteHeader(403)
			return

		}
		start := time.Now()
		token, err := spnegoCli.GetToken()
		elapsed := time.Since(start)
		if err != nil {
			logger.Printf("Failed to get SPNEGO token: %v (%s)", err, elapsed)
			w.WriteHeader(500)
			return
		}
		logger.Printf("%v %v %v %v (%s)", req.Method, req.Host, req.URL, req.RemoteAddr, elapsed)
		if *debug {
			logger.Printf("Token: %v", token)
		}
		w.Header().Set("Authenticated-User", user)
		fmt.Fprint(w, token)
	}

	http.HandleFunc("/ktoken", ktoken)

	if (*tlsCrtPath != "") && (*tlsKeyPath != "") {
		logger.Println("tls")
		http.ListenAndServeTLS(*addr, *tlsCrtPath, *tlsKeyPath, nil)
	} else {
		logger.Println("plain http")
		http.ListenAndServe(*addr, nil)
	}
}
