package main

import (
	"os"
	"log"
	"fmt"
	"time"
	"flag"
	"context"
	"strings"
	"net/http"
	"github.com/dgrijalva/jwt-go"
	"github.com/avinashtanniru/go-mod/adi"
)

// Secret key for token validation
var secretKey = []byte("qwerty-qwerty")

// Custom ResponseWriter to track status code
type statusRecorder struct {
    http.ResponseWriter
    status int
}

func (sr *statusRecorder) WriteHeader(code int) {
    sr.status = code
    sr.ResponseWriter.WriteHeader(code)
}

func accessLogHandler(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Custom ResponseWriter to track status code
        recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

        // Call the next handler
        next.ServeHTTP(recorder, r)

        // Log the request along with status
        log.Printf("[%s] %s %s %s - Status: %d", time.Now().Format(time.RFC3339), r.RemoteAddr, r.Method, r.URL.Path, recorder)
    })
}

func apbHandler(w http.ResponseWriter, r *http.Request, mongoFlagValue string, dbName string, colName string){

	// Ensure only POST requests are allowed
    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "This request is NOT allowed")

        return
    }

	// Extract the JWT token from the request headers
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

	// Parse the JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Return the secret key for verification
		return secretKey, nil
	})
	if err != nil {
		fmt.Println("Error parsing JWT token:", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Check if the token is valid
	if !token.Valid {
		fmt.Println("Invalid JWT token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Extract claims from the token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Error extracting claims from JWT token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Validate expiration time
	expirationTime := time.Unix(int64(claims["exp"].(float64)), 0)
	if time.Now().After(expirationTime) {
		fmt.Println("JWT token has expired")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Extract data from claims
	zone, ok := claims["zone"].(string)
	if !ok {
		fmt.Println("Error extracting username from JWT token claims")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	hosts, ok := claims["hosts"].(string)
	group, ok := claims["group"].(string)


	// Respond with a success message
	w.WriteHeader(http.StatusOK)
	// fmt.Fprintf(w, "Zone: %s", zone)

	// // Create a new context
    ctx := context.Background()

    // Create a new MongoDB connection
    mongoDB, err := adi.MDb(ctx, mongoFlagValue, dbName, colName)
    if err != nil {
        log.Fatal("Error connecting to MongoDB:", err)
    }

	defer func() {
        if err := mongoDB.Close(); err != nil {
            log.Fatal("Error closing MongoDB connection:", err)
        }
    }()

	var Groups []adi.Group

	var fGroups = []string{
      "hosts",
      "containers",
	}

	for _, name := range fGroups {
		g, err := mongoDB.Getgroups(name, false)
		if err != nil {
			fmt.Printf("Error finding document : %s\n", err)
		}
		Groups = append(Groups, g...)
	}
	var hostregx string
	if group != "" {
		a, err := mongoDB.Hostgroup(group, zone)
		if err != nil {
			fmt.Fprintf(w, "Error finding HostGroup : %s\n", err)
		}
		hostregx = adi.Validate(a)
	}

	if hosts != "" {
		hostregx = adi.Validate(strings.Split(hosts, ","))
	}
	g, err := mongoDB.Getgroups(hostregx, true)
	Groups = append(Groups, g...)

	var Hosts []adi.HostVars
	// fmt.Println(Groups)
	h, err := mongoDB.Gethosts(hostregx, "host_vars")
	if err != nil {
		fmt.Printf("Error finding document : %s\n", err)
	}
	Hosts = append(Hosts, h...)
	// fmt.Println(Hosts)
	var makedata = adi.Data{Groups: Groups, Hosts: Hosts}
	b, err := makedata.GenerateJSON()
	// fmt.Println(b.String())
	fmt.Fprintf(w, "%s", b.String())


}

func main() {

	// Define flags
  mongoFlag := flag.String("mongo", "", "Value for the mongo Ex: mongodb://localhost:27017")
	dbName := flag.String("db", "ansible", "DB Name for Ansible")
	colName := flag.String("colName", "groups", "Collection Name for Ansible")
	port := flag.String("port", "8080", "Default Port Example: 8080")

	flag.Usage = func() {
        fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", "ansible-inventory")
        flag.PrintDefaults()
    }

	// Parse command-line flags
    flag.Parse()

	// Check if mongoFlag is provided
	if *mongoFlag == "" {
		fmt.Println("Error: mongo parameter is required")
		flag.Usage()
		os.Exit(1)
	}

    // Create a new HTTP multiplexer
    mux := http.NewServeMux()

    // Register handlers
	mux.HandleFunc("/apb", func(w http.ResponseWriter, r *http.Request) {
	
		// Call the handler function with the flag value
		apbHandler(w, r, *mongoFlag, *dbName, *colName)
	})
	

    fmt.Println("Server listening on port "+ *port +"...")
    // Attach access log middleware
    http.ListenAndServe(":" + *port, accessLogHandler(mux))
}
