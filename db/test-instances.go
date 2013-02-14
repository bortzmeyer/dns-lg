/*
Connect to all DNS-LG instances currently declared and check they reply
*/

package main

import (
	"github.com/mreiferson/go-httpclient" // To have HTTP timeouts
	"launchpad.net/goyaml"

	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

type endpoints struct {
	Endpoint string
	Contact  string
	Status   string
}
type endpointsArray []endpoints

type queryObject struct {
	Versions string
	// We ignore the other fields 
}
type dnslgResponse struct {
	Query queryObject
	// We ignore the other fields 
}

type instanceTest struct {
	ok      bool
	url     string
	message string
}

var (
	verbose *bool
)

func reporter(comm chan instanceTest, over chan string, number int) {
	for i := 0; i < number; i++ {
		result := <-comm
		if *verbose || !result.ok {
			fmt.Printf("%s: %s\n", result.url, result.message)
		}
	}
	over <- "DONE"
}

func checkOne(comm chan instanceTest, url string) {
	var (
		object dnslgResponse
	)
	client := httpclient.New()
	client.ConnectTimeout = 5 * time.Second
	client.ReadWriteTimeout = 5 * time.Second
	// TODO: the format=json is redundant with the Accept header but, as of 2013-02-14, some instances still run the old code, without content negotiation
	request, err := http.NewRequest("GET", fmt.Sprintf("%s/example.org/NS?format=json", url), nil)
	if err != nil {
		comm <- instanceTest{false, url, fmt.Sprintf("Cannot create request: %s", err)}
		return
	}
	request.Header.Add("Accept", "application/json")
	request.Header.Add("User-Agent", "DNS Looking Glass Checker")
	response, err := client.Do(request)
	if err != nil {
		comm <- instanceTest{false, url, fmt.Sprintf("Cannot get: %s", err)}
		return
	}
	if response.StatusCode != http.StatusOK {
		comm <- instanceTest{false, url, fmt.Sprintf("Bad status: %s", response.Status)}
		return
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		comm <- instanceTest{false, url, fmt.Sprintf("Cannot read body: %s", err)}
		return
	}
	if len(body) == 0 {
		comm <- instanceTest{false, url, fmt.Sprintf("Got an empty body: %s", err)}
		return
	}
	err = json.Unmarshal(body, &object)
	if err != nil {
		comm <- instanceTest{false, url, fmt.Sprintf("Cannot parse the JSON result: %s", err)}
		return
	}
	comm <- instanceTest{true, url, fmt.Sprintf("OK (%d bytes) %s", len(body), object.Query.Versions)}
}

func main() {
	var (
		filename string
	)
	verbose = flag.Bool("v", false, "verbose mode, displays a line for every instance")
	flag.Parse()
	if flag.NArg() == 1 {
		filename = flag.Arg(0)
	} else {
		panic("Usage: test-instances filename.yaml\n")
	}
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	data := make([]byte, 1000000)
	count, err := file.Read(data)
	if err != nil {
		panic(err)
	}
	list := endpointsArray{}
	err = goyaml.Unmarshal(data[:count], &list)
	if err != nil {
		panic(err)
	}
	toReporter := make(chan instanceTest)
	fromReporter := make(chan string)
	go reporter(toReporter, fromReporter, len(list))

	for i := 0; i < len(list); i++ {
		go checkOne(toReporter, list[i].Endpoint)
	}
	<-fromReporter
}
