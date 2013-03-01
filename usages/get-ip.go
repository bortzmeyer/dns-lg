/* Use the DNS looking-glass to ask the IP addresses for a given
domain name. It may help to pinpoint local problems, lying resolvers,
censorship, etc. */

package main

import (
	"fmt"
	"os"
	"time"
	"io/ioutil"
	"net/http"
	"encoding/json"
	"github.com/miekg/dns"
	"github.com/mreiferson/go-httpclient" // To have HTTP timeouts
)

const (
	BASE string = "existing-dns-lg.bortzmeyer.fr."
)

type answerObject struct {
	Type    string
	Address string
	// We ignore the other fields
}
type dnslgResponse struct {
	AnswerSection []answerObject
	// We ignore the other fields
}

type instanceQuery struct {
	ok        bool
	url       string
	addresses []string
	message   string
}

func queryOne(comm chan instanceQuery, url string, name string) {
	var (
		object dnslgResponse
	)
	client := httpclient.New()
	client.ConnectTimeout = 5 * time.Second
	client.ReadWriteTimeout = 5 * time.Second
	// TODO: the format=json is redundant with the Accept header but, as of 2013-02-14, some instances still run the old code, without content negotiation
	request, err := http.NewRequest("GET", fmt.Sprintf("%s/%s/ADDR?format=json", url, name), nil)
	if err != nil {
		comm <- instanceQuery{false, url, nil, fmt.Sprintf("Cannot create the HTTP request for %s\n", url)}
		return
	}
	request.Header.Add("Accept", "application/json")
	request.Header.Add("User-Agent", "DNS Looking Glass Querier")
	response, err := client.Do(request)
	if err != nil {
		comm <- instanceQuery{false, url, nil, fmt.Sprintf("Cannot execute the HTTP request: %s\n", err)}
		return
	}
	if response.StatusCode != http.StatusOK {
		comm <- instanceQuery{false, url, nil, fmt.Sprintf("Bad status for %s: %s", url, response.Status)}
		return
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		comm <- instanceQuery{false, url, nil, fmt.Sprintf("Cannot read body for %s: %s", url, err)}
		return
	}
	if len(body) == 0 {
		comm <- instanceQuery{false, url, nil, fmt.Sprintf("Got an empty body for %s: %s", url, err)}
		return
	}
	err = json.Unmarshal(body, &object)
	if err != nil {
		comm <- instanceQuery{false, url, nil, fmt.Sprintf("Cannot parse the JSON result of %s: %s", err)}
		return
	}
	addresses := make([]string, len(object.AnswerSection))
	for i := 0; i < len(object.AnswerSection); i++ {
		addresses[i] = object.AnswerSection[i].Address
	}
	comm <- instanceQuery{true, url, addresses, ""}
}

func reporter(comm chan instanceQuery, over chan string, number int) {
	for i := 0; i < number; i++ {
		result := <-comm
		if result.ok {
			fmt.Printf("%s: %s\n", result.url, result.addresses)
		} else {
			fmt.Printf("%s: ERROR %s\n", result.url, result.message)
		}
	}
	over <- "DONE"
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("%s NAME\n", os.Args[0])
		os.Exit(1)
	}
	name := os.Args[1]
	conf, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	client := new(dns.Client)
	message := new(dns.Msg)
	message.Question = make([]dns.Question, 1)
	message.Question[0] = dns.Question{BASE, dns.TypeTXT, dns.ClassINET}
	message.SetEdns0(4096, true)
	message.RecursionDesired = true
	reply, _, err := client.Exchange(message, conf.Servers[0]+":"+conf.Port)
	if err != nil {
		fmt.Printf("Cannot get info for %s: %s\n", BASE, err)
		os.Exit(1)
	}
	if reply.Rcode != dns.RcodeSuccess {
		fmt.Printf("Bad answer from the resolver: %v\n", reply.Rcode)
		os.Exit(1)
	}
	if len(reply.Answer) == 0 {
		fmt.Printf("Zero answer for %s\n", BASE)
		os.Exit(1)
	}
	toReporter := make(chan instanceQuery)
	urls := 0
	for _, rr := range reply.Answer {
		switch rr.(type) {
		case *dns.TXT:
			url := rr.(*dns.TXT).Txt[0]
			urls++
			go queryOne(toReporter, url, name)
		}
		// Otherwise, ignore it. Probably a DNSSEC signature
	}
	fromReporter := make(chan string)
	go reporter(toReporter, fromReporter, urls)
	<-fromReporter

}
