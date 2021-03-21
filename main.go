package main

import (
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"os"
	"strings"
	"time"
)

var (
	client = dns.Client{
		Timeout: 4 * time.Second,
	}

	address = "1.1.1.1"
	zone    = ""

	flagSet  = flag.NewFlagSet("walk", flag.ExitOnError)
	fullWalk = flagSet.Bool("f", false, "Do a full zone walk")
	start    = flagSet.String("s", "", "Start walk with this owner name")
	port     = flagSet.String("p", "53", "Specify port number")

	usage = func() {
		w := flag.CommandLine.Output()
		fmt.Fprintf(w, "Usage: %s [@nameserver] [options] zone\n", os.Args[0])
		fmt.Fprintf(w, "[options]:\n")
		flagSet.PrintDefaults()
	}
)

func main() {
	parseArgs(os.Args[1:])
	zone := dns.Fqdn(zone)

	next := nextName(zone, true)
	if *start != "" {
		next = nextName(*start, false)
	}

	for {
		res, err := query(next, dns.TypeDS)
		if err != nil {
			fmt.Fprintf(os.Stderr, "query: %s %s\n", next, dns.TypeToString[dns.TypeDS])
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		nsecRecords := extractRRSet(res.Ns, dns.TypeNSEC)
		if len(nsecRecords) == 0 {
			fmt.Fprintf(os.Stderr, "No NSEC records found in authority section:\n%v", res)
			os.Exit(1)
		}

		nsec := nsecRecords[0].(*dns.NSEC)

		// likely using NSEC black lies
		// https://blog.cloudflare.com/black-lies/
		if strings.HasPrefix(nsec.NextDomain, "\\000.\\000") {
			fmt.Fprintf(os.Stderr, "This zone is likely using online signing\n\n%v\n", res)
			os.Exit(1)
		}

		if *fullWalk {
			lookupBitmap(nsec)
		} else {
			fmt.Printf("%s %s\n", nsec.NextDomain, bitmapToString(nsec))
		}

		if nsec.NextDomain == zone {
			break
		}
		next = nextName(nsec.NextDomain, false)
	}
}

func lookupBitmap(nsec *dns.NSEC) {
	for _, t := range nsec.TypeBitMap {
		r, err := query(nsec.Header().Name, t)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		for _, rr := range r.Answer {
			fmt.Println(rr)
		}

		// glue records
		if t == dns.TypeNS && len(r.Answer) == 0 && r.Rcode == dns.RcodeSuccess {
			for _, rr := range r.Ns {
				fmt.Println(rr)
			}
			for _, rr := range r.Extra {
				if rr.Header().Rrtype != dns.TypeOPT {
					fmt.Println(rr)
				}
			}
		}
	}
}

func bitmapToString(rr *dns.NSEC) string {
	s := ""
	for _, t := range rr.TypeBitMap {
		s += " " + dns.Type(t).String()
	}
	return s
}

func nextName(qname string, first bool) string {
	if qname == "." {
		return "\\000."
	}

	if first {
		return "\\000." + qname
	}

	labels := dns.SplitDomainName(qname)
	labels[0] = labels[0] + "\\000"
	return dns.Fqdn(strings.Join(labels, "."))
}

func query(qname string, qtype uint16) (r *dns.Msg, err error) {
	retry := 0
	for {
		m := new(dns.Msg)
		m.RecursionDesired = true
		m.AuthenticatedData = true
		m.SetQuestion(dns.Fqdn(qname), qtype)
		m.SetEdns0(4096, true)
		r, _, err = client.Exchange(m, address+":"+*port)

		if err == nil || retry > 3 {
			return
		}

		time.Sleep(time.Second * 2)
		retry++
	}
}

func extractRRSet(rrs []dns.RR, qtype uint16) []dns.RR {
	var set []dns.RR
	for _, r := range rrs {
		if r.Header().Rrtype == qtype {
			set = append(set, r)
		}
	}

	return set
}

func parseArgs(args []string) {
	flagSet.Usage = usage
	var flags []string

	needVal := false
	for _, arg := range args {
		if len(arg) < 2 {
			continue
		}

		switch arg[0] {
		case '@':
			address = arg[1:]
		case '-':
			// -f is the only flag that doesn't need a value
			needVal = arg[1] != 'f'
			flags = append(flags, arg)
		default:
			if needVal {
				flags = append(flags, arg)
				needVal = false
				continue
			}
			zone = arg
		}
	}

	if zone == "" {
		flagSet.Usage()
		os.Exit(1)
	}

	flagSet.Parse(flags)
}
