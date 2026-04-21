package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ANSI color codes
const (
	RST  = "\033[0m"
	CYN  = "\033[36m"
	GRN  = "\033[32m"
	RED  = "\033[31m"
	YEL  = "\033[33m"
	BLU  = "\033[34m"
	MAG  = "\033[35m"
	GRY  = "\033[90m"
	BOLD = "\033[1m"
	DIM  = "\033[2m"
)

var statusDescriptions = map[int]string{
	200: "OK",
	201: "Created",
	204: "No Content",
	301: "Moved Permanently",
	302: "Found",
	304: "Not Modified",
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	408: "Request Timeout",
	429: "Too Many Requests",
	500: "Internal Server Error",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
}

func colorStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return GRN + strconv.Itoa(code) + RST
	case code >= 300 && code < 400:
		return BLU + strconv.Itoa(code) + RST
	case code >= 400 && code < 500:
		return YEL + strconv.Itoa(code) + RST
	case code >= 500:
		return RED + strconv.Itoa(code) + RST
	default:
		return GRY + strconv.Itoa(code) + RST
	}
}

func printBanner() {
	fmt.Println()
	fmt.Print(CYN + `   _____            __  _            __  _  __` + RST + "\n")
	fmt.Print(CYN + `  / ___/___  ____  / /_(_)___  ___  / / | |/ /` + RST + "\n")
	fmt.Print(CYN + `  \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ /  |   /` + RST + "\n")
	fmt.Print(CYN + ` ___/ /  __/ / / / /_/ / / / /  __/ /___/   |` + RST + "\n")
	fmt.Print(CYN + `/____/\___/_/ /_/\__/_/_/ /_/\___/_____/_/|_|` + RST + "\n")
	fmt.Println()
	fmt.Println(GRY + "  SentinelX HTTP" + RST + GRY + DIM + " — Web Status" + RST)
	fmt.Println(GRY + DIM + "  Author : WildanDev" + RST)
	fmt.Println()
}

type Result struct {
	URL    string
	Code   int
	Desc   string
	Err    string
}

func checkURL(rawURL string, timeout int) Result {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(rawURL)
	if err != nil {
		return Result{URL: rawURL, Code: 0, Err: "connection failed"}
	}
	defer resp.Body.Close()

	code := resp.StatusCode
	desc := statusDescriptions[code]
	if desc == "" {
		desc = "Unknown"
	}

	return Result{URL: rawURL, Code: code, Desc: desc}
}

func parseOnlyCodes(only string) ([]int, error) {
	var codes []int
	for _, s := range strings.Split(only, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("invalid status code: %s", s)
		}
		codes = append(codes, n)
	}
	return codes, nil
}

func contains(codes []int, code int) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}

func main() {
	file    := flag.String("file", "", "Input file containing URLs (one per line)")
	threads := flag.Int("threads", 10, "Number of concurrent workers")
	timeout := flag.Int("timeout", 10, "Request timeout in seconds")
	only    := flag.String("only", "", "Filter by status codes, comma-separated (e.g. 200,403)")
	save    := flag.String("save", "", "Save matched URLs to output file")
	flag.Parse()

	printBanner()

	if *file == "" {
		fmt.Println(RED + "  [ERR] --file is required" + RST)
		fmt.Println(GRY + "  Usage: sentinelx --file urls.txt [--threads 10] [--only 200] [--save out.txt]" + RST)
		fmt.Println()
		os.Exit(1)
	}

	// Parse --only
	var onlyCodes []int
	if *only != "" {
		var err error
		onlyCodes, err = parseOnlyCodes(*only)
		if err != nil {
			fmt.Println(RED + "  [ERR] " + err.Error() + RST)
			os.Exit(1)
		}
	}

	// Read input file
	f, err := os.Open(*file)
	if err != nil {
		fmt.Println(RED + "  [ERR] Cannot open file: " + *file + RST)
		os.Exit(1)
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}

	if len(urls) == 0 {
		fmt.Println(RED + "  [ERR] No URLs found in file" + RST)
		os.Exit(1)
	}

	// Print config
	fmt.Printf(GRY+"  Target   : %s%s\n"+RST, BOLD, *file)
	fmt.Printf(GRY+"  URLs     : %s%d%s\n", BOLD, len(urls), RST)
	fmt.Printf(GRY+"  Threads  : %s%d%s\n", BOLD, *threads, RST)
	fmt.Printf(GRY+"  Timeout  : %s%ds%s\n", BOLD, *timeout, RST)
	if len(onlyCodes) > 0 {
		fmt.Printf(GRY+"  Filter   : %s%s%s\n", BOLD, *only, RST)
	}
	if *save != "" {
		fmt.Printf(GRY+"  Output   : %s%s%s\n", BOLD, *save, RST)
	}
	fmt.Println()
	fmt.Println(GRY + DIM + "  " + strings.Repeat("-", 70) + RST)
	fmt.Println()

	// Worker pool
	jobs    := make(chan string, len(urls))
	resultsCh := make(chan Result, len(urls))
	var wg sync.WaitGroup

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				resultsCh <- checkURL(u, *timeout)
			}
		}()
	}

	for _, u := range urls {
		jobs <- u
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect and print
	var results []Result
	var mu sync.Mutex
	var saved []string

	startTime := time.Now()

	for r := range resultsCh {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()

		if r.Code == 0 {
			if len(onlyCodes) == 0 {
				fmt.Printf("  %s  %-25s  %s\n",
					GRY+"[---]"+RST,
					GRY+"connection-failed"+RST,
					GRY+r.URL+RST,
				)
			}
			continue
		}

		match := len(onlyCodes) == 0 || contains(onlyCodes, r.Code)
		if match {
			fmt.Printf("  [%s]  %-25s  %s\n",
				colorStatus(r.Code),
				GRY+r.Desc+RST,
				r.URL,
			)
			saved = append(saved, r.URL)
		}
	}

	elapsed := time.Since(startTime)

	// Save output
	if *save != "" && len(saved) > 0 {
		out, err := os.Create(*save)
		if err != nil {
			fmt.Println(RED + "\n  [ERR] Cannot create output file: " + *save + RST)
		} else {
			defer out.Close()
			w := bufio.NewWriter(out)
			for _, u := range saved {
				fmt.Fprintln(w, u)
			}
			w.Flush()
		}
	}

	// Summary
	var s200, s3xx, s4xx, s5xx, sErr int
	for _, r := range results {
		switch {
		case r.Code >= 200 && r.Code < 300:
			s200++
		case r.Code >= 300 && r.Code < 400:
			s3xx++
		case r.Code >= 400 && r.Code < 500:
			s4xx++
		case r.Code >= 500:
			s5xx++
		default:
			sErr++
		}
	}

	fmt.Println()
	fmt.Println(GRY + DIM + "  " + strings.Repeat("-", 70) + RST)
	fmt.Println()
	fmt.Printf("  "+BOLD+"Scan complete"+RST+GRY+"  %d URLs  //  %.2fs\n"+RST, len(results), elapsed.Seconds())
	fmt.Println()
	fmt.Printf("  "+GRN+"2xx"+RST+GRY+"  %-6d"+RST, s200)
	fmt.Printf("  "+BLU+"3xx"+RST+GRY+"  %-6d"+RST, s3xx)
	fmt.Printf("  "+YEL+"4xx"+RST+GRY+"  %-6d"+RST, s4xx)
	fmt.Printf("  "+RED+"5xx"+RST+GRY+"  %-6d"+RST, s5xx)
	fmt.Printf("  "+GRY+"err  %-6d"+RST, sErr)
	fmt.Println()
	if *save != "" {
		fmt.Printf("\n  "+GRY+"Saved %d URLs to %s%s\n"+RST, len(saved), BOLD+*save, RST)
	}
	fmt.Println()
}
