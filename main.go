package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	RST     = "\033[0m"
	CYN     = "\033[36m"
	GRN     = "\033[32m"
	RED     = "\033[31m"
	YEL     = "\033[33m"
	BLU     = "\033[34m"
	MAG     = "\033[35m"
	GRY     = "\033[90m"
	BOLD    = "\033[1m"
	DIM     = "\033[2m"
	Version = "v1.0.3"
)

func checkVersion() {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/SentinelXoffical/sxhttp/releases/latest")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var data struct {
		TagName string `json:"tag_name"`
	}
	json.NewDecoder(resp.Body).Decode(&data)

	if data.TagName == "" {
		return
	}

	if data.TagName != Version {
		fmt.Printf(GRY+"  [INF] Current sxhttp version: "+BOLD+"%s"+RST+YEL+" (outdated, latest: %s)"+RST+"\n\n", Version, data.TagName)
	} else {
		fmt.Printf(GRY+"  [INF] Current sxhttp version: "+BOLD+"%s"+RST+GRN+" (latest)"+RST+"\n\n", Version)
	}
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
	"curl/8.7.1",
	"python-requests/2.31.0",
	"Go-http-client/1.1",
}

var wafSignatures = map[string]string{
	"cloudflare":     "Cloudflare",
	"cf-ray":         "Cloudflare",
	"x-sucuri-id":    "Sucuri",
	"x-sucuri-cache": "Sucuri",
	"x-fw-protect":   "Wordfence",
	"x-cdn":          "CDN",
	"x-akamai":       "Akamai",
	"x-amz-cf-id":    "AWS CloudFront",
	"x-azure-ref":    "Azure CDN",
	"x-ddos-guard":   "DDoS-Guard",
	"x-protected-by": "WAF",
}

var techSignatures = []struct {
	Header string
	Value  string
	Body   string
	Name   string
}{
	{Header: "x-powered-by", Value: "php", Name: "PHP"},
	{Header: "x-powered-by", Value: "asp.net", Name: "ASP.NET"},
	{Header: "x-powered-by", Value: "express", Name: "Express.js"},
	{Header: "server", Value: "apache", Name: "Apache"},
	{Header: "server", Value: "nginx", Name: "Nginx"},
	{Header: "server", Value: "iis", Name: "IIS"},
	{Header: "server", Value: "litespeed", Name: "LiteSpeed"},
	{Header: "x-generator", Value: "wordpress", Name: "WordPress"},
	{Body: "wp-content/themes", Name: "WordPress"},
	{Body: "wp-content/plugins", Name: "WordPress"},
	{Body: "drupal.js", Name: "Drupal"},
	{Body: "joomla", Name: "Joomla"},
	{Body: "laravel", Name: "Laravel"},
	{Body: "codeigniter", Name: "CodeIgniter"},
	{Body: "symfony", Name: "Symfony"},
	{Body: "django", Name: "Django"},
	{Body: "react", Name: "React"},
	{Body: "vue.js", Name: "Vue.js"},
	{Body: "angular", Name: "Angular"},
	{Header: "set-cookie", Value: "phpsessid", Name: "PHP"},
	{Header: "set-cookie", Value: "asp.net_sessionid", Name: "ASP.NET"},
	{Header: "set-cookie", Value: "laravel_session", Name: "Laravel"},
}

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

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>([^<]{1,200})</title>`)

func randomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
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

func colorRT(ms int64) string {
	switch {
	case ms < 500:
		return GRN + fmt.Sprintf("%dms", ms) + RST
	case ms < 1500:
		return YEL + fmt.Sprintf("%dms", ms) + RST
	default:
		return RED + fmt.Sprintf("%dms", ms) + RST
	}
}

func detectWAF(headers http.Header, server string) string {
	serverLower := strings.ToLower(server)
	if strings.Contains(serverLower, "cloudflare") {
		return "Cloudflare"
	}
	if strings.Contains(serverLower, "ddos-guard") {
		return "DDoS-Guard"
	}
	for h, waf := range wafSignatures {
		if headers.Get(h) != "" {
			return waf
		}
	}
	return ""
}

func detectTech(headers http.Header, body string) []string {
	seen := map[string]bool{}
	var techs []string
	bodyLower := strings.ToLower(body)

	for _, sig := range techSignatures {
		if seen[sig.Name] {
			continue
		}
		if sig.Header != "" {
			val := strings.ToLower(headers.Get(sig.Header))
			if val != "" && (sig.Value == "" || strings.Contains(val, sig.Value)) {
				seen[sig.Name] = true
				techs = append(techs, sig.Name)
				continue
			}
		}
		if sig.Body != "" && strings.Contains(bodyLower, sig.Body) {
			seen[sig.Name] = true
			techs = append(techs, sig.Name)
		}
	}
	return techs
}

func extractTitle(body string) string {
	match := titleRegex.FindStringSubmatch(body)
	if len(match) > 1 {
		title := strings.TrimSpace(match[1])
		title = strings.ReplaceAll(title, "\n", " ")
		title = strings.ReplaceAll(title, "\r", "")
		if len(title) > 60 {
			title = title[:57] + "..."
		}
		return title
	}
	return ""
}

type Result struct {
	URL          string   `json:"url"`
	Code         int      `json:"status_code"`
	Desc         string   `json:"status_desc"`
	Title        string   `json:"title,omitempty"`
	Tech         []string `json:"tech,omitempty"`
	WAF          string   `json:"waf,omitempty"`
	ResponseTime int64    `json:"response_time_ms"`
	Error        string   `json:"error,omitempty"`
}

func doRequest(url string, timeout int) (*http.Response, string, int64, error) {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("User-Agent", randomUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return nil, "", elapsed, err
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
	resp.Body.Close()
	body := string(bodyBytes)

	return resp, body, elapsed, nil
}

func checkURL(rawURL string, timeout int) Result {
	rawURL = strings.TrimSpace(rawURL)

	var schemes []string
	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		schemes = []string{rawURL}
	} else {
		schemes = []string{"https://" + rawURL, "http://" + rawURL}
	}

	for _, url := range schemes {
		resp, body, elapsed, err := doRequest(url, timeout)
		if err != nil {
			continue
		}

		code := resp.StatusCode
		desc := statusDescriptions[code]
		if desc == "" {
			desc = "Unknown"
		}

		title := extractTitle(body)
		tech := detectTech(resp.Header, body)
		waf := detectWAF(resp.Header, resp.Header.Get("Server"))

		return Result{
			URL:          url,
			Code:         code,
			Desc:         desc,
			Title:        title,
			Tech:         tech,
			WAF:          waf,
			ResponseTime: elapsed,
		}
	}

	return Result{URL: rawURL, Code: 0, Error: "connection failed"}
}

func parseOnlyCodes(s string) ([]int, error) {
	var codes []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid status code: %s", p)
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
	checkVersion()
}

func main() {
	file     := flag.String("file", "", "Input file containing URLs (one per line)")
	threads  := flag.Int("threads", 10, "Number of concurrent workers")
	timeout  := flag.Int("timeout", 10, "Request timeout in seconds")
	only     := flag.String("only", "", "Show only these status codes (e.g. 200,403)")
	exclude  := flag.String("exclude", "", "Exclude these status codes (e.g. 404,301)")
	save     := flag.String("save", "", "Save matched URLs to output file")
	saveJSON := flag.String("json", "", "Save full results as JSON (e.g. out.json)")
	silent   := flag.Bool("silent", false, "Only print URLs, no banner or summary")
	noWAF    := flag.Bool("no-waf", false, "Disable WAF detection")
	noTech   := flag.Bool("no-tech", false, "Disable tech detection")
	noTitle  := flag.Bool("no-title", false, "Disable title grabbing")
	rate     := flag.Int("rate", 0, "Max requests per second (0 = unlimited)")
	flag.Parse()

	if !*silent {
		printBanner()
	}

	var onlyCodes, excludeCodes []int
	var err error
	if *only != "" {
		onlyCodes, err = parseOnlyCodes(*only)
		if err != nil {
			fmt.Println(RED + "  [ERR] " + err.Error() + RST)
			os.Exit(1)
		}
	}
	if *exclude != "" {
		excludeCodes, err = parseOnlyCodes(*exclude)
		if err != nil {
			fmt.Println(RED + "  [ERR] " + err.Error() + RST)
			os.Exit(1)
		}
	}

	// Read URLs
	var urls []string
	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			fmt.Println(RED + "  [ERR] Cannot open file: " + *file + RST)
			os.Exit(1)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			urls = append(urls, line)
		}
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				urls = append(urls, line)
			}
		} else {
			fmt.Println(RED + "  [ERR] --file is required or pipe URLs via stdin" + RST)
			fmt.Println(GRY + "  Usage: sxhttp --file urls.txt [--threads 10] [--only 200] [--save out.txt]" + RST)
			fmt.Println(GRY + "         cat urls.txt | sxhttp --only 200" + RST)
			fmt.Println()
			os.Exit(1)
		}
	}

	if len(urls) == 0 {
		fmt.Println(RED + "  [ERR] No URLs found" + RST)
		os.Exit(1)
	}

	if !*silent {
		src := *file
		if src == "" {
			src = "stdin"
		}
		fmt.Printf(GRY+"  Target   : %s%s\n"+RST, BOLD, src)
		fmt.Printf(GRY+"  URLs     : %s%d%s\n", BOLD, len(urls), RST)
		fmt.Printf(GRY+"  Threads  : %s%d%s\n", BOLD, *threads, RST)
		fmt.Printf(GRY+"  Timeout  : %s%ds%s\n", BOLD, *timeout, RST)
		if *rate > 0 {
			fmt.Printf(GRY+"  Rate     : %s%d/s%s\n", BOLD, *rate, RST)
		}
		if len(onlyCodes) > 0 {
			fmt.Printf(GRY+"  Filter   : %s%s%s\n", BOLD, *only, RST)
		}
		if len(excludeCodes) > 0 {
			fmt.Printf(GRY+"  Exclude  : %s%s%s\n", BOLD, *exclude, RST)
		}
		if *save != "" {
			fmt.Printf(GRY+"  Output   : %s%s%s\n", BOLD, *save, RST)
		}
		if *saveJSON != "" {
			fmt.Printf(GRY+"  JSON     : %s%s%s\n", BOLD, *saveJSON, RST)
		}
		fmt.Println()
		fmt.Println(GRY + DIM + "  " + strings.Repeat("-", 70) + RST)
		fmt.Println()
	}

	// Rate limiter
	var rateLimiter <-chan time.Time
	if *rate > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(*rate))
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	jobs      := make(chan string, len(urls))
	resultsCh := make(chan Result, len(urls))
	var wg sync.WaitGroup

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				if rateLimiter != nil {
					<-rateLimiter
				}
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

	var results []Result
	var mu sync.Mutex
	var saved []string
	startTime := time.Now()

	for r := range resultsCh {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()

		if r.Code == 0 {
			if len(onlyCodes) == 0 && !*silent {
				fmt.Printf("  %s  %-20s  %-10s  %s\n",
					GRY+"[---]"+RST,
					GRY+"connection-failed"+RST,
					GRY+"---"+RST,
					GRY+r.URL+RST,
				)
			}
			continue
		}

		if len(onlyCodes) > 0 && !contains(onlyCodes, r.Code) {
			continue
		}
		if len(excludeCodes) > 0 && contains(excludeCodes, r.Code) {
			continue
		}

		saved = append(saved, r.URL)

		if *silent {
			fmt.Println(r.URL)
			continue
		}

		wafLabel := ""
		if !*noWAF && r.WAF != "" {
			wafLabel = "  " + MAG + "[" + r.WAF + "]" + RST
		}

		techLabel := ""
		if !*noTech && len(r.Tech) > 0 {
			techLabel = "  " + CYN + "[" + strings.Join(r.Tech, ", ") + "]" + RST
		}

		titleLabel := ""
		if !*noTitle && r.Title != "" {
			titleLabel = "  " + GRY + DIM + "\"" + r.Title + "\"" + RST
		}

		fmt.Printf("  [%s]  %-20s  %-10s  %s%s%s%s\n",
			colorStatus(r.Code),
			GRY+r.Desc+RST,
			colorRT(r.ResponseTime),
			r.URL,
			wafLabel,
			techLabel,
			titleLabel,
		)
	}

	elapsed := time.Since(startTime)

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

	if *saveJSON != "" {
		jsonOut, err := os.Create(*saveJSON)
		if err != nil {
			fmt.Println(RED + "\n  [ERR] Cannot create JSON file: " + *saveJSON + RST)
		} else {
			defer jsonOut.Close()
			enc := json.NewEncoder(jsonOut)
			enc.SetIndent("", "  ")
			enc.Encode(results)
		}
	}

	if *silent {
		return
	}

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
	if *saveJSON != "" {
		fmt.Printf("  "+GRY+"JSON saved to %s%s\n"+RST, BOLD+*saveJSON, RST)
	}
	fmt.Println()
}
