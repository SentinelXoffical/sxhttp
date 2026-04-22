package main

import (
	"bufio"
	"encoding/csv"
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
	Version = "v1.0.4"
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

// CMS version patterns
var cmsVersionPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"WordPress", regexp.MustCompile(`(?i)<meta name="generator" content="WordPress ([0-9.]+)"`)},
	{"Drupal", regexp.MustCompile(`(?i)Drupal ([0-9.]+)`)},
	{"Joomla", regexp.MustCompile(`(?i)<meta name="generator" content="Joomla! ([0-9.]+)"`)},
	{"Laravel", regexp.MustCompile(`(?i)laravel/([0-9.]+)`)},
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

// Default credentials hints
var defaultCreds = map[string]string{
	"cPanel":     "admin:admin | root:root",
	"WordPress":  "admin:admin | admin:password",
	"Laravel":    "admin@example.com:password",
	"CodeIgniter": "admin:admin",
	"phpMyAdmin": "root:(empty) | root:root",
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

func colorSize(bytes int64) string {
	switch {
	case bytes < 1024:
		return GRY + fmt.Sprintf("%dB", bytes) + RST
	case bytes < 1024*1024:
		return GRY + fmt.Sprintf("%.1fKB", float64(bytes)/1024) + RST
	default:
		return GRY + fmt.Sprintf("%.1fMB", float64(bytes)/1024/1024) + RST
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

func detectCMSVersion(body string) string {
	for _, p := range cmsVersionPatterns {
		match := p.Pattern.FindStringSubmatch(body)
		if len(match) > 1 {
			return p.Name + " " + match[1]
		}
	}
	return ""
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

func getDefaultCred(title string, techs []string) string {
	titleLower := strings.ToLower(title)
	if strings.Contains(titleLower, "cpanel") {
		return defaultCreds["cPanel"]
	}
	if strings.Contains(titleLower, "phpmyadmin") {
		return defaultCreds["phpMyAdmin"]
	}
	for _, tech := range techs {
		if cred, ok := defaultCreds[tech]; ok {
			return cred
		}
	}
	return ""
}

type Result struct {
	URL           string   `json:"url"`
	Code          int      `json:"status_code"`
	Desc          string   `json:"status_desc"`
	Title         string   `json:"title,omitempty"`
	Tech          []string `json:"tech,omitempty"`
	CMSVersion    string   `json:"cms_version,omitempty"`
	WAF           string   `json:"waf,omitempty"`
	ResponseTime  int64    `json:"response_time_ms"`
	ContentLength int64    `json:"content_length"`
	Redirects     []string `json:"redirects,omitempty"`
	DefaultCred   string   `json:"default_cred,omitempty"`
	Error         string   `json:"error,omitempty"`
}

func doRequest(url string, timeout int, extraHeaders map[string]string) (*http.Response, string, int64, int64, error) {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", 0, 0, err
	}
	req.Header.Set("User-Agent", randomUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return nil, "", elapsed, 0, err
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
	resp.Body.Close()
	body := string(bodyBytes)
	size := resp.ContentLength
	if size < 0 {
		size = int64(len(bodyBytes))
	}

	return resp, body, elapsed, size, nil
}

func followRedirects(startURL string, timeout int, extraHeaders map[string]string) []string {
	var chain []string
	current := startURL
	seen := map[string]bool{}

	for i := 0; i < 10; i++ {
		if seen[current] {
			break
		}
		seen[current] = true

		client := &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		req, err := http.NewRequest("GET", current, nil)
		if err != nil {
			break
		}
		req.Header.Set("User-Agent", randomUA())
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			break
		}
		resp.Body.Close()

		code := resp.StatusCode
		if code >= 300 && code < 400 {
			loc := resp.Header.Get("Location")
			if loc == "" {
				break
			}
			chain = append(chain, fmt.Sprintf("%d → %s", code, loc))
			current = loc
		} else {
			break
		}
	}
	return chain
}

func checkURL(rawURL string, timeout, retries int, extraHeaders map[string]string) Result {
	rawURL = strings.TrimSpace(rawURL)

	var schemes []string
	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		schemes = []string{rawURL}
	} else {
		schemes = []string{"https://" + rawURL, "http://" + rawURL}
	}

	for _, url := range schemes {
		var resp *http.Response
		var body string
		var elapsed, size int64
		var err error

		for attempt := 0; attempt <= retries; attempt++ {
			resp, body, elapsed, size, err = doRequest(url, timeout, extraHeaders)
			if err == nil {
				break
			}
			if attempt < retries {
				time.Sleep(500 * time.Millisecond)
			}
		}

		if err != nil {
			continue
		}

		code := resp.StatusCode
		desc := statusDescriptions[code]
		if desc == "" {
			desc = "Unknown"
		}

		title      := extractTitle(body)
		tech       := detectTech(resp.Header, body)
		cmsVersion := detectCMSVersion(body)
		waf        := detectWAF(resp.Header, resp.Header.Get("Server"))
		defCred    := getDefaultCred(title, tech)

		var redirects []string
		if code >= 300 && code < 400 {
			redirects = followRedirects(url, timeout, extraHeaders)
		}

		return Result{
			URL:           url,
			Code:          code,
			Desc:          desc,
			Title:         title,
			Tech:          tech,
			CMSVersion:    cmsVersion,
			WAF:           waf,
			ResponseTime:  elapsed,
			ContentLength: size,
			Redirects:     redirects,
			DefaultCred:   defCred,
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

func parseHeaders(raw string) map[string]string {
	headers := map[string]string{}
	if raw == "" {
		return headers
	}
	for _, h := range strings.Split(raw, ";;") {
		parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
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
	retries  := flag.Int("retry", 0, "Number of retries on failure")
	only     := flag.String("only", "", "Show only these status codes (e.g. 200,403)")
	exclude  := flag.String("exclude", "", "Exclude these status codes (e.g. 404,301)")
	save     := flag.String("save", "", "Save matched URLs to output file")
	saveJSON := flag.String("json", "", "Save full results as JSON")
	saveCSV  := flag.String("csv", "", "Save full results as CSV")
	silent   := flag.Bool("silent", false, "Only print URLs, no banner or summary")
	noWAF    := flag.Bool("no-waf", false, "Disable WAF detection")
	noTech   := flag.Bool("no-tech", false, "Disable tech detection")
	noTitle  := flag.Bool("no-title", false, "Disable title grabbing")
	noSize   := flag.Bool("no-size", false, "Disable content length")
	showCred := flag.Bool("cred", false, "Show default credential hints")
	showRedir:= flag.Bool("redirect", false, "Show redirect chain for 3xx")
	rate     := flag.Int("rate", 0, "Max requests per second (0 = unlimited)")
	headers  := flag.String("header", "", "Custom headers, semicolon-separated (e.g. 'X-Forwarded-For:127.0.0.1;;Cookie:session=abc')")
	flag.Parse()

	if !*silent {
		printBanner()
	}

	extraHeaders := parseHeaders(*headers)

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
		if *retries > 0 {
			fmt.Printf(GRY+"  Retry    : %s%d%s\n", BOLD, *retries, RST)
		}
		if *rate > 0 {
			fmt.Printf(GRY+"  Rate     : %s%d/s%s\n", BOLD, *rate, RST)
		}
		if len(extraHeaders) > 0 {
			fmt.Printf(GRY+"  Headers  : %s%s%s\n", BOLD, *headers, RST)
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
		if *saveCSV != "" {
			fmt.Printf(GRY+"  CSV      : %s%s%s\n", BOLD, *saveCSV, RST)
		}
		fmt.Println()
		fmt.Println(GRY + DIM + "  " + strings.Repeat("-", 70) + RST)
		fmt.Println()
	}

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
				resultsCh <- checkURL(u, *timeout, *retries, extraHeaders)
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
			t := r.Tech
			if r.CMSVersion != "" {
				// replace generic CMS name with versioned one
				for i, tech := range t {
					for _, p := range cmsVersionPatterns {
						if strings.HasPrefix(r.CMSVersion, p.Name) && tech == p.Name {
							t[i] = r.CMSVersion
						}
					}
				}
			}
			techLabel = "  " + CYN + "[" + strings.Join(t, ", ") + "]" + RST
		}

		titleLabel := ""
		if !*noTitle && r.Title != "" {
			titleLabel = "  " + GRY + DIM + "\"" + r.Title + "\"" + RST
		}

		sizeLabel := ""
		if !*noSize {
			sizeLabel = "  " + colorSize(r.ContentLength)
		}

		fmt.Printf("  [%s]  %-20s  %-10s%s  %s%s%s%s\n",
			colorStatus(r.Code),
			GRY+r.Desc+RST,
			colorRT(r.ResponseTime),
			sizeLabel,
			r.URL,
			wafLabel,
			techLabel,
			titleLabel,
		)

		// Redirect chain
		if *showRedir && len(r.Redirects) > 0 {
			for _, redir := range r.Redirects {
				fmt.Printf("       "+GRY+DIM+"↳ %s"+RST+"\n", redir)
			}
		}

		// Default cred hint
		if *showCred && r.DefaultCred != "" {
			fmt.Printf("       "+YEL+"[CRED] %s"+RST+"\n", r.DefaultCred)
		}
	}

	elapsed := time.Since(startTime)

	// Save URLs
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

	// Save JSON
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

	// Save CSV
	if *saveCSV != "" {
		csvOut, err := os.Create(*saveCSV)
		if err != nil {
			fmt.Println(RED + "\n  [ERR] Cannot create CSV file: " + *saveCSV + RST)
		} else {
			defer csvOut.Close()
			w := csv.NewWriter(csvOut)
			w.Write([]string{"url", "status_code", "status_desc", "title", "tech", "cms_version", "waf", "response_time_ms", "content_length", "redirects", "default_cred"})
			for _, r := range results {
				w.Write([]string{
					r.URL,
					strconv.Itoa(r.Code),
					r.Desc,
					r.Title,
					strings.Join(r.Tech, "|"),
					r.CMSVersion,
					r.WAF,
					strconv.FormatInt(r.ResponseTime, 10),
					strconv.FormatInt(r.ContentLength, 10),
					strings.Join(r.Redirects, " | "),
					r.DefaultCred,
				})
			}
			w.Flush()
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
	if *saveCSV != "" {
		fmt.Printf("  "+GRY+"CSV saved to %s%s\n"+RST, BOLD+*saveCSV, RST)
	}
	fmt.Println()
}
