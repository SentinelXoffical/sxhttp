# sxhttp

Fast, concurrent web status probe built in Go.

```
   _____            __  _            __  _  __
  / ___/___  ____  / /_(_)___  ___  / / | |/ /
  \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ /  |   /
 ___/ /  __/ / / / /_/ / / / /  __/ /___/   |
/____/\___/_/ /_/\__/_/_/ /_/\___/_____/_/|_|

  SentinelX HTTP — Web Status
  Author : WildanDev
```

---

## Installation

**Via Go:**
```bash
go install github.com/SentinelXoffical/sxhttp@latest
```

**Build from source:**
```bash
git clone https://github.com/SentinelXoffical/sxhttp
cd sxhttp
go build -o sxhttp main.go
```

---

## Usage

```
sxhttp --file <urls.txt> [--threads N] [--timeout N] [--only CODE] [--save output.txt]
```

| Flag | Default | Description |
|---|---|---|
| `--file` | required | Input file, one URL per line |
| `--threads` | 10 | Number of concurrent workers |
| `--timeout` | 10 | Request timeout in seconds |
| `--only` | - | Filter by status code(s), comma-separated |
| `--save` | - | Save matched URLs to output file |

---

## Examples

Scan all URLs:
```bash
sxhttp --file urls.txt
```

Show only 200:
```bash
sxhttp --file urls.txt --only 200
```

Show 200 and 403, save to file:
```bash
sxhttp --file urls.txt --only 200,403 --save result.txt
```

High concurrency scan:
```bash
sxhttp --file urls.txt --threads 100 --only 200 --save alive.txt
```

---

## Input File Format

One URL per line. Lines starting with `#` are ignored.

```
https://example.com
https://target.com
# this is a comment
target2.com
```

> `http://` and `https://` are optional — sxhttp will auto-prepend `https://` if missing.

---

## Output

```
  [200]  OK                        https://example.com
  [403]  Forbidden                 https://target.com
  [500]  Internal Server Error     https://other.com

  Scan complete  3 URLs  //  1.23s

  2xx  1       3xx  0       4xx  1       5xx  1       err  0
```

Status colors:
- `2xx` — Green
- `3xx` — Blue
- `4xx` — Yellow
- `5xx` — Red

---

## License

MIT
