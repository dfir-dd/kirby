# kirby
A cute script to parse several forensic artifacts of given windows (triage) images, using dissect

## Usage

```
usage: kirby [-h] -o OUTPUT [--overwrite] [--dialect {excel,excel-tab,unix}] TARGETS [TARGETS ...]

parse forensic artifacts from windows images, using dissect

positional arguments:
  TARGETS               Path to single target or directory with multiple targets to parse

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Specify the output directory
  --overwrite           overwrite destination directory
  --dialect {excel,excel-tab,unix}
                        select CSV dialect
```

## Output

- hostinfo.csv - hostinfo of all targets parsed
- Directory (named by the hostname of the image) including:
  - hostinfo_\<hostname\>.csv - with information of hostname, domain, windows version, install date, language, timezone, ips and users
  - other output of different plugins (TODO)
