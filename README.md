# quicktimeline
create a timeline of a windows image, using dissect

## Usage

```
usage: windows-timeline [-h] [--overwrite] [--dialect {excel,excel-tab,unix}] image_path

create a timeline of a windows image, using dissect

positional arguments:
  image_path

options:
  -h, --help            show this help message and exit
  --overwrite           overwrite destination directory
  --dialect {excel,excel-tab,unix}
                        select CSV dialect
```

## Output
Directory (named by the hostname of the image) including:
- hostname.txt - with information of hostname, domain, windows version, install date, language, timezone, ips and users
- otheroutput of different plugins (TODO)
