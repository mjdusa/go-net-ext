# super-linter

## BASH issues

To disable BASH add the following lines to super-linter.env
```bash
VALIDATE_BASH=false
VALIDATE_BASH_EXEC=false
```

### See: [github.com/koalaman/shellcheck](https://github.com/koalaman/shellcheck)

### Config
The .shellcheckrc file should normally go in ./.github/linters/.shellcheckrc, but currently seems to only works in the project's root directory.

## SHFMT

To disable SHFMT add the following line to super-linter.env
```bash
VALIDATE_SHELL_SHFMT=false
```

### See: [github.com/mvdan/sh](https://github.com/mvdan/sh?tab=readme-ov-file#shfmt)

### Running
Running "shfmt -l -w subject-script.sh" will fix most shfmt issues and overwrite/update your file with the fixes.
