## Lisansly API Gateway

### Running Locally

Before invoking the function, you must set environment variables in the 'env.local.json' file.</br>
Afterward, you can invoke the function.</br>
Make sure to open Docker in the background.

```shell
make build && make zip

# then

sls invoke local -f funcName
#or
serverless invoke local -f funcName
```

### Linting
Needs golangci-lint package installed locally

```shell
make lint
```

### Testing

```shell
make test
```

### Git Hooks:
Needs pre-commit package installed locally

Installation:
```shell
pre-commit install
```

Run:
```shell
pre-commit run
```
