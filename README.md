# Veil for Laravel

Veil is a package to help manage encrypted environments in your Laravel or Laravel Zero application. It adds an `--only-values` flag to the Laravel encrypted environment commands. Without this package, this environment file:

```text
APP_NAME="My awesome app"
APP_ENV=local
APP_DEBUG=true

SOME_API_KEY=12345678
```

Will turn into:

```text
eyJpdiI6ImplT2xTaGRzV... # Really long string
```

But with this package you can make it look like this:

```text
APP_NAME="My awesome app"
APP_ENV=local
APP_DEBUG=true

SOME_API_KEY=eyJpdiI6ImplT2xTaGRzV...
```

This improves readability of the encrypted environment file, maybe even making the `.env.example` file obsolete.

## Installation

Just install this package through composer:

```shell
composer require intermax/veil
```

## Usage

Just use the `env:encrypt` and `env:decrypt` commands as usual, but add an `--only-values` flag:

```shell
php artisan env:encrypt --only-values ...
php artisan env:decrypt --only-values ...
```

### Only Encrypting Secrets
By default, if the `--only-values` flag is used only variables ending with `_PASSWORD`, `_KEY` and `_SECRET` will be encrypted. You can configure this behaviour with the `--only` flag. If you would only want to encrypt the variables ending with `_SECRET` and the `APP_KEY`, you can specify multiple `--only` flags like this:

```shell
php artisan env:encrypt --only-values --only=*_SECRET --only=APP_KEY
```

For decrypting, there is no difference: the decrypt command will leave unencrypted values.

### Encrypting Everything
If you still want to encrypt everything while keeping variable names readable, use the `--all` flag:

```shell
php artisan env:encrypt --only-values --all
```
