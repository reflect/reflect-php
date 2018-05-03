# reflect-php

## Installation

```console
$ composer require reflect-io/reflect-php
```

## Generating user tokens

```php
use Reflect\Project\Token;

$accessKey = 'd232c1e5-6083-4aa7-9042-0547052cc5dd';
$secretKey = '74678a9b-685c-4c14-ac45-7312fe29de06';

$parameter = new Token\Parameter(
    'user-id',
    Token\Parameter\Op::EQUALS,
    '1234'
);

$token = (new Token\Builder($accessKey))
    ->setAttribute('user-id', 1234)
    ->setAttribute('user-name', 'Billy Bob')
    ->addParameter($parameter)
    ->build($secretKey);
```
