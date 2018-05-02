<?php

declare(strict_types=1);

namespace Reflect\Project\Token\Parameter;

final class Op
{
    public const EQUALS                 = '=';
    public const NOT_EQUALS             = '!=';
    public const GREATER_THAN           = '>';
    public const GREATER_THAN_OR_EQUALS = '>=';
    public const LESS_THAN              = '<';
    public const LESS_THAN_OR_EQUALS    = '<=';
    public const CONTAINS               = '=~';
    public const NOT_CONTAINS           = '!~';

    private function __construct() {}
}
