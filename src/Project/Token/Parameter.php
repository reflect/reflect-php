<?php

declare(strict_types=1);

namespace Reflect\Project\Token;

class Parameter implements \JsonSerializable
{
    /**
     * @var string
     */
    protected $field;

    /**
     * @var string
     */
    protected $op;

    protected $value;

    public function __construct(string $field, string $op, $value)
    {
        $this->field = $field;
        $this->op = $op;
        $this->value = $value;
    }

    public function jsonSerialize(): array
    {
        $data = [
            'field' => $this->field,
            'op'    => $this->op,
        ];

        if (is_array($this->value)) {
            $data['any'] = $this->value;
        } else {
            $data['value'] = $this->value;
        }

        return $data;
    }
}
