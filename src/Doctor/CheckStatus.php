<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Doctor;

enum CheckStatus: string
{
    case Ok = 'ok';
    case Warning = 'warning';
    case Failure = 'failure';
    case Skipped = 'skipped';
}
