<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Install;

enum ChangeKind: string
{
    /** File does not exist — will be created. */
    case Create = 'create';
    /** Existing file — targeted, verified edit. */
    case Modify = 'modify';
    /** Existing configuration could not be edited safely — the user pastes a snippet. */
    case Manual = 'manual';
    /** Nothing to do. */
    case Unchanged = 'unchanged';
}
