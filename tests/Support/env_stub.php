<?php

declare(strict_types=1);

if (! function_exists('env')) {
    /** Test stand-in for Laravel's env() when loading config/ outside the framework. */
    function env(string $key, mixed $default = null): mixed
    {
        unset($key);

        return $default;
    }
}
