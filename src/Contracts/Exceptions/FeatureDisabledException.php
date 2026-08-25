<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts\Exceptions;

final class FeatureDisabledException extends NettoolsException
{
    public function __construct()
    {
        parent::__construct('feature_disabled', [], 'feature group disabled');
    }
}
