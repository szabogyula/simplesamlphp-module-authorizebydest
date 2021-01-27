<?php

/**
 * Subclass authorize filter to make it unit testable.
 */

namespace SimpleSAML\Module\AuthorizeByDest\Tests\Utils;

use SimpleSAML\Module\authorizebydest\Auth\Process\AuthorizeByDest;

class TestableAuthorize extends AuthorizeByDest
{
    /**
     * Override the redirect behavior since its difficult to test
     * @param array $request the state
     */
    protected function unauthorized(array &$request): void
    {
        $request['NOT_AUTHORIZED'] = true;
    }
}
