<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\authorizebydest\Controller;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module\authorizebydest\Controller;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Set of tests for the controllers in the "authorize" module.
 *
 * @package SimpleSAML\Test
 */
class AuthorizeByDestTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected $config;

    /** @var string */
    protected $stateId;


    /**
     * Set up for each test.
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->config = Configuration::loadFromArray(
            [
                'baseurlpath' => 'https://example.org/simplesaml',
                'module.enable' => ['authorizebydest' => true],
            ],
            '[ARRAY]',
            'simplesaml'
        );

        $state = [
            'StateId' => 'SomeState',
            'Source' => ['auth' => 'test'],
            'authprocAuthorize_reject_msg' => 'Test Rejected'
        ];
        $this->stateId = Auth\State::saveState($state, 'authorizebydest:AuthorizeByDest');

        Configuration::setPreLoadedConfig($this->config, 'config.php');
    }


    /**
     * Test that a valid requests results in a HTTP/403 Forbidden page with translated messages
     * @return void
     */
    public function testValidRequest()
    {
        $request = Request::create(
            '/',
            'GET',
            ['StateId' => $this->stateId]
        );
        $session = Session::getSessionFromRequest();

        $c = new Controller\AuthorizeByDest($this->config, $session);

        /** @var \SimpleSAML\XHTML\Template $response */
        $response = $c->forbidden($request);

        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isForbidden());
    }


    /**
     * Test that a request with a missing StateId throws an exception
     * @return void
     */
    public function testMissingStateIdThrowsException()
    {
        $request = new Request();
        $session = Session::getSessionFromRequest();

        $c = new Controller\AuthorizeByDest($this->config, $session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('Missing required StateId query parameter.');

        $c->forbidden($request);
    }
}
