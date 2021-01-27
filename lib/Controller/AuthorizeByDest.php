<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authorizebydest\Controller;

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller class for the authorize module.
 *
 * This class serves the different views available in the module.
 *
 * @package SimpleSAML\Module\authorize
 */

class AuthorizeByDest
{
    /** @var \SimpleSAML\Configuration */
    protected $config;

    /** @var \SimpleSAML\Session */
    protected $session;


    /**
     * Controller constructor.
     *
     * It initializes the global configuration and auth source configuration for the controllers implemented here.
     *
     * @param \SimpleSAML\Configuration              $config The configuration to use by the controllers.
     * @param \SimpleSAML\Session                    $session The session to use by the controllers.
     *
     * @throws \Exception
     */
    public function __construct(
        Configuration $config,
        Session $session
    ) {
        $this->config = $config;
        $this->session = $session;
    }


    /**
     * Show a 403 Forbidden page about not authorized to access an application.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\XHTML\Template
     */
    public function forbidden(Request $request): Template
    {
        $stateId = $request->get('StateId', false);
        if ($stateId === false) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }

        /** @var array $state */
        $state = Auth\State::loadState($stateId, 'authorizebydest:AuthorizeByDest');

        $t = new Template($this->config, 'authorizebydest:authorize_403.twig');
        if (isset($state['Source']['auth'])) {
            $t->data['logoutURL'] = Module::getModuleURL(
                'core/authenticate.php',
                ['as' => $state['Source']['auth']]
            ) . "&logout";
        }
        if (isset($state['authprocAuthorizeByDest_reject_msg'])) {
            $t->data['reject_msg'] = $state['authprocAuthorizeByDest_reject_msg'];
        }

        $t->setStatusCode(403);
        return $t;
    }
}
