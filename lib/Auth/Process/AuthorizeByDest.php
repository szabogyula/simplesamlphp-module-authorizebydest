<?php

namespace SimpleSAML\Module\authorizebydest\Auth\Process;

use SimpleSAML\Auth;
use SimpleSAML\Error\CriticalConfigurationError;
use SimpleSAML\Module;
use SimpleSAML\Utils;
use Webmozart\Assert\Assert;

/**
 * Filter to authorize only certain users.
 * See docs directory.
 *
 * @package SimpleSAMLphp
 */
class AuthorizeByDest extends Auth\ProcessingFilter
{
    /**
     * Flag to deny/unauthorize the user a attribute filter IS found
     *
     * @var string
     */
    protected $attribute;

    /**
     * @var string
     */
    protected $attribute_value;

    /**
     * @var array
     */
    protected $destination_whitelist = [];

    /**
     * @var string
     */
    protected $discriminant_attribute;

    /**
     * @var array
     */
    protected $discriminant_users = [];

    /**
     * Initialize this filter.
     * Validate configuration parameters.
     *
     * @param array $config   Configuration information about this filter.
     * @param mixed $reserved For future use.
     *
     * @throws CriticalConfigurationError
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        if (isset($config['attribute']) && is_string($config['attribute'])) {
            $this->attribute = $config['attribute'];
        } else {
            $reason = 'There is no attribute config in authorizeByDest authproc filter';
            throw new CriticalConfigurationError($reason);
        }
        if (isset($config['attribute_value']) && is_string($config['attribute_value'])) {
            $this->attribute_value = $config['attribute_value'];
        } else {
            $reason = 'There is no attribute_value config in authorizeByDest authproc filter';
            throw new CriticalConfigurationError($reason);
        }
        if (isset($config['destination_whitelist']) && is_array($config['destination_whitelist'])) {
            $this->destination_whitelist = $config['destination_whitelist'];
        } else {
            $reason = 'There is no destination_whitelist config in authorizeByDest authproc filter';
            throw new CriticalConfigurationError($reason);
        }

        if (isset($config['discriminant_attribute']) && is_string($config['discriminant_attribute'])) {
            $this->discriminant_attribute = $config['discriminant_attribute'];
        }
        if (isset($config['discriminant_users']) && is_array($config['discriminant_users'])) {
            $this->discriminant_users = $config['discriminant_users'];
        }
        if (isset($this->discriminant_users) and !isset($this->discriminant_attribute)) {
            $reason = 'You have to define discriminant attribute in authorizeByDest authproc filter';
            throw new CriticalConfigurationError($reason);
        }
    }


    /**
     * Apply filter to validate dest and user.
     *
     * @param array &$request The current request
     */
    public function process(&$request)
    {
        Assert::keyExists($request, 'Attributes');
        Assert::keyExists($request, 'SPMetadata');
        Assert::keyExists($request['SPMetadata'], 'entityid');

        $attributes = $request['Attributes'];
        $destination = $request['SPMetadata']['entityid'];

        if (!empty($attributes[$this->discriminant_attribute])
            && empty(array_intersect($attributes[$this->discriminant_attribute], $this->discriminant_users))
        ) {
            if (!empty($attributes[$this->attribute]) && in_array($this->attribute_value, $attributes[$this->attribute])) {
                if (!in_array($destination, $this->destination_whitelist)) {
                    $this->unauthorized($request);
                }
            }
        }


    }


    /**
     * When the process logic determines that the user is not
     * authorized for this service, then forward the user to
     * an 403 unauthorized page.
     *
     * Separated this code into its own method so that child
     * classes can override it and change the action. Forward
     * thinking in case a "chained" ACL is needed, more complex
     * permission logic.
     *
     * @param array $request
     */
    protected function unauthorized(&$request)
    {
        // Save state and redirect to 403 page
        $id = Auth\State::saveState($request, 'authorizebydest:AuthorizeByDest');
        $url = Module::getModuleURL('authorizebydest/authorize_403.php');
        Utils\HTTP::redirectTrustedURL($url, ['StateId' => $id]);
    }
}
