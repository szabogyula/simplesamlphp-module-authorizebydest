<?php

/**
 * Test for the authorizebydest:AuthorizeByDest authproc filter.
 */

namespace SimpleSAML\Module\authorizebytest\Auth\Process;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\AuthorizeByDest\Tests\Utils\TestableAuthorize;
use SimpleSAML\Utils\Attributes;

class AuthorizeByDestTest extends TestCase
{
    /**
     * Test that having a matching attribute grants access
     *
     * @dataProvider allowScenarioProvider
     *
     * @param array $userAttributes The attributes to test
     * @param bool  $isAuthorized   Should the user be authorized
     */
    public function testAllowScenarios(array $userAttributes, string $entityid, bool $isAuthorized): void
    {
        $userAttributes = Attributes::normalizeAttributesArray($userAttributes);
        $config = [
            'discriminant_attribute' => 'uid',
            'discriminant_users'     => ['vip_1@example.com', 'vip_2@example.com'],
            'attribute'              => 'checkAttribute',
            'attribute_value'        => '0',
            'destination_whitelist'  => ['sp-a', 'sp-b'],
        ];

        $request = [
            'Attributes'  => $userAttributes,
            'SPMetadata' => ['entityid' => $entityid],
        ];

        $resultState = $this->processFilter($config, $request);

        $resultAuthorized = isset($resultState['NOT_AUTHORIZED']) ? false : true;
        $this->assertEquals($isAuthorized, $resultAuthorized);
    }

    /**
     * Helper function to run the filter with a given configuration.
     *
     * @param array $config  The filter configuration.
     * @param array $request The request state.
     *
     * @return array  The state array after processing.
     */
    private function processFilter(array $config, array $request): array
    {
        $filter = new TestableAuthorize($config, null);
        $filter->process($request);

        return $request;
    }

    /**
     * @return array
     */
    public function allowScenarioProvider(): array
    {
        return [
            // Should be allowed
            [
                [
                    'uid'            => 'anything@example.com',
                    'checkAttribute' => '0',
                ],
                'sp-a',
                true,
            ],
            [
                [
                    'uid'            => 'anything@example.com',
                    'checkAttribute' => '1',
                ],
                'sp-a',
                true,
            ],
            [
                [
                    'uid'            => 'anything@example.com',
                    'checkAttribute' => '1',
                ],
                'sp-c',
                true,
            ],
            [
                [
                    'uid'            => 'vip_1@example.com',
                    'checkAttribute' => '0',
                ],
                'sp-c',
                true,
            ],
            //Should be denied
            [
                [
                    'uid'            => 'anything@example.com',
                    'checkAttribute' => '0',
                ],
                'sp-c',
                false,
            ],

        ];
    }
}
